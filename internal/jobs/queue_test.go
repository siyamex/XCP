package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestQueue(t *testing.T) (*Queue, *clock) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	q := NewQueue(db)
	q.now = c.now
	return q, c
}

var ctx = context.Background()

func mustEnqueue(t *testing.T, q *Queue, kind string, opt EnqueueOptions) string {
	t.Helper()
	id, err := q.Enqueue(ctx, kind, map[string]string{"k": "v"}, opt)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustClaim(t *testing.T, q *Queue, worker string, kinds ...string) *Job {
	t.Helper()
	j, err := q.Claim(ctx, worker, kinds, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestEnqueueClaimComplete(t *testing.T) {
	q, _ := newTestQueue(t)
	id := mustEnqueue(t, q, "backup", EnqueueOptions{AccountID: "acc1"})

	if j := mustClaim(t, q, "w1", "ssl"); j != nil {
		t.Fatal("claimed a job of a kind the worker did not ask for")
	}
	j := mustClaim(t, q, "w1", "backup", "ssl")
	if j == nil || j.ID != id || j.Status != StatusRunning || j.Attempts != 1 || string(j.Payload) != `{"k":"v"}` {
		t.Fatalf("claimed %+v", j)
	}
	if again := mustClaim(t, q, "w2", "backup"); again != nil {
		t.Fatal("job claimed twice")
	}
	if err := q.SetProgress(ctx, id, "w2", 50); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("other worker updated job: %v", err)
	}
	if err := q.Complete(ctx, id, "w1", map[string]int{"bytes": 42}); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(ctx, id)
	if got.Status != StatusSucceeded || got.Progress != 100 || string(got.Result) != `{"bytes":42}` || got.FinishedAt == nil {
		t.Fatalf("after complete: %+v", got)
	}
}

func TestRunAfterIsRespected(t *testing.T) {
	q, c := newTestQueue(t)
	mustEnqueue(t, q, "k", EnqueueOptions{RunAfter: c.now().Add(time.Hour)})
	if mustClaim(t, q, "w", "k") != nil {
		t.Fatal("claimed a job before run_after")
	}
	c.add(time.Hour)
	if mustClaim(t, q, "w", "k") == nil {
		t.Fatal("job not claimable at run_after")
	}
}

func TestLockKeySerialisesJobs(t *testing.T) {
	q, _ := newTestQueue(t)
	first := mustEnqueue(t, q, "k", EnqueueOptions{LockKey: "account:1"})
	mustEnqueue(t, q, "k", EnqueueOptions{LockKey: "account:1"})
	other := mustEnqueue(t, q, "k", EnqueueOptions{LockKey: "account:2"})

	if j := mustClaim(t, q, "w", "k"); j.ID != first {
		t.Fatalf("claimed %s, want %s", j.ID, first)
	}
	if j := mustClaim(t, q, "w", "k"); j == nil || j.ID != other {
		t.Fatalf("second claim = %+v, want the job with another lock key", j)
	}
	if j := mustClaim(t, q, "w", "k"); j != nil {
		t.Fatal("claimed a job whose lock key is held")
	}
	if err := q.Complete(ctx, first, "w", nil); err != nil {
		t.Fatal(err)
	}
	if mustClaim(t, q, "w", "k") == nil {
		t.Fatal("lock key not released after completion")
	}
}

func TestLockKeyKeepsOrderAcrossRetries(t *testing.T) {
	q, c := newTestQueue(t)
	create := mustEnqueue(t, q, "account.create", EnqueueOptions{LockKey: "account:1"})
	addDomain := mustEnqueue(t, q, "domain.add", EnqueueOptions{LockKey: "account:1"})

	j := mustClaim(t, q, "w", "account.create", "domain.add")
	if j.ID != create {
		t.Fatalf("claimed %s first", j.Kind)
	}
	if err := q.Fail(ctx, create, "w", errors.New("transient"), j.Attempts, j.MaxAttempts); err != nil {
		t.Fatal(err)
	}
	if j := mustClaim(t, q, "w", "account.create", "domain.add"); j != nil {
		t.Fatalf("claimed %s while an earlier job with the same key waits for retry", j.Kind)
	}
	c.add(Backoff(1))
	if j := mustClaim(t, q, "w", "account.create", "domain.add"); j == nil || j.ID != create {
		t.Fatalf("retry claim = %+v", j)
	}
	if err := q.Complete(ctx, create, "w", nil); err != nil {
		t.Fatal(err)
	}
	if j := mustClaim(t, q, "w", "account.create", "domain.add"); j == nil || j.ID != addDomain {
		t.Fatalf("after create succeeded, claim = %+v", j)
	}
}

func TestExpiredLeaseIsReclaimedThenFails(t *testing.T) {
	q, c := newTestQueue(t)
	id := mustEnqueue(t, q, "k", EnqueueOptions{MaxAttempts: 2})
	mustClaim(t, q, "dead-worker", "k")

	c.add(2 * time.Minute) // lease expired, worker died
	j := mustClaim(t, q, "w2", "k")
	if j == nil || j.ID != id || j.Attempts != 2 {
		t.Fatalf("reclaim = %+v", j)
	}
	if err := q.Heartbeat(ctx, id, "dead-worker", time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("dead worker heartbeat: %v", err)
	}

	c.add(2 * time.Minute) // second worker died on the last attempt
	if mustClaim(t, q, "w3", "k") != nil {
		t.Fatal("job ran more than max_attempts")
	}
	if got, _ := q.Get(ctx, id); got.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
}

func TestFailRetriesWithBackoffThenFails(t *testing.T) {
	q, c := newTestQueue(t)
	id := mustEnqueue(t, q, "k", EnqueueOptions{MaxAttempts: 2})

	j := mustClaim(t, q, "w", "k")
	if err := q.Fail(ctx, id, "w", errors.New("dns timeout"), j.Attempts, j.MaxAttempts); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(ctx, id)
	if got.Status != StatusQueued || got.Error != "dns timeout" || !got.RunAfter.Equal(c.now().Add(Backoff(1))) {
		t.Fatalf("after first failure: %+v", got)
	}
	if mustClaim(t, q, "w", "k") != nil {
		t.Fatal("retried before back-off elapsed")
	}
	c.add(Backoff(1))
	j = mustClaim(t, q, "w", "k")
	if err := q.Fail(ctx, id, "w", errors.New("dns timeout"), j.Attempts, j.MaxAttempts); err != nil {
		t.Fatal(err)
	}
	if got, _ := q.Get(ctx, id); got.Status != StatusFailed {
		t.Fatalf("status = %s, want failed after max attempts", got.Status)
	}
	if err := q.Retry(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got, _ := q.Get(ctx, id); got.Status != StatusQueued || got.Attempts != 0 {
		t.Fatalf("after Retry: %+v", got)
	}
}

func TestPermanentErrorIsNotRetried(t *testing.T) {
	q, _ := newTestQueue(t)
	id := mustEnqueue(t, q, "k", EnqueueOptions{MaxAttempts: 5})
	j := mustClaim(t, q, "w", "k")
	err := q.Fail(ctx, id, "w", Permanent(errors.New("domain invalid")), j.Attempts, j.MaxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := q.Get(ctx, id); got.Status != StatusFailed {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestCancelUniqueAndLogs(t *testing.T) {
	q, _ := newTestQueue(t)
	id := mustEnqueue(t, q, "autossl", EnqueueOptions{LockKey: "x", Unique: true})
	if _, err := q.Enqueue(ctx, "autossl", nil, EnqueueOptions{LockKey: "x", Unique: true}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("Unique: err = %v", err)
	}
	mustClaim(t, q, "w", "autossl")
	if err := q.Cancel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := q.Heartbeat(ctx, id, "w", time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("heartbeat after cancel: %v", err)
	}
	if err := q.Cancel(ctx, id); !errors.Is(err, ErrBadState) {
		t.Fatalf("double cancel: %v", err)
	}
	if _, err := q.Enqueue(ctx, "autossl", nil, EnqueueOptions{LockKey: "x", Unique: true}); err != nil {
		t.Fatalf("Unique after cancel: %v", err)
	}

	for _, m := range []string{"one", "two", "three"} {
		if err := q.Log(ctx, id, "info", m); err != nil {
			t.Fatal(err)
		}
	}
	lines, err := q.Logs(ctx, id, 1)
	if err != nil || len(lines) != 2 || lines[0].Message != "two" || lines[1].Seq != 3 {
		t.Fatalf("Logs = %+v, %v", lines, err)
	}
	if _, err := q.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
}
