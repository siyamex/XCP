package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func waitStatus(t *testing.T, q *Queue, id string, want Status) *Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := q.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == want {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	j, _ := q.Get(ctx, id)
	t.Fatalf("job %s status = %s, want %s (error %q)", id, j.Status, want, j.Error)
	return nil
}

func startWorker(t *testing.T, w *Worker) {
	t.Helper()
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
}

func TestWorkerRunsHandlerWithProgressAndLogs(t *testing.T) {
	q, _ := newTestQueue(t)
	q.now = time.Now
	w := NewWorker(q, "w1", discardLog())
	w.Poll = 10 * time.Millisecond
	w.Register("echo", 1, func(_ context.Context, j *Job, r Reporter) (any, error) {
		r.Progress(40)
		r.Logf("working on %s", j.Kind)
		return map[string]string{"ok": "yes"}, nil
	})
	id := mustEnqueue(t, q, "echo", EnqueueOptions{})
	startWorker(t, w)

	j := waitStatus(t, q, id, StatusSucceeded)
	if string(j.Result) != `{"ok":"yes"}` {
		t.Fatalf("result = %s", j.Result)
	}
	lines, _ := q.Logs(ctx, id, 0)
	if len(lines) != 1 || lines[0].Message != "working on echo" {
		t.Fatalf("logs = %+v", lines)
	}
}

func TestWorkerPanicBecomesPermanentFailureWithoutStack(t *testing.T) {
	q, _ := newTestQueue(t)
	q.now = time.Now
	w := NewWorker(q, "w1", discardLog())
	w.Poll = 10 * time.Millisecond
	w.Register("boom", 1, func(context.Context, *Job, Reporter) (any, error) { panic("nil map") })
	id := mustEnqueue(t, q, "boom", EnqueueOptions{MaxAttempts: 5})
	startWorker(t, w)

	j := waitStatus(t, q, id, StatusFailed)
	if j.Error != "internal error" || j.Attempts != 1 {
		t.Fatalf("job = %+v", j)
	}
}

func TestWorkerRespectsConcurrencyLimit(t *testing.T) {
	q, _ := newTestQueue(t)
	q.now = time.Now
	w := NewWorker(q, "w1", discardLog())
	w.Poll = 5 * time.Millisecond
	var running, peak atomic.Int32
	release := make(chan struct{})
	w.Register("slow", 2, func(context.Context, *Job, Reporter) (any, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		running.Add(-1)
		return nil, nil
	})
	var idsList []string
	for range 5 {
		idsList = append(idsList, mustEnqueue(t, q, "slow", EnqueueOptions{}))
	}
	startWorker(t, w)
	time.Sleep(150 * time.Millisecond)
	if p := peak.Load(); p != 2 {
		t.Fatalf("peak concurrency = %d, want 2", p)
	}
	close(release)
	for _, id := range idsList {
		waitStatus(t, q, id, StatusSucceeded)
	}
}

func TestWorkerStopsHandlerWhenJobCanceled(t *testing.T) {
	q, _ := newTestQueue(t)
	q.now = time.Now
	w := NewWorker(q, "w1", discardLog())
	w.Poll = 10 * time.Millisecond
	w.Lease = 90 * time.Millisecond // heartbeat every 30ms
	stopped := make(chan error, 1)
	w.Register("long", 1, func(ctx context.Context, _ *Job, _ Reporter) (any, error) {
		<-ctx.Done()
		stopped <- ctx.Err()
		return nil, ctx.Err()
	})
	id := mustEnqueue(t, q, "long", EnqueueOptions{})
	startWorker(t, w)
	waitStatus(t, q, id, StatusRunning)
	if err := q.Cancel(ctx, id); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler ctx err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler was not stopped after cancel")
	}
	if j, _ := q.Get(ctx, id); j.Status != StatusCanceled {
		t.Fatalf("status = %s, want canceled (worker must not overwrite it)", j.Status)
	}
}
