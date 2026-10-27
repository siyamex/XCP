package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Reporter lets a handler report progress and log lines for the UI.
type Reporter interface {
	Progress(pct int)
	Logf(format string, args ...any)
}

// Handler runs one job. The returned result is stored as JSON. ctx is
// canceled if the job is canceled or the lease is lost.
type Handler func(ctx context.Context, job *Job, r Reporter) (result any, err error)

type kindSpec struct {
	handler Handler
	slots   chan struct{} // buffered to the kind's concurrency limit
}

// Worker claims and runs jobs.
type Worker struct {
	q     *Queue
	id    string
	log   *slog.Logger
	kinds map[string]*kindSpec

	// Lease is how long a claim lasts without a heartbeat; heartbeats are sent every Lease/3.
	Lease time.Duration
	// Poll is the wait between claim attempts when the queue is idle.
	Poll time.Duration
}

// NewWorker returns a worker with id (unique per process, e.g. "hostname:pid").
func NewWorker(q *Queue, id string, log *slog.Logger) *Worker {
	return &Worker{q: q, id: id, log: log, kinds: map[string]*kindSpec{}, Lease: 60 * time.Second, Poll: time.Second}
}

// Register adds a handler for kind with at most concurrency parallel runs in this worker.
// It must be called before Run.
func (w *Worker) Register(kind string, concurrency int, h Handler) {
	w.kinds[kind] = &kindSpec{handler: h, slots: make(chan struct{}, max(concurrency, 1))}
}

// Run claims jobs until ctx is canceled, then waits for running jobs to finish.
func (w *Worker) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		ran := w.claimOnce(ctx, &wg)
		if ran {
			continue // more work may be waiting
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.Poll):
		}
	}
}

// claimOnce tries to start one job for kinds with a free slot.
func (w *Worker) claimOnce(ctx context.Context, wg *sync.WaitGroup) bool {
	if ctx.Err() != nil {
		return false
	}
	var free []string
	for kind, spec := range w.kinds {
		if len(spec.slots) < cap(spec.slots) {
			free = append(free, kind)
		}
	}
	job, err := w.q.Claim(ctx, w.id, free, w.Lease)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("claim job", "err", err)
		}
		return false
	}
	if job == nil {
		return false
	}
	spec := w.kinds[job.Kind]
	spec.slots <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-spec.slots }()
		w.execute(ctx, job, spec.handler)
	}()
	return true
}

type reporter struct {
	ctx context.Context
	q   *Queue
	job *Job
	w   *Worker
}

func (r reporter) Progress(pct int) {
	if err := r.q.SetProgress(r.ctx, r.job.ID, r.w.id, pct); err != nil && !errors.Is(err, ErrLeaseLost) {
		r.w.log.Warn("job progress", "job", r.job.ID, "err", err)
	}
}

func (r reporter) Logf(format string, args ...any) {
	if err := r.q.Log(r.ctx, r.job.ID, "info", fmt.Sprintf(format, args...)); err != nil {
		r.w.log.Warn("job log", "job", r.job.ID, "err", err)
	}
}

func (w *Worker) execute(parent context.Context, job *Job, h Handler) {
	log := w.log.With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)
	// Job bookkeeping must still be written after shutdown starts.
	bg := context.WithoutCancel(parent)
	jobCtx, cancel := context.WithCancel(parent)
	defer cancel()

	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		t := time.NewTicker(w.Lease / 3)
		defer t.Stop()
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-t.C:
				if err := w.q.Heartbeat(bg, job.ID, w.id, w.Lease); err != nil {
					log.Warn("lost job lease; stopping job", "err", err)
					cancel()
					return
				}
			}
		}
	}()

	log.Info("job started")
	result, jobErr := runSafely(jobCtx, job, h, reporter{ctx: bg, q: w.q, job: job, w: w}, log)
	cancel()
	<-hbDone

	var err error
	if jobErr == nil {
		if err = w.q.Complete(bg, job.ID, w.id, result); err == nil {
			log.Info("job succeeded")
			return
		}
	} else {
		if err = w.q.Fail(bg, job.ID, w.id, jobErr, job.Attempts, job.MaxAttempts); err == nil {
			log.Warn("job failed", "err", jobErr, "permanent", IsPermanent(jobErr))
			return
		}
	}
	if errors.Is(err, ErrLeaseLost) {
		log.Info("job outcome discarded: job was canceled or taken over")
		return
	}
	log.Error("record job outcome", "err", err)
}

// runSafely turns a handler panic into a permanent error so the worker
// survives. The stack goes to the server log only, not to the job error
// that users can see.
func runSafely(ctx context.Context, job *Job, h Handler, r Reporter, log *slog.Logger) (result any, err error) {
	defer func() {
		if p := recover(); p != nil {
			log.Error("job handler panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = Permanent(errors.New("internal error"))
		}
	}()
	return h(ctx, job, r)
}
