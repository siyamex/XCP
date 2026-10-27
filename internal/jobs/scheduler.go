package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"
)

// Scheduler enqueues jobs on cron schedules (backups, AutoSSL renewals,
// bandwidth roll-ups, ...). Only one process (xcp-worker) runs it.
// Scheduled jobs are Unique, so a slow run is never stacked with another.
type Scheduler struct {
	q    *Queue
	log  *slog.Logger
	cron *cron.Cron
}

// NewScheduler returns a scheduler using UTC times.
func NewScheduler(q *Queue, log *slog.Logger) *Scheduler {
	return &Scheduler{
		q:    q,
		log:  log,
		cron: cron.New(cron.WithLocation(time.UTC)),
	}
}

// Every enqueues a job of kind with payload on the 5-field cron spec.
func (s *Scheduler) Every(spec, kind string, payload any) error {
	_, err := s.cron.AddFunc(spec, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		id, err := s.q.Enqueue(ctx, kind, payload, EnqueueOptions{
			LockKey:   "schedule:" + kind,
			Unique:    true,
			CreatedBy: "scheduler",
		})
		switch {
		case errors.Is(err, ErrDuplicate):
			s.log.Info("scheduled job skipped: previous run still queued or running", "kind", kind)
		case err != nil:
			s.log.Error("enqueue scheduled job", "kind", kind, "err", err)
		default:
			s.log.Info("scheduled job enqueued", "kind", kind, "job", id)
		}
	})
	if err != nil {
		return fmt.Errorf("jobs: schedule %q for %s: %w", spec, kind, err)
	}
	return nil
}

// Run starts the scheduler and blocks until ctx is canceled.
func (s *Scheduler) Run(ctx context.Context) {
	s.cron.Start()
	<-ctx.Done()
	<-s.cron.Stop().Done()
}
