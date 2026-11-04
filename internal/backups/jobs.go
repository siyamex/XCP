package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// Job kinds.
const (
	JobCreate   = "backup.create"   // make one backup
	JobSchedule = "backup.schedule" // start the scheduled backups when due
)

// ScheduleCheck is how often JobSchedule looks whether backups are due.
const ScheduleCheck = "5 * * * *"

type createPayload struct {
	BackupID string `json:"backup_id"`
}

// AccountFile is a backup's account.json (ADR-0013).
type AccountFile struct {
	Format  int                 `json:"format"`
	Package string              `json:"package"` // by name: package ids differ between servers
	Export  store.AccountExport `json:"export"`
}

// RegisterJobs adds the backup job handlers to a worker: one backup at a
// time on the server.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobCreate, 1, s.createJob)
	w.Register(JobSchedule, 1, s.scheduleJob)
	w.Register(JobRestore, 1, s.restoreJob)
}

// Schedule adds the hourly check of the backup schedule.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(ScheduleCheck, JobSchedule, struct{}{})
}

// accountFile builds an account's account.json.
func (s *Service) accountFile(ctx context.Context, a *store.Account) ([]byte, error) {
	e, err := s.db.ExportAccount(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	pk, err := s.db.PackageByID(ctx, a.PackageID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(AccountFile{Format: 1, Package: pk.Name, Export: e})
}

func (s *Service) createJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p createPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.BackupID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	b, err := s.db.BackupByID(ctx, p.BackupID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "the backup was removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	a, err := s.db.AccountByID(ctx, b.AccountID)
	if err != nil {
		return nil, err
	}
	res, err := s.make(ctx, a)
	if err != nil {
		b.Status, b.Detail = store.BackupFailed, err.Error()
		if ferr := store.FinishBackup(context.WithoutCancel(ctx), s.db.W, b); ferr != nil {
			return nil, ferr
		}
		return nil, jobs.Permanent(err)
	}
	b.Status, b.File, b.Size, b.SHA256 = store.BackupOK, res.GetFile(), res.GetSize(), res.GetSha256()
	if sk := res.GetSkipped(); len(sk) > 0 {
		b.Detail = fmt.Sprintf("%d file(s) could not be read and are not in it: %s", len(sk), strings.Join(sk, "; "))
	}
	if err := store.FinishBackup(ctx, s.db.W, b); err != nil {
		return nil, err
	}
	r.Logf("backup %s: %d bytes", b.File, b.Size)
	if b.Kind == store.BackupScheduled {
		if err := s.prune(ctx, a); err != nil {
			r.Logf("prune old backups: %v", err)
		}
	}
	return map[string]any{"file": b.File, "size": b.Size, "skipped": len(res.GetSkipped())}, nil
}

func (s *Service) make(ctx context.Context, a *store.Account) (*agentv1.BackupCreateResponse, error) {
	af, err := s.accountFile(ctx, a)
	if err != nil {
		return nil, err
	}
	dbs, err := s.db.ListDatabases(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	req := &agentv1.BackupCreateRequest{Username: a.Username, AccountJson: af}
	for _, d := range dbs {
		req.Databases = append(req.Databases, d.Name)
	}
	return s.agent.BackupCreate(ctx, req)
}

// prune removes the oldest scheduled backups beyond the schedule's keep.
func (s *Service) prune(ctx context.Context, a *store.Account) error {
	sched, err := s.schedule(ctx)
	if err != nil {
		return err
	}
	bs, err := store.AccountBackups(ctx, s.db.R, a.ID) // newest first
	if err != nil {
		return err
	}
	kept := 0
	var errs []error
	for i := range bs {
		b := &bs[i]
		if b.Kind != store.BackupScheduled || b.Status == store.BackupRunning {
			continue
		}
		if b.Status == store.BackupOK && kept < sched.Keep {
			kept++
			continue
		}
		errs = append(errs, s.remove(ctx, b)) // older than the kept ones, or failed
	}
	return errors.Join(errs...)
}

func (s *Service) scheduleJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	sched, err := s.schedule(ctx)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	if !sched.Due(now) {
		return map[string]string{"skipped": "not due"}, nil
	}
	slot := now.Format("2006-01-02T15")
	var last string
	if err := s.db.GetSetting(ctx, lastRunKey, &last); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if last == slot {
		return map[string]string{"skipped": "already started this hour"}, nil
	}
	as, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return nil, err
	}
	n := 0
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		for i := range as {
			a := &as[i]
			if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
				continue
			}
			b, err := s.start(ctx, tx, "schedule", a, store.BackupScheduled)
			if err != nil {
				return err
			}
			if err := s.audit.RecordTx(ctx, tx, event(clientNone, nil, "backup.schedule", a.ID, b.ID, nil)); err != nil {
				return err
			}
			n++
		}
		return store.PutSetting(ctx, tx, lastRunKey, slot)
	})
	if err != nil {
		return nil, err
	}
	r.Logf("started %d scheduled backup(s)", n)
	return map[string]int{"started": n}, nil
}
