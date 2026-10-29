package zones

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// Job kinds. Both use the zone's name as lock key, so removing a zone and
// adding it again happen in order.
const (
	JobApply  = "dns.apply"  // make the DNS server serve the zone as stored
	JobDelete = "dns.delete" // remove a zone from the DNS server
	// JobSync applies the zones the DNS server does not have yet: added
	// before PowerDNS was installed, or while it was down. It runs on a schedule.
	JobSync = "dns.sync"
)

// SyncSchedule is how often JobSync runs.
const SyncSchedule = "*/5 * * * *"

type applyPayload struct {
	ZoneID string `json:"zone_id"`
}

type deletePayload struct {
	Zone string `json:"zone"`
}

// RegisterJobs adds the zone job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
	w.Register(JobDelete, 2, s.deleteJob)
	w.Register(JobSync, 1, s.syncJob)
}

// Schedule adds the periodic zone sync to a scheduler.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(SyncSchedule, JobSync, struct{}{})
}

// syncJob queues an apply for every zone the DNS server does not have, if
// the DNS server runs at all.
func (s *Service) syncJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	zs, err := s.db.ZonesNotServing(ctx)
	if err != nil || len(zs) == 0 {
		return map[string]int{"queued": 0}, err
	}
	st, err := s.agent.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: "dns"})
	if status.Code(err) == codes.NotFound || (err == nil && st.GetActiveState() != "active") {
		return map[string]any{"queued": 0, "skipped": "the DNS server is not running"}, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error { return s.Enqueue(ctx, tx, "scheduler", nil, zs) })
	r.Logf("queued %d zone(s) the DNS server does not have yet", len(zs))
	return map[string]int{"queued": len(zs)}, err
}

func (s *Service) enqueueApply(ctx context.Context, tx *sql.Tx, createdBy string, z store.Zone) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobApply, applyPayload{ZoneID: z.ID}, jobs.EnqueueOptions{
		AccountID: z.AccountID, LockKey: "dns:" + z.Name, MaxAttempts: 5, CreatedBy: createdBy,
	})
}

// Enqueue queues, inside tx, the jobs that delete zones from the DNS
// server and apply others (as DomainAdded and DomainRemoving return them).
func (s *Service) Enqueue(ctx context.Context, tx *sql.Tx, createdBy string, remove, apply []store.Zone) error {
	for _, z := range remove {
		if _, err := s.jobs.EnqueueTx(ctx, tx, JobDelete, deletePayload{Zone: z.Name}, jobs.EnqueueOptions{
			AccountID: z.AccountID, LockKey: "dns:" + z.Name, MaxAttempts: 5, CreatedBy: createdBy,
		}); err != nil {
			return err
		}
	}
	for _, z := range apply {
		if _, err := s.enqueueApply(ctx, tx, createdBy, z); err != nil {
			return err
		}
	}
	return nil
}

// ZoneRequest builds the agent request for a zone as stored.
func (s *Service) ZoneRequest(ctx context.Context, z *store.Zone) (*agentv1.DNSZoneApplyRequest, error) {
	set, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	recs, err := store.ZoneRecords(ctx, s.db.R, z.ID)
	if err != nil {
		return nil, err
	}
	req := &agentv1.DNSZoneApplyRequest{Zone: z.Name, Nameservers: set.nameservers(z.Name), Hostmaster: "hostmaster." + z.Name}
	for _, r := range recs {
		req.Records = append(req.Records, &agentv1.DNSRecord{Name: r.Name, Type: r.Type, Ttl: r.TTL, Content: r.Content})
	}
	return req, nil
}

func (s *Service) applyJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p applyPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.ZoneID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	z, err := store.ZoneByID(ctx, s.db.R, p.ZoneID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "zone removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	req, err := s.ZoneRequest(ctx, z)
	if err != nil {
		return nil, err
	}
	r.Logf("applying zone %s (%d records)", z.Name, len(req.GetRecords()))
	res, err := s.agent.DNSZoneApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		// dns.sync applies it once PowerDNS is there.
		return map[string]string{"dns": "skipped: no DNS server installed"}, s.db.SetZoneServing(ctx, z.ID, false)
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	return map[string]any{"dns": "applied", "zone": z.Name, "records": len(req.GetRecords()), "changed": res.GetChanged()},
		s.db.SetZoneServing(ctx, z.ID, true)
}

func (s *Service) deleteJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p deletePayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.Zone == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	r.Logf("removing zone %s from the DNS server", p.Zone)
	res, err := s.agent.DNSZoneDelete(ctx, &agentv1.DNSZoneDeleteRequest{Zone: p.Zone})
	switch {
	case status.Code(err) == codes.NotFound:
		return map[string]string{"dns": "skipped: no DNS server installed"}, nil
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	return map[string]any{"zone": p.Zone, "deleted": res.GetDeleted()}, nil
}

// permanentIfRefused stops retrying when the agent refused the request
// itself (bad input): retrying cannot help.
func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

// EnsureDomains gives DNS to every domain that has none yet, such as those
// added before DNS existed. Domains of other kinds come before subdomains,
// so a subdomain finds its domain's zone.
func (s *Service) EnsureDomains(ctx context.Context) (int, error) {
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range accts {
		if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
			continue
		}
		ds, err := s.db.ListDomains(ctx, a.ID)
		if err != nil {
			return n, err
		}
		slices.SortStableFunc(ds, func(x, y store.Domain) int {
			return map[bool]int{false: 0, true: 1}[x.Kind == store.DomainSub] - map[bool]int{false: 0, true: 1}[y.Kind == store.DomainSub]
		})
		for _, d := range ds {
			err := s.db.Tx(ctx, func(tx *sql.Tx) error {
				own, err := store.DomainZones(ctx, tx, d.ID)
				if err != nil {
					return err
				}
				recs, err := store.DomainRecordZones(ctx, tx, d.ID)
				if err != nil || len(own) > 0 || len(recs) > 0 {
					return err // has DNS already
				}
				apply, err := s.DomainAdded(ctx, tx, &d)
				if err != nil || len(apply) == 0 {
					return err
				}
				n++
				return s.Enqueue(ctx, tx, "system", nil, apply)
			})
			if err != nil {
				return n, fmt.Errorf("DNS for %s: %w", d.Name, err)
			}
		}
	}
	return n, nil
}
