package backups_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/backups"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

func (e *env) useBox(t *testing.T) {
	t.Helper()
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	e.svc.UseBox(box)
}

func TestDestinations(t *testing.T) {
	e := newEnv(t)
	e.useBox(t)
	_, user := e.account(t, "alice")
	if _, err := e.svc.Destinations(ctx, user); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user lists destinations: %v", err)
	}
	if _, err := e.svc.CreateDestination(ctx, client, user, backups.DestinationInput{Name: "x", Kind: "folder", Path: "/mnt/backup"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user adds one: %v", err)
	}

	f, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{Name: "Disk", Kind: "folder", Path: "/mnt/backup"})
	if err != nil || f.Kind != "folder" || f.Path != "/mnt/backup" {
		t.Fatalf("folder: %+v %v", f, err)
	}
	// SFTP without a host key: trusted on first use, the key is returned.
	sf, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{
		Name: "Offsite", Kind: "sftp", Host: "backup.example.com", User: "xcp", Password: "a secret password", Path: "xcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sf.HostKeyNew || !strings.HasPrefix(sf.HostKey, "SHA256:") || sf.Port != 22 || !sf.HasPassword || sf.HasPrivateKey {
		t.Errorf("sftp: %+v", sf)
	}
	s3, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{
		Name: "Bucket", Kind: "s3", Bucket: "my-backups", Region: "eu-west-1", AccessKey: "AKIATEST", SecretKey: "s3 secret", Path: "xcp",
	})
	if err != nil || !s3.HasSecretKey {
		t.Fatalf("s3: %+v %v", s3, err)
	}
	// Secrets are sealed in the database, and never in the view.
	d, _ := e.db.BackupDestinationByID(ctx, sf.ID)
	if strings.Contains(d.Config, "a secret password") || strings.Contains(string(d.SecretsEnc), "a secret password") || len(d.SecretsEnc) == 0 {
		t.Errorf("the password is stored in the open: %s", d.Config)
	}
	list, _ := e.svc.Destinations(ctx, e.admin)
	if len(list) != 3 {
		t.Fatalf("list: %+v", list)
	}

	// Invalid ones, a name taken, an unreachable one.
	for name, in := range map[string]backups.DestinationInput{
		"name":      {Name: "", Kind: "folder", Path: "/mnt/x"},
		"kind":      {Name: "A", Kind: "ftp"},
		"relative":  {Name: "B", Kind: "folder", Path: "mnt/x"},
		"system":    {Name: "C", Kind: "folder", Path: "/etc/xcp"},
		"sftp host": {Name: "D", Kind: "sftp", Host: "a b", User: "x", Password: "p"},
		"s3 bucket": {Name: "E", Kind: "s3", Bucket: "X", AccessKey: "abc", SecretKey: "s"},
	} {
		if _, err := e.svc.CreateDestination(ctx, client, e.admin, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{Name: "Disk", Kind: "folder", Path: "/mnt/other"}); !conflict(err, "name_taken") {
		t.Errorf("the same name twice: %v", err)
	}
	e.fake.FailRemote(specOfFolder("/mnt/down"), "connection refused")
	if _, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{Name: "Down", Kind: "folder", Path: "/mnt/down"}); !field(err, "destination") {
		t.Errorf("an unreachable destination was saved: %v", err)
	}

	// Changing keeps the secrets when none are given.
	up, err := e.svc.UpdateDestination(ctx, client, e.admin, sf.ID, backups.DestinationInput{
		Name: "Offsite 2", Host: "backup.example.com", User: "xcp", Path: "xcp2", HostKey: sf.HostKey,
	})
	if err != nil || up.Name != "Offsite 2" || !up.HasPassword || up.Path != "xcp2" || up.HostKeyNew {
		t.Fatalf("update: %+v %v", up, err)
	}
	if err := e.svc.TestDestination(ctx, e.admin, f.ID); err != nil {
		t.Errorf("test: %v", err)
	}
	e.fake.FailRemote(specOfFolder("/mnt/backup"), "disk is gone")
	if err := e.svc.TestDestination(ctx, e.admin, f.ID); !field(err, "destination") {
		t.Errorf("test of a failing destination: %v", err)
	}
	e.fake.FailRemote(specOfFolder("/mnt/backup"), "")
	if err := e.svc.DeleteDestination(ctx, client, e.admin, s3.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteDestination(ctx, client, e.admin, s3.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}

func TestSendAndRetainRemote(t *testing.T) {
	e := newEnv(t)
	e.useBox(t)
	a, user := e.account(t, "alice")
	dest, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{Name: "Disk", Kind: "folder", Path: "/mnt/backup"})
	if err != nil {
		t.Fatal(err)
	}
	spec := specOfFolder("/mnt/backup")

	// The schedule names the destination: bad ids are refused, and it cannot be deleted then.
	if _, err := e.svc.SetSchedule(ctx, client, e.admin, backups.Schedule{Enabled: true, Frequency: "daily", Hour: 2, Day: 1, Keep: 5, DestinationID: "nope"}); !field(err, "destination_id") {
		t.Errorf("unknown destination in the schedule: %v", err)
	}
	if _, err := e.svc.SetSchedule(ctx, client, e.admin, backups.Schedule{Enabled: true, Frequency: "daily", Hour: 2, Day: 1, Keep: 5, RemoteKeep: 2, DestinationID: dest.ID}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteDestination(ctx, client, e.admin, dest.ID); !conflict(err, "in_use") {
		t.Errorf("deleting the scheduled destination: %v", err)
	}

	// Four scheduled runs: each copy goes to the destination; it keeps the newest 2.
	for day := range 4 {
		e.svc.Now = func() time.Time { return time.Date(2026, 11, 2+day, 2, 5, 0, 0, time.UTC) }
		id, _ := e.q.Enqueue(ctx, backups.JobSchedule, struct{}{}, jobs.EnqueueOptions{})
		e.waitJob(t, id)
		waitFor(t, func() bool {
			o, _ := e.svc.Overview(ctx, user, a.ID)
			for _, b := range o.Backups {
				if b.Status == store.BackupRunning {
					return false
				}
			}
			return true
		})
		waitFor(t, func() bool { // the upload and the pruning follow the backup
			o, _ := e.svc.Overview(ctx, e.admin, a.ID)
			for _, b := range o.Backups {
				for _, r := range b.Remote {
					if r.Status == store.RemoteRunning {
						return false
					}
				}
			}
			return len(e.fake.RemoteFiles(spec)) <= 2 && len(o.Backups) > 0 && len(o.Backups[0].Remote) == 1
		})
	}
	files := e.fake.RemoteFiles(spec)
	if len(files) != 2 {
		t.Fatalf("remote copies: %d, want the newest 2: %v", len(files), files)
	}
	local := e.fake.Backups("alice")
	for k, v := range files {
		_, file, _ := strings.Cut(k, "/")
		if string(v) != string(local[file]) {
			t.Errorf("%s: the copy differs from the backup", file)
		}
	}
	// Users do not see where the copies are; admins do.
	uo, _ := e.svc.Overview(ctx, user, a.ID)
	for _, b := range uo.Backups {
		if len(b.Remote) != 0 {
			t.Errorf("a user sees remote copies: %+v", b.Remote)
		}
	}
	ao, _ := e.svc.Overview(ctx, e.admin, a.ID)
	if len(ao.Backups[0].Remote) != 1 || ao.Backups[0].Remote[0].Status != "ok" || ao.Backups[0].Remote[0].Destination != "Disk" {
		t.Errorf("admin view: %+v", ao.Backups[0].Remote)
	}

	// Sending by hand; a failing destination is recorded and retried.
	b := ao.Backups[0]
	e.fake.FailRemote(spec, "disk is full")
	if _, err := e.svc.SendToDestination(ctx, client, e.admin, b.ID, dest.ID); err != nil {
		t.Fatal(err)
	}
	// The job is retried with a pause; the first failure is already recorded.
	waitFor(t, func() bool {
		o, _ := e.svc.Overview(ctx, e.admin, a.ID)
		return len(o.Backups[0].Remote) == 1 && o.Backups[0].Remote[0].Status == "failed"
	})
	ao, _ = e.svc.Overview(ctx, e.admin, a.ID)
	if r := ao.Backups[0].Remote[0]; !strings.Contains(r.Detail, "disk is full") {
		t.Errorf("failed copy: %+v", r)
	}
	e.fake.FailRemote(spec, "")
	if _, err := e.svc.SendToDestination(ctx, client, user, b.ID, dest.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user sends: %v", err)
	}
	if _, err := e.svc.SendToDestination(ctx, client, e.admin, b.ID, "nope"); err == nil {
		t.Error("an unknown destination")
	}
}

func TestFetchFromDestination(t *testing.T) {
	e := newEnv(t)
	e.useBox(t)
	dest, err := e.svc.CreateDestination(ctx, client, e.admin, backups.DestinationInput{Name: "Disk", Kind: "folder", Path: "/mnt/backup"})
	if err != nil {
		t.Fatal(err)
	}
	spec := specOfFolder("/mnt/backup")
	e.fake.PutRemote(spec, "ghost", "ghost-20260101T020000Z.tar.zst", []byte("archive bytes"))

	files, err := e.svc.DestinationFiles(ctx, e.admin, dest.ID, "")
	if err != nil || len(files) != 1 || files[0].Username != "ghost" || files[0].OnServer || files[0].Size != 13 {
		t.Fatalf("files: %+v %v", files, err)
	}
	if _, err := e.svc.FetchFromDestination(ctx, client, e.admin, dest.ID, "ghost", "../x"); err == nil {
		t.Error("a bad file name")
	}
	id, err := e.svc.FetchFromDestination(ctx, client, e.admin, dest.ID, "ghost", "ghost-20260101T020000Z.tar.zst")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, id)
	// It is now a backup of a removed account, with a copy at the destination.
	orphans, err := e.svc.Orphans(ctx, e.admin)
	if err != nil || len(orphans) != 1 || orphans[0].Username != "ghost" || len(orphans[0].Remote) != 1 {
		t.Fatalf("orphans: %+v %v", orphans, err)
	}
	if string(e.fake.Backups("ghost")["ghost-20260101T020000Z.tar.zst"]) != "archive bytes" {
		t.Error("the file is not in the backup folder")
	}
	files, _ = e.svc.DestinationFiles(ctx, e.admin, dest.ID, "ghost")
	if !files[0].OnServer {
		t.Error("the listing does not know the server has it")
	}
	if _, err := e.svc.FetchFromDestination(ctx, client, e.admin, dest.ID, "ghost", "ghost-20260101T020000Z.tar.zst"); !conflict(err, "on_server") {
		t.Errorf("fetching again: %v", err)
	}
}

func specOfFolder(path string) *agentv1.RemoteSpec {
	return &agentv1.RemoteSpec{Kind: "folder", Path: path}
}
