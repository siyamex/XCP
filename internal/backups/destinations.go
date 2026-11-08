package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

// Remote destinations for copies of the backups (ADR-0031).

// Job kinds of the remote copies.
const (
	JobUpload = "backup.upload"
	JobFetch  = "backup.fetch"
)

const destinationAD = "backup-destination"

// UseBox gives the service the box that seals the destinations' secrets.
func (s *Service) UseBox(b *secretbox.Box) { s.box = b }

// RemoteCopy is a backup's copy at a destination, as the admin sees it.
type RemoteCopy struct {
	DestinationID string    `json:"destination_id"`
	Destination   string    `json:"destination"`
	Status        string    `json:"status"` // running, ok or failed
	Detail        string    `json:"detail"`
	Size          int64     `json:"size"`
	At            time.Time `json:"at"`
}

// Destination is the API view of a destination: never its secrets.
type Destination struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Path          string    `json:"path"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	User          string    `json:"user"`
	HostKey       string    `json:"host_key"`
	Endpoint      string    `json:"endpoint"`
	Region        string    `json:"region"`
	Bucket        string    `json:"bucket"`
	AccessKey     string    `json:"access_key"`
	UseTLS        bool      `json:"use_tls"`
	HasPassword   bool      `json:"has_password"`
	HasPrivateKey bool      `json:"has_private_key"`
	HasSecretKey  bool      `json:"has_secret_key"`
	CreatedAt     time.Time `json:"created_at"`
	HostKeyNew    bool      `json:"host_key_new,omitempty"` // the host key was just learned: check it
}

// DestinationInput makes or changes a destination. Empty secrets keep the
// stored ones when changing.
type DestinationInput struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	HostKey    string `json:"host_key"`
	Endpoint   string `json:"endpoint"`
	Region     string `json:"region"`
	Bucket     string `json:"bucket"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	UseTLS     bool   `json:"use_tls"`
}

type destConfig struct {
	Path      string `json:"path,omitempty"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	User      string `json:"user,omitempty"`
	HostKey   string `json:"host_key,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	UseTLS    bool   `json:"use_tls,omitempty"`
}

type destSecrets struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	SecretKey  string `json:"secret_key,omitempty"`
}

var destNameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,59}$`)

func (s *Service) openDest(d *store.BackupDestination) (destConfig, destSecrets, error) {
	var c destConfig
	var sec destSecrets
	if err := json.Unmarshal([]byte(d.Config), &c); err != nil {
		return c, sec, err
	}
	if len(d.SecretsEnc) > 0 {
		if s.box == nil {
			return c, sec, errors.New("the backup destinations need the master key")
		}
		raw, err := s.box.Open(d.SecretsEnc, []byte(destinationAD))
		if err != nil {
			return c, sec, err
		}
		if err := json.Unmarshal(raw, &sec); err != nil {
			return c, sec, err
		}
	}
	return c, sec, nil
}

func specOf(kind string, c destConfig, sec destSecrets) *agentv1.RemoteSpec {
	return &agentv1.RemoteSpec{
		Kind: kind, Path: c.Path, Host: c.Host, Port: int32(c.Port), User: c.User, Password: sec.Password, PrivateKey: sec.PrivateKey, //nolint:gosec // G115: 1..65535
		HostKey: c.HostKey, Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, AccessKey: c.AccessKey, SecretKey: sec.SecretKey, UseTls: c.UseTLS,
	}
}

func (s *Service) spec(d *store.BackupDestination) (*agentv1.RemoteSpec, error) {
	c, sec, err := s.openDest(d)
	if err != nil {
		return nil, err
	}
	return specOf(d.Kind, c, sec), nil
}

func destView(d *store.BackupDestination, c destConfig, sec destSecrets) Destination {
	return Destination{
		ID: d.ID, Name: d.Name, Kind: d.Kind, Path: c.Path, Host: c.Host, Port: c.Port, User: c.User, HostKey: c.HostKey,
		Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, AccessKey: c.AccessKey, UseTLS: c.UseTLS,
		HasPassword: sec.Password != "", HasPrivateKey: sec.PrivateKey != "", HasSecretKey: sec.SecretKey != "", CreatedAt: d.CreatedAt,
	}
}

// agentMessage is what the agent said, without the gRPC wrapping.
func agentMessage(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Message()
	}
	return err.Error()
}

func unusable(err error) error {
	return badField("destination", "unreachable", "this destination did not work: "+agentMessage(err))
}

// Destinations lists the destinations (admins).
func (s *Service) Destinations(ctx context.Context, p *auth.Principal) ([]Destination, error) {
	if err := adminOnly(p); err != nil {
		return nil, err
	}
	ds, err := s.db.BackupDestinations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Destination, 0, len(ds))
	for i := range ds {
		c, sec, err := s.openDest(&ds[i])
		if err != nil {
			return nil, err
		}
		out = append(out, destView(&ds[i], c, sec))
	}
	return out, nil
}

func (s *Service) build(ctx context.Context, in DestinationInput, old *store.BackupDestination) (*store.BackupDestination, destConfig, destSecrets, bool, error) {
	var c destConfig
	var sec destSecrets
	if old != nil {
		var err error
		if c, sec, err = s.openDest(old); err != nil {
			return nil, c, sec, false, err
		}
	}
	name := strings.TrimSpace(in.Name)
	if !destNameRe.MatchString(name) {
		return nil, c, sec, false, badField("name", "format", "1 to 60 letters, digits, spaces and . _ -")
	}
	kind := in.Kind
	if old != nil {
		kind = old.Kind
	}
	if kind != agent.RemoteFolder && kind != agent.RemoteSFTP && kind != agent.RemoteS3 {
		return nil, c, sec, false, badField("kind", "format", "folder, sftp or s3")
	}
	// Where it is: replaced as a whole. Secrets: replaced only when given.
	c = destConfig{
		Path: strings.TrimSpace(in.Path), Host: strings.ToLower(strings.TrimSpace(in.Host)), Port: in.Port, User: strings.TrimSpace(in.User),
		HostKey: strings.TrimSpace(in.HostKey), Endpoint: strings.ToLower(strings.TrimSpace(in.Endpoint)), Region: strings.TrimSpace(in.Region),
		Bucket: strings.TrimSpace(in.Bucket), AccessKey: strings.TrimSpace(in.AccessKey), UseTLS: in.UseTLS,
	}
	if kind == agent.RemoteSFTP && c.Port == 0 {
		c.Port = 22
	}
	if in.Password != "" {
		sec.Password = in.Password
	}
	if in.PrivateKey != "" {
		sec.PrivateKey = in.PrivateKey
	}
	if in.SecretKey != "" {
		sec.SecretKey = in.SecretKey
	}
	if kind != agent.RemoteSFTP {
		sec.Password, sec.PrivateKey = "", ""
	}
	if kind != agent.RemoteS3 {
		sec.SecretKey = ""
	}
	learned := false
	spec := specOf(kind, c, sec)
	if err := agent.CheckRemote(agentSpec(spec)); err != nil {
		return nil, c, sec, false, badField("destination", "format", strings.TrimPrefix(err.Error(), agent.ErrInvalidRequest.Error()+": "))
	}
	if kind == agent.RemoteSFTP && c.HostKey == "" {
		res, err := s.agent.BackupRemoteTest(ctx, &agentv1.BackupRemoteTestRequest{Spec: spec})
		if err != nil {
			return nil, c, sec, false, unusable(err)
		}
		c.HostKey, learned = res.GetHostKey(), true
		spec = specOf(kind, c, sec)
	}
	if _, err := s.agent.BackupRemoteTest(ctx, &agentv1.BackupRemoteTestRequest{Spec: spec}); err != nil {
		return nil, c, sec, false, unusable(err)
	}
	cfg, _ := json.Marshal(c) //nolint:gosec // G117: the access key id is not a secret; the secret key is sealed below
	d := &store.BackupDestination{Name: name, Kind: kind, Config: string(cfg)}
	if old != nil {
		d.ID, d.CreatedAt = old.ID, old.CreatedAt
	}
	if sec != (destSecrets{}) {
		raw, _ := json.Marshal(sec) //nolint:gosec // G117: sealed with the master key right below
		if s.box == nil {
			return nil, c, sec, false, errors.New("the backup destinations need the master key")
		}
		d.SecretsEnc = s.box.Seal(raw, []byte(destinationAD))
	}
	return d, c, sec, learned, nil
}

// agentSpec converts the wire spec back for the agent's own checks.
func agentSpec(s *agentv1.RemoteSpec) agent.RemoteSpec {
	return agent.RemoteSpec{
		Kind: s.GetKind(), Path: s.GetPath(), Host: s.GetHost(), Port: int(s.GetPort()), User: s.GetUser(), Password: s.GetPassword(),
		PrivateKey: s.GetPrivateKey(), HostKey: s.GetHostKey(), Endpoint: s.GetEndpoint(), Region: s.GetRegion(), Bucket: s.GetBucket(),
		AccessKey: s.GetAccessKey(), SecretKey: s.GetSecretKey(), UseTLS: s.GetUseTls(),
	}
}

// CreateDestination tests and saves a destination (admins). An SFTP server
// whose host key was not given is trusted on first use: the key it
// presents is saved and returned for the admin to check.
func (s *Service) CreateDestination(ctx context.Context, c auth.Client, p *auth.Principal, in DestinationInput) (Destination, error) {
	if err := adminOnly(p); err != nil {
		return Destination{}, err
	}
	d, cfg, sec, learned, err := s.build(ctx, in, nil)
	if err != nil {
		return Destination{}, err
	}
	d.ID = ids.New()
	if err := store.InsertBackupDestination(ctx, s.db.W, d); errors.Is(err, store.ErrConflict) {
		return Destination{}, apperr.NewConflict("name_taken", "a destination with this name exists already")
	} else if err != nil {
		return Destination{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "backup.destination.create", "", d.ID, map[string]any{"name": d.Name, "kind": d.Kind})); err != nil {
		return Destination{}, err
	}
	v := destView(d, cfg, sec)
	v.HostKeyNew = learned
	return v, nil
}

// UpdateDestination changes and re-tests a destination (admins).
func (s *Service) UpdateDestination(ctx context.Context, c auth.Client, p *auth.Principal, id string, in DestinationInput) (Destination, error) {
	if err := adminOnly(p); err != nil {
		return Destination{}, err
	}
	old, err := s.db.BackupDestinationByID(ctx, id)
	if err != nil {
		return Destination{}, err
	}
	d, cfg, sec, learned, err := s.build(ctx, in, old)
	if err != nil {
		return Destination{}, err
	}
	if d.SecretsEnc == nil {
		d.SecretsEnc = old.SecretsEnc
	}
	if err := store.UpdateBackupDestination(ctx, s.db.W, d); errors.Is(err, store.ErrConflict) {
		return Destination{}, apperr.NewConflict("name_taken", "a destination with this name exists already")
	} else if err != nil {
		return Destination{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "backup.destination.update", "", d.ID, map[string]any{"name": d.Name})); err != nil {
		return Destination{}, err
	}
	v := destView(d, cfg, sec)
	v.HostKeyNew = learned
	return v, nil
}

// DeleteDestination forgets a destination. The files stay where they are.
func (s *Service) DeleteDestination(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	if err := adminOnly(p); err != nil {
		return err
	}
	d, err := s.db.BackupDestinationByID(ctx, id)
	if err != nil {
		return err
	}
	if sched, err := s.schedule(ctx); err == nil && sched.DestinationID == id {
		return apperr.NewConflict("in_use", "the backup schedule sends copies here: choose another destination or none first")
	}
	if err := store.DeleteBackupDestination(ctx, s.db.W, id); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "backup.destination.delete", "", id, map[string]any{"name": d.Name}))
}

// TestDestination connects to a destination again (admins).
func (s *Service) TestDestination(ctx context.Context, p *auth.Principal, id string) error {
	if err := adminOnly(p); err != nil {
		return err
	}
	d, err := s.db.BackupDestinationByID(ctx, id)
	if err != nil {
		return err
	}
	spec, err := s.spec(d)
	if err != nil {
		return err
	}
	if _, err := s.agent.BackupRemoteTest(ctx, &agentv1.BackupRemoteTestRequest{Spec: spec}); err != nil {
		return unusable(err)
	}
	return nil
}

// RemoteFile is a backup at a destination.
type RemoteFile struct {
	Username string    `json:"username"`
	File     string    `json:"file"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	OnServer bool      `json:"on_server"` // this server has a record of it
}

// DestinationFiles lists what a destination holds (admins).
func (s *Service) DestinationFiles(ctx context.Context, p *auth.Principal, id, username string) ([]RemoteFile, error) {
	if err := adminOnly(p); err != nil {
		return nil, err
	}
	d, err := s.db.BackupDestinationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	spec, err := s.spec(d)
	if err != nil {
		return nil, err
	}
	res, err := s.agent.BackupRemoteList(ctx, &agentv1.BackupRemoteListRequest{Spec: spec, Username: username})
	if err != nil {
		return nil, unusable(err)
	}
	out := make([]RemoteFile, 0, len(res.GetObjects()))
	for _, o := range res.GetObjects() {
		_, err := s.db.BackupByFile(ctx, o.GetUsername(), o.GetFile())
		out = append(out, RemoteFile{Username: o.GetUsername(), File: o.GetFile(), Size: o.GetSize(), Modified: time.Unix(o.GetModifiedUnix(), 0).UTC(), OnServer: err == nil})
	}
	return out, nil
}

type uploadPayload struct {
	BackupID      string `json:"backup_id"`
	DestinationID string `json:"destination_id"`
}

type fetchPayload struct {
	DestinationID string `json:"destination_id"`
	Username      string `json:"username"`
	File          string `json:"file"`
}

// SendToDestination queues the copy of a finished backup (admins).
func (s *Service) SendToDestination(ctx context.Context, c auth.Client, p *auth.Principal, backupID, destID string) (string, error) {
	if err := adminOnly(p); err != nil {
		return "", err
	}
	b, err := s.db.BackupByID(ctx, backupID)
	if err != nil {
		return "", err
	}
	if b.Status != store.BackupOK || b.File == "" {
		return "", apperr.NewConflict("not_ready", "the backup is not finished")
	}
	d, err := s.db.BackupDestinationByID(ctx, destID)
	if err != nil {
		return "", badField("destination_id", "format", "no such destination")
	}
	id, err := s.queueUpload(ctx, b, d.ID)
	if err != nil {
		return "", err
	}
	return id, s.audit.Record(ctx, event(c, p, "backup.upload", b.AccountID, b.ID, map[string]any{"destination": d.Name, "file": b.File}))
}

func (s *Service) queueUpload(ctx context.Context, b *store.Backup, destID string) (string, error) {
	if err := store.SetBackupRemote(ctx, s.db.W, store.BackupRemote{BackupID: b.ID, DestinationID: destID, Status: store.RemoteRunning, At: s.Now().UTC()}); err != nil {
		return "", err
	}
	return s.jobs.Enqueue(ctx, JobUpload, uploadPayload{BackupID: b.ID, DestinationID: destID},
		jobs.EnqueueOptions{AccountID: b.AccountID, LockKey: "backup-upload:" + destID, MaxAttempts: 3})
}

// FetchFromDestination queues the copy of a backup from a destination to this
// server, where it appears with the backups (admins).
func (s *Service) FetchFromDestination(ctx context.Context, c auth.Client, p *auth.Principal, destID, username, file string) (string, error) {
	if err := adminOnly(p); err != nil {
		return "", err
	}
	d, err := s.db.BackupDestinationByID(ctx, destID)
	if err != nil {
		return "", err
	}
	if err := agent.CheckBackupFile(username, file); err != nil {
		return "", badField("file", "format", "not the name of an account backup")
	}
	if _, err := s.db.BackupByFile(ctx, username, file); err == nil {
		return "", apperr.NewConflict("on_server", "this server has that backup already")
	}
	id, err := s.jobs.Enqueue(ctx, JobFetch, fetchPayload{DestinationID: d.ID, Username: username, File: file},
		jobs.EnqueueOptions{LockKey: "backup-upload:" + d.ID, MaxAttempts: 2})
	if err != nil {
		return "", err
	}
	return id, s.audit.Record(ctx, event(c, p, "backup.fetch", "", id, map[string]any{"destination": d.Name, "username": username, "file": file}))
}

func (s *Service) uploadJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p uploadPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return nil, jobs.Permanent(err)
	}
	b, err := s.db.BackupByID(ctx, p.BackupID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "the backup was removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	d, err := s.db.BackupDestinationByID(ctx, p.DestinationID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "the destination was removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	spec, err := s.spec(d)
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	rec := store.BackupRemote{BackupID: b.ID, DestinationID: d.ID, At: s.Now().UTC()}
	res, err := s.agent.BackupRemoteUpload(ctx, &agentv1.BackupRemoteFileRequest{Spec: spec, Username: b.Username, File: b.File})
	if err != nil {
		rec.Status, rec.Detail = store.RemoteFailed, agentMessage(err)
		_ = store.SetBackupRemote(context.WithoutCancel(ctx), s.db.W, rec)
		return nil, err
	}
	rec.Status, rec.Size = store.RemoteOK, res.GetSize()
	if err := store.SetBackupRemote(ctx, s.db.W, rec); err != nil {
		return nil, err
	}
	r.Logf("%s sent to %s: %d bytes", b.File, d.Name, rec.Size)
	pruned := 0
	if b.Kind == store.BackupScheduled {
		n, err := s.pruneRemote(ctx, d, spec, b.Username)
		pruned = n
		if err != nil {
			r.Logf("prune the copies at %s: %v", d.Name, err)
		}
	}
	return map[string]any{"destination": d.Name, "size": rec.Size, "pruned": pruned}, nil
}

var remoteFileRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}-[0-9]{8}T[0-9]{6}Z\.tar\.zst$`)

// pruneRemote keeps the newest copies of an account at a destination.
func (s *Service) pruneRemote(ctx context.Context, d *store.BackupDestination, spec *agentv1.RemoteSpec, username string) (int, error) {
	sched, err := s.schedule(ctx)
	if err != nil {
		return 0, err
	}
	keep := sched.RemoteKeep
	if keep < 1 {
		keep = sched.Keep
	}
	res, err := s.agent.BackupRemoteList(ctx, &agentv1.BackupRemoteListRequest{Spec: spec, Username: username})
	if err != nil {
		return 0, err
	}
	var files []string
	for _, o := range res.GetObjects() {
		if remoteFileRe.MatchString(o.GetFile()) {
			files = append(files, o.GetFile())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files))) // names carry the time: newest first
	n := 0
	var errs []error
	for _, f := range files[min(keep, len(files)):] {
		if _, err := s.agent.BackupRemoteDelete(ctx, &agentv1.BackupRemoteFileRequest{Spec: spec, Username: username, File: f}); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
		if b, err := s.db.BackupByFile(ctx, username, f); err == nil {
			_ = store.DeleteBackupRemote(ctx, s.db.W, b.ID, d.ID)
		}
	}
	return n, errors.Join(errs...)
}

func (s *Service) fetchJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p fetchPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return nil, jobs.Permanent(err)
	}
	d, err := s.db.BackupDestinationByID(ctx, p.DestinationID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "the destination was removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.db.BackupByFile(ctx, p.Username, p.File); err == nil {
		return map[string]string{"skipped": "this server has that backup already"}, nil
	}
	spec, err := s.spec(d)
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	res, err := s.agent.BackupRemoteFetch(ctx, &agentv1.BackupRemoteFileRequest{Spec: spec, Username: p.Username, File: p.File})
	if err != nil {
		return nil, err
	}
	b := &store.Backup{
		ID: ids.New(), Username: p.Username, Kind: store.BackupManual, Status: store.BackupOK, File: p.File, Size: res.GetSize(),
		Detail: "fetched from " + d.Name, CreatedAt: s.Now().UTC(),
	}
	if a, err := s.db.AccountByUsername(ctx, p.Username); err == nil {
		b.AccountID = a.ID
	}
	now := s.Now().UTC()
	b.FinishedAt = &now
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.InsertBackup(ctx, tx, b); err != nil {
			return err
		}
		return store.SetBackupRemote(ctx, tx, store.BackupRemote{BackupID: b.ID, DestinationID: d.ID, Status: store.RemoteOK, Size: b.Size, At: now})
	})
	if err != nil {
		return nil, err
	}
	r.Logf("%s fetched from %s: %d bytes", p.File, d.Name, b.Size)
	return map[string]any{"file": p.File, "size": b.Size, "orphan": b.AccountID == ""}, nil
}

// attachRemote adds the copies at destinations to backups the admin looks at.
func (s *Service) attachRemote(ctx context.Context, p *auth.Principal, list []Backup) {
	if p == nil || p.Login.Role != store.RoleAdmin || len(list) == 0 {
		return
	}
	idl := make([]string, len(list))
	for i, b := range list {
		idl[i] = b.ID
	}
	m, err := s.db.BackupRemotes(ctx, idl)
	if err != nil {
		return
	}
	for i := range list {
		list[i].Remote = []RemoteCopy{}
		for _, r := range m[list[i].ID] {
			list[i].Remote = append(list[i].Remote, RemoteCopy{DestinationID: r.DestinationID, Destination: r.DestinationName, Status: r.Status, Detail: r.Detail, Size: r.Size, At: r.At})
		}
	}
}

func (s *Service) attachOrphanRemote(ctx context.Context, list []Orphan) {
	if len(list) == 0 {
		return
	}
	idl := make([]string, len(list))
	for i, o := range list {
		idl[i] = o.ID
	}
	m, err := s.db.BackupRemotes(ctx, idl)
	if err != nil {
		return
	}
	for i := range list {
		for _, r := range m[list[i].ID] {
			list[i].Remote = append(list[i].Remote, RemoteCopy{DestinationID: r.DestinationID, Destination: r.DestinationName, Status: r.Status, Detail: r.Detail, Size: r.Size, At: r.At})
		}
	}
}
