// Package files is the file manager's side in xcp-api (USR-FILE-01..03, 05;
// ADR-0009): access checks and audit, then the account's xcp-userd, which
// does the work as the account's user.
package files

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"syscall"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/userfs"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureFileManager switches the file manager on in a feature list.
const FeatureFileManager = "file_manager"

// Service reaches accounts' files through their helpers.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	plans *plans.Service
	agent agentrpc.Client
	// Socket returns where an account's helper listens (the agent's answer
	// is the same; tests point it elsewhere).
	Socket  func(username string) string
	mu      sync.Mutex
	clients map[string]*userfs.Client
}

// NewService returns a files service.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, ag agentrpc.Client, socket func(string) string) *Service {
	return &Service{db: db, audit: rec, plans: pl, agent: ag, Socket: socket, clients: map[string]*userfs.Client{}}
}

// Account is an account whose files the caller may manage.
type Account struct {
	*store.Account
	principal *auth.Principal
}

// Access loads an account the caller may manage: admins the admin-owned
// accounts, users their own if its feature list has the file manager. Files
// are only for an active account (a suspended one has no helper).
func (s *Service) Access(ctx context.Context, p *auth.Principal, accountID string) (*Account, error) {
	if p == nil {
		return nil, apperr.ErrForbidden
	}
	a, err := s.db.AccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	switch p.Login.Role {
	case store.RoleAdmin:
		if a.OwnerID != "" {
			return nil, store.ErrNotFound
		}
	case store.RoleUser:
		if p.Login.AccountID != a.ID {
			return nil, store.ErrNotFound
		}
		_, features, err := s.plans.Entitlements(ctx, a.PackageID)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(features, FeatureFileManager) {
			return nil, apperr.ErrForbidden
		}
	default:
		return nil, apperr.ErrForbidden
	}
	if a.Status != store.AccountActive {
		return nil, apperr.NewConflict("bad_status", "files are available only for an active account")
	}
	return &Account{Account: a, principal: p}, nil
}

func (s *Service) client(username string) *userfs.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[username]
	if !ok {
		c = userfs.NewClient(s.Socket(username))
		s.clients[username] = c
	}
	return c
}

// noHelper tells whether a request failed because the helper's socket is
// not there (after a reboot, or never started) or not the helper's.
func noHelper(err error) bool {
	var op *net.OpError
	// EACCES: a socket file left from before, not the helper's.
	return errors.As(err, &op) && (errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EACCES))
}

// stream sends a request to the account's helper, starting the helper's
// socket through the agent first if it is not there.
func (s *Service) stream(ctx context.Context, a *Account, method, path string, q url.Values, in any) (*http.Response, error) {
	c := s.client(a.Username)
	resp, err := c.Stream(ctx, method, path, q, in)
	if noHelper(err) {
		if _, serr := s.agent.UserHelperStart(ctx, &agentv1.UserHelperStartRequest{Username: a.Username}); serr != nil {
			return nil, serr
		}
		if _, ok := in.(io.Reader); !ok || in == nil {
			resp, err = c.Stream(ctx, method, path, q, in)
		}
	}
	return resp, mapErr(err)
}

func (s *Service) do(ctx context.Context, a *Account, method, path string, q url.Values, in, out any) error {
	resp, err := s.stream(ctx, a, method, path, q, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return decode(resp.Body, out)
}

// mapErr turns the helper's errors into the API's.
func mapErr(err error) error {
	var e *userfs.Error
	if !errors.As(err, &e) {
		return err
	}
	switch e.Code {
	case userfs.CodeNotFound:
		return store.ErrNotFound
	case userfs.CodeExists:
		return apperr.NewConflict("exists", e.Message)
	case userfs.CodeInvalid:
		return &validate.Error{Field: "path", Code: validate.CodeFormat, Message: e.Message}
	case userfs.CodeTooLarge, userfs.CodeTooMany:
		return apperr.NewConflict(e.Code, e.Message)
	}
	return err
}

func (s *Service) record(ctx context.Context, c auth.Client, a *Account, action string, details map[string]any) {
	p := a.principal
	_ = s.audit.Record(ctx, audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "account", TargetID: a.ID, AccountID: a.ID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	})
}

// Listing is a folder and what is in it.
type Listing struct {
	Dir   userfs.Entry   `json:"dir"`
	Items []userfs.Entry `json:"items"`
}

// List lists a folder.
func (s *Service) List(ctx context.Context, a *Account, path string) (Listing, error) {
	var l Listing
	err := s.do(ctx, a, http.MethodGet, "/v1/list", url.Values{"path": {path}}, nil, &l)
	return l, err
}

// Download opens a file for reading; the caller closes the response.
func (s *Service) Download(ctx context.Context, c auth.Client, a *Account, path string) (*http.Response, error) {
	resp, err := s.stream(ctx, a, http.MethodGet, "/v1/download", url.Values{"path": {path}}, nil)
	if err == nil {
		s.record(ctx, c, a, "files.download", map[string]any{"path": path})
	}
	return resp, err
}

// Upload stores body at path.
func (s *Service) Upload(ctx context.Context, c auth.Client, a *Account, path string, overwrite bool, body io.Reader) (userfs.Entry, error) {
	q := url.Values{"path": {path}}
	if overwrite {
		q.Set("overwrite", "1")
	}
	// The body can be read only once: start the helper before sending it.
	if _, err := s.Stat(ctx, a, ""); err != nil {
		return userfs.Entry{}, err
	}
	var e userfs.Entry
	if err := s.do(ctx, a, http.MethodPut, "/v1/upload", q, body, &e); err != nil {
		return e, err
	}
	s.record(ctx, c, a, "files.upload", map[string]any{"path": e.Path, "size": e.Size, "overwrite": overwrite})
	return e, nil
}

// Stat describes a path.
func (s *Service) Stat(ctx context.Context, a *Account, path string) (userfs.Entry, error) {
	var e userfs.Entry
	err := s.do(ctx, a, http.MethodGet, "/v1/stat", url.Values{"path": {path}}, nil, &e)
	return e, err
}

// Op is a change with a JSON body: mkdir, rename, copy, trash, chmod, compress, extract.
func (s *Service) Op(ctx context.Context, c auth.Client, a *Account, op string, in map[string]any) (any, error) {
	if !slices.Contains([]string{"mkdir", "rename", "copy", "trash", "chmod", "compress", "extract"}, op) {
		return nil, store.ErrNotFound
	}
	var out any
	if err := s.do(ctx, a, http.MethodPost, "/v1/"+op, nil, in, &out); err != nil {
		return nil, err
	}
	s.record(ctx, c, a, "files."+op, in)
	return out, nil
}

// Search finds names below a folder.
func (s *Service) Search(ctx context.Context, a *Account, path, q string) (any, error) {
	var out any
	err := s.do(ctx, a, http.MethodGet, "/v1/search", url.Values{"path": {path}, "q": {q}}, nil, &out)
	return out, err
}

// Usage measures a folder.
func (s *Service) Usage(ctx context.Context, a *Account, path string) (userfs.Usage, error) {
	var u userfs.Usage
	err := s.do(ctx, a, http.MethodGet, "/v1/usage", url.Values{"path": {path}}, nil, &u)
	return u, err
}

// ReadText opens a file for the editor.
func (s *Service) ReadText(ctx context.Context, a *Account, path, enc string) (userfs.Text, error) {
	var t userfs.Text
	err := s.do(ctx, a, http.MethodGet, "/v1/text", url.Values{"path": {path}, "encoding": {enc}}, nil, &t)
	return t, err
}

// WriteText saves the editor's text.
func (s *Service) WriteText(ctx context.Context, c auth.Client, a *Account, path string, t userfs.Text) (userfs.Entry, error) {
	var e userfs.Entry
	if err := s.do(ctx, a, http.MethodPut, "/v1/text", url.Values{"path": {path}}, t, &e); err != nil {
		return e, err
	}
	s.record(ctx, c, a, "files.edit", map[string]any{"path": e.Path, "size": e.Size, "encoding": t.Encoding})
	return e, nil
}

func decode(r io.Reader, out any) error {
	return json.NewDecoder(r).Decode(out)
}
