// Package messages sends email from the panel to its customers: the welcome
// message of a new account (RSL-ACC-09) and a message to all customers
// (RSL-UI-03). ADR-0027.
package messages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Job kinds.
const (
	JobWelcome   = "messages.welcome"
	JobBroadcast = "messages.broadcast"
)

// Limits of a message.
const (
	MaxSubject    = 200
	MaxBody       = 8000
	MaxRecipients = 2000
	// BroadcastGap is how long a sender waits between two messages to all customers.
	BroadcastGap = 10 * time.Minute
)

// Variables a message may use, written {{name}}.
var Variables = []string{"username", "domain", "panel_url", "owner"}

var varRe = regexp.MustCompile(`\{\{\s*([A-Za-z_]+)\s*\}\}`)

// Mailer sends one message.
type Mailer interface {
	Send(ctx context.Context, from, to, subject, body string) error
}

// Info tells the service who it writes as and where the panel is.
type Info struct {
	From     func(ctx context.Context) string // sender address
	PanelURL func(ctx context.Context) string // like https://panel.example.com:2443
}

// Service sends the panel's messages.
type Service struct {
	db     *store.DB
	audit  *audit.Recorder
	jobs   *jobs.Queue
	mailer Mailer
	info   Info
	log    *slog.Logger
	Now    func() time.Time
	Pause  time.Duration // between two messages of a broadcast
}

// NewService returns a messages service.
func NewService(db *store.DB, rec *audit.Recorder, q *jobs.Queue, m Mailer, info Info, log *slog.Logger) *Service {
	return &Service{db: db, audit: rec, jobs: q, mailer: m, info: info, log: log, Now: time.Now, Pause: 100 * time.Millisecond}
}

// RegisterJobs registers the sending jobs.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobWelcome, 2, s.welcomeJob)
	w.Register(JobBroadcast, 1, s.broadcastJob)
}

// Template is a message the sender wrote or the default.
type Template struct {
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Custom    bool     `json:"custom"` // false: the built-in text
	Variables []string `json:"variables"`
}

const (
	defaultSubject = "Your hosting account {{domain}} is ready"
	defaultBody    = "Hello,\n\nYour account {{username}} for {{domain}} is ready.\n\nSign in: {{panel_url}}\nUser name: {{username}}\n\n" +
		"The password was chosen when the account was made. If you do not have it, ask {{owner}}.\n"
)

func scopeOf(p *auth.Principal) (string, error) {
	switch {
	case p != nil && p.Login.Role == store.RoleAdmin:
		return "", nil
	case p != nil && p.Login.Role == store.RoleReseller:
		return p.Login.ID, nil
	}
	return "", apperr.ErrForbidden
}

func checkVars(field, text string) error {
	for _, m := range varRe.FindAllStringSubmatch(text, -1) {
		if !contains(Variables, strings.ToLower(m[1])) {
			return &validate.Error{Field: field, Code: validate.CodeFormat, Message: "{{" + m[1] + "}} is not a variable: " + strings.Join(Variables, ", ")}
		}
	}
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(text, "{{", ""), "}}", ""), "\x00") {
		return &validate.Error{Field: field, Code: validate.CodeFormat, Message: "no control characters"}
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func checkText(subject, body string) (string, string, error) {
	subject = strings.TrimSpace(subject)
	switch {
	case subject == "":
		return "", "", &validate.Error{Field: "subject", Code: validate.CodeRequired, Message: "a subject is needed"}
	case len(subject) > MaxSubject || strings.ContainsAny(subject, "\r\n\x00"):
		return "", "", &validate.Error{Field: "subject", Code: validate.CodeFormat, Message: "one line of at most 200 characters"}
	case strings.TrimSpace(body) == "":
		return "", "", &validate.Error{Field: "body", Code: validate.CodeRequired, Message: "a message is needed"}
	case len(body) > MaxBody || strings.ContainsRune(body, 0):
		return "", "", &validate.Error{Field: "body", Code: validate.CodeTooLong, Message: "at most 8000 characters"}
	}
	if err := checkVars("subject", subject); err != nil {
		return "", "", err
	}
	if err := checkVars("body", body); err != nil {
		return "", "", err
	}
	return subject, body, nil
}

// Welcome returns the welcome message the sender's new customers get: its
// own, else the admin's, else the built-in one.
func (s *Service) Welcome(ctx context.Context, p *auth.Principal) (Template, error) {
	own, err := scopeOf(p)
	if err != nil {
		return Template{}, err
	}
	return s.template(ctx, own), nil
}

func (s *Service) template(ctx context.Context, owner string) Template {
	t := Template{Subject: defaultSubject, Body: defaultBody, Variables: Variables}
	for _, o := range []string{owner, ""} {
		sub, body, found, err := s.db.MessageTemplate(ctx, o)
		if err == nil && found {
			t.Subject, t.Body, t.Custom = sub, body, o == owner
			return t
		}
	}
	return t
}

// SetWelcome saves the sender's welcome message; an empty subject and body
// go back to the default (the admin's for a reseller).
func (s *Service) SetWelcome(ctx context.Context, c auth.Client, p *auth.Principal, subject, body string) (Template, error) {
	own, err := scopeOf(p)
	if err != nil {
		return Template{}, err
	}
	if strings.TrimSpace(subject) == "" && strings.TrimSpace(body) == "" {
		if err := s.db.DeleteMessageTemplate(ctx, own); err != nil {
			return Template{}, err
		}
	} else {
		if subject, body, err = checkText(subject, body); err != nil {
			return Template{}, err
		}
		if err := s.db.SetMessageTemplate(ctx, own, subject, body, s.Now().UTC()); err != nil {
			return Template{}, err
		}
	}
	if err := s.audit.Record(ctx, event(c, p, "messages.welcome.set", "", map[string]any{"reset": subject == ""})); err != nil {
		return Template{}, err
	}
	return s.template(ctx, own), nil
}

// vars are the values of a customer's message.
func (s *Service) vars(ctx context.Context, a *store.Account) map[string]string {
	owner := "your hosting provider"
	if a.OwnerID != "" {
		if l, err := s.db.LoginByID(ctx, a.OwnerID); err == nil {
			owner = l.Username
		}
	}
	return map[string]string{"username": a.Username, "domain": a.PrimaryDomain, "panel_url": s.info.PanelURL(ctx), "owner": owner}
}

// Render fills the variables in. Values never contain template syntax.
func Render(text string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(text, func(m string) string {
		name := strings.ToLower(varRe.FindStringSubmatch(m)[1])
		return vars[name]
	})
}

// OnActivated queues the welcome message of a new account (called when the
// account becomes active the first time). Accounts without an email address
// get none.
func (s *Service) OnActivated(ctx context.Context, a *store.Account) {
	if a.Email == "" {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, JobWelcome, map[string]string{"account_id": a.ID}, jobs.EnqueueOptions{AccountID: a.ID, MaxAttempts: 3}); err != nil {
		s.log.Warn("queue the welcome message", "account", a.Username, "err", err)
	}
}

func (s *Service) welcomeJob(ctx context.Context, j *jobs.Job, _ jobs.Reporter) (any, error) {
	var p struct {
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Email == "" {
		return map[string]string{"skipped": "no email address"}, nil
	}
	t := s.template(ctx, a.OwnerID)
	v := s.vars(ctx, a)
	if err := s.mailer.Send(ctx, s.info.From(ctx), a.Email, Render(t.Subject, v), Render(t.Body, v)); err != nil {
		return nil, err
	}
	return map[string]string{"sent_to": a.Email}, nil
}

// BroadcastInput is a message to all customers.
type BroadcastInput struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// Broadcast queues a message to all the sender's customers that have an
// email address (admins: every account). One at a time per sender.
func (s *Service) Broadcast(ctx context.Context, c auth.Client, p *auth.Principal, in BroadcastInput) (string, error) {
	own, err := scopeOf(p)
	if err != nil {
		return "", err
	}
	subject, body, err := checkText(in.Subject, in.Body)
	if err != nil {
		return "", err
	}
	key := "messages.last_broadcast." + p.Login.ID
	var last time.Time
	if err := s.db.GetSetting(ctx, key, &last); err == nil && s.Now().Sub(last) < BroadcastGap {
		return "", apperr.NewConflict("too_soon", "a message to all customers was sent a moment ago: wait ten minutes")
	}
	filter := own
	if p.Login.Role == store.RoleAdmin {
		filter = "*"
	}
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: filter})
	if err != nil {
		return "", err
	}
	n := 0
	for _, a := range accts {
		if a.Email != "" {
			n++
		}
	}
	if n == 0 {
		return "", apperr.NewConflict("no_recipients", "none of your customers has an email address")
	}
	if n > MaxRecipients {
		return "", apperr.NewConflict("too_many", fmt.Sprintf("more than %d customers: send in parts", MaxRecipients))
	}
	if err := s.db.SetSetting(ctx, key, s.Now().UTC()); err != nil {
		return "", err
	}
	id, err := s.jobs.Enqueue(ctx, JobBroadcast, map[string]string{"sender_id": p.Login.ID, "filter": filter, "subject": subject, "body": body},
		jobs.EnqueueOptions{MaxAttempts: 1, CreatedBy: p.Login.ID})
	if err != nil {
		return "", err
	}
	return id, s.audit.Record(ctx, event(c, p, "messages.broadcast", id, map[string]any{"subject": subject, "recipients": n}))
}

func (s *Service) broadcastJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p struct {
		SenderID, Filter, Subject, Body string
	}
	var raw map[string]string
	if err := json.Unmarshal(j.Payload, &raw); err != nil {
		return nil, jobs.Permanent(err)
	}
	p.SenderID, p.Filter, p.Subject, p.Body = raw["sender_id"], raw["filter"], raw["subject"], raw["body"]
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: p.Filter})
	if err != nil {
		return nil, err
	}
	from := s.info.From(ctx)
	sent, failed := 0, 0
	seen := map[string]bool{}
	for _, a := range accts {
		to := strings.ToLower(a.Email)
		if to == "" || seen[to] {
			continue
		}
		seen[to] = true
		v := s.vars(ctx, &a)
		if err := s.mailer.Send(ctx, from, a.Email, Render(p.Subject, v), Render(p.Body, v)); err != nil {
			failed++
			r.Logf("%s: %v", a.Email, err)
		} else {
			sent++
		}
		select {
		case <-ctx.Done():
			return map[string]int{"sent": sent, "failed": failed}, ctx.Err()
		case <-time.After(s.Pause):
		}
	}
	return map[string]int{"sent": sent, "failed": failed}, nil
}

func event(c auth.Client, p *auth.Principal, action, target string, details map[string]any) audit.Event {
	return audit.Event{
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "messages", TargetID: target, Details: details,
	}
}
