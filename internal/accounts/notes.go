package accounts

import (
	"context"
	"database/sql"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Bounds of an account's internal note.
const (
	MaxNote    = 5000
	MaxTags    = 10
	MaxTagSize = 30
)

var tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Note is the admins' internal note and tags on an account (ADM-ACC-18).
// Resellers and customers never see it.
type Note struct {
	Note      string     `json:"note"`
	Tags      []string   `json:"tags"`
	UpdatedBy string     `json:"updated_by,omitempty"` // username
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func adminOnly(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

func (s *Service) noteView(ctx context.Context, n store.AccountNote) Note {
	v := Note{Note: n.Note, Tags: n.Tags}
	if !n.UpdatedAt.IsZero() {
		v.UpdatedAt = &n.UpdatedAt
		if l, err := s.db.LoginByID(ctx, n.UpdatedBy); err == nil {
			v.UpdatedBy = l.Username
		}
	}
	return v
}

// Note returns an account's internal note (admins).
func (s *Service) Note(ctx context.Context, p *auth.Principal, id string) (Note, error) {
	if err := adminOnly(p); err != nil {
		return Note{}, err
	}
	a, err := s.account(ctx, p, id)
	if err != nil {
		return Note{}, err
	}
	n, err := s.db.AccountNoteByID(ctx, a.ID)
	if err != nil {
		return Note{}, err
	}
	return s.noteView(ctx, n), nil
}

// SetNote saves an account's internal note and tags (admins). Tags are
// lower-case words of letters, digits and hyphens.
func (s *Service) SetNote(ctx context.Context, c auth.Client, p *auth.Principal, id, note string, tags []string) (Note, error) {
	if err := adminOnly(p); err != nil {
		return Note{}, err
	}
	a, err := s.account(ctx, p, id)
	if err != nil {
		return Note{}, err
	}
	note = strings.TrimSpace(note)
	if len(note) > MaxNote {
		return Note{}, &validate.Error{Field: "note", Code: validate.CodeTooLong, Message: "a note can have 5000 characters"}
	}
	clean := []string{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || slices.Contains(clean, t) {
			continue
		}
		if len(t) > MaxTagSize || !tagRE.MatchString(t) {
			return Note{}, &validate.Error{Field: "tags", Code: validate.CodeFormat, Message: "a tag is up to 30 letters, digits and hyphens"}
		}
		clean = append(clean, t)
	}
	if len(clean) > MaxTags {
		return Note{}, &validate.Error{Field: "tags", Code: validate.CodeTooLong, Message: "an account can have 10 tags"}
	}
	slices.Sort(clean)
	n := store.AccountNote{AccountID: a.ID, Note: note, Tags: clean, UpdatedBy: p.Login.ID, UpdatedAt: time.Now().UTC()}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetAccountNote(ctx, tx, n); err != nil {
			return err
		}
		// The note's text stays out of the audit log: it may be about a person.
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.note", a.ID, map[string]any{"tags": clean, "length": len(note)}))
	})
	if err != nil {
		return Note{}, err
	}
	return s.noteView(ctx, n), nil
}
