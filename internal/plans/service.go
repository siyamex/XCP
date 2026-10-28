package plans

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureList is the API view of a feature list.
type FeatureList struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Features  []string  `json:"features"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Package is the API view of a package.
type Package struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	FeatureListID string    `json:"feature_list_id"`
	Limits        Limits    `json:"limits"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// FeatureListInput creates or replaces a feature list.
type FeatureListInput struct {
	Name     string   `json:"name"`
	Features []string `json:"features"`
}

// PackageInput creates or replaces a package.
type PackageInput struct {
	Name          string `json:"name"`
	FeatureListID string `json:"feature_list_id"`
	Limits        Limits `json:"limits"`
}

// Service manages packages and feature lists.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
}

// NewService returns a plans service.
func NewService(db *store.DB, rec *audit.Recorder) *Service { return &Service{db: db, audit: rec} }

// owner returns the package owner scope for p. Only admins manage packages
// until resellers arrive (P2), and admin packages are global ("").
func owner(p *auth.Principal) (string, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return "", apperr.ErrForbidden
	}
	return "", nil
}

var nameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$`)

func checkName(s string) (string, error) {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "", &validate.Error{Field: "name", Code: validate.CodeRequired, Message: "name is required"}
	}
	if !nameRe.MatchString(s) {
		return "", &validate.Error{Field: "name", Code: validate.CodeFormat, Message: "use up to 64 letters, digits, spaces, dots, dashes or underscores"}
	}
	return s, nil
}

func checkFeatures(keys []string) ([]string, error) {
	for _, k := range keys {
		if !IsFeature(k) {
			return nil, &validate.Error{Field: "features", Code: validate.CodeFormat, Message: fmt.Sprintf("unknown feature %q", k)}
		}
	}
	// Keep catalog order and drop duplicates, so equal lists compare equal.
	out := []string{}
	for _, f := range Catalog {
		if slices.Contains(keys, f.Key) {
			out = append(out, f.Key)
		}
	}
	return out, nil
}

func event(c auth.Client, p *auth.Principal, action, typ, id string, details map[string]any) audit.Event {
	e := audit.Event{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: typ, TargetID: id, Details: details}
	if p != nil {
		e.ActorID, e.ImpersonatorID, e.Role = p.Login.ID, p.Session.ImpersonatorID, p.Login.Role
	} else {
		e.Role = "system"
	}
	return e
}

func toFeatureList(f *store.FeatureList) FeatureList {
	return FeatureList{ID: f.ID, Name: f.Name, Features: f.Features, CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt}
}

func toPackage(p *store.Package) (Package, error) {
	out := Package{ID: p.ID, Name: p.Name, FeatureListID: p.FeatureListID, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	if err := json.Unmarshal(p.Limits, &out.Limits); err != nil {
		return out, fmt.Errorf("package %s: stored limits: %w", p.ID, err)
	}
	return out, out.Limits.Normalize()
}

// ListFeatureLists returns the caller's feature lists.
func (s *Service) ListFeatureLists(ctx context.Context, p *auth.Principal) ([]FeatureList, error) {
	own, err := owner(p)
	if err != nil {
		return nil, err
	}
	list, err := s.db.FeatureLists(ctx, own)
	out := make([]FeatureList, 0, len(list))
	for i := range list {
		out = append(out, toFeatureList(&list[i]))
	}
	return out, err
}

// featureList loads a list the caller may see; others look like "not found".
func (s *Service) featureList(ctx context.Context, p *auth.Principal, id string) (*store.FeatureList, error) {
	own, err := owner(p)
	if err != nil {
		return nil, err
	}
	f, err := s.db.FeatureListByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if f.OwnerID != own {
		return nil, store.ErrNotFound
	}
	return f, nil
}

// GetFeatureList returns one of the caller's feature lists.
func (s *Service) GetFeatureList(ctx context.Context, p *auth.Principal, id string) (FeatureList, error) {
	f, err := s.featureList(ctx, p, id)
	if err != nil {
		return FeatureList{}, err
	}
	return toFeatureList(f), nil
}

// SaveFeatureList creates a list (id == "") or replaces one.
func (s *Service) SaveFeatureList(ctx context.Context, c auth.Client, p *auth.Principal, id string, in FeatureListInput) (FeatureList, error) {
	own, err := owner(p)
	if err != nil {
		return FeatureList{}, err
	}
	name, err := checkName(in.Name)
	if err != nil {
		return FeatureList{}, err
	}
	feats, err := checkFeatures(in.Features)
	if err != nil {
		return FeatureList{}, err
	}
	f := &store.FeatureList{ID: id, OwnerID: own, Name: name, Features: feats}
	action := "feature_list.update"
	if id == "" {
		f.ID, action = ids.New(), "feature_list.create"
	} else if _, err := s.featureList(ctx, p, id); err != nil {
		return FeatureList{}, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SaveFeatureList(ctx, tx, f, id == ""); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, action, "feature_list", f.ID, map[string]any{"name": name, "features": feats}))
	})
	if errors.Is(err, store.ErrConflict) {
		return FeatureList{}, apperr.NewConflict("name_taken", "a feature list with this name already exists")
	}
	if err != nil {
		return FeatureList{}, err
	}
	saved, err := s.db.FeatureListByID(ctx, f.ID)
	if err != nil {
		return FeatureList{}, err
	}
	return toFeatureList(saved), nil
}

// DeleteFeatureList removes a list that no package uses.
func (s *Service) DeleteFeatureList(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	f, err := s.featureList(ctx, p, id)
	if err != nil {
		return err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteFeatureList(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "feature_list.delete", "feature_list", id, map[string]any{"name": f.Name}))
	})
	if errors.Is(err, store.ErrInUse) {
		return apperr.NewConflict("in_use", "packages still use this feature list; move them to another list first")
	}
	return err
}

// ListPackages returns the caller's packages.
func (s *Service) ListPackages(ctx context.Context, p *auth.Principal) ([]Package, error) {
	own, err := owner(p)
	if err != nil {
		return nil, err
	}
	list, err := s.db.Packages(ctx, own)
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(list))
	for i := range list {
		v, err := toPackage(&list[i])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) pkg(ctx context.Context, p *auth.Principal, id string) (*store.Package, error) {
	own, err := owner(p)
	if err != nil {
		return nil, err
	}
	pk, err := s.db.PackageByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if pk.OwnerID != own {
		return nil, store.ErrNotFound
	}
	return pk, nil
}

// GetPackage returns one of the caller's packages.
func (s *Service) GetPackage(ctx context.Context, p *auth.Principal, id string) (Package, error) {
	pk, err := s.pkg(ctx, p, id)
	if err != nil {
		return Package{}, err
	}
	return toPackage(pk)
}

// SavePackage creates a package (id == "") or replaces one.
func (s *Service) SavePackage(ctx context.Context, c auth.Client, p *auth.Principal, id string, in PackageInput) (Package, error) {
	own, err := owner(p)
	if err != nil {
		return Package{}, err
	}
	name, err := checkName(in.Name)
	if err != nil {
		return Package{}, err
	}
	if err := in.Limits.Normalize(); err != nil {
		return Package{}, err
	}
	if _, err := s.featureList(ctx, p, in.FeatureListID); errors.Is(err, store.ErrNotFound) {
		return Package{}, &validate.Error{Field: "feature_list_id", Code: validate.CodeFormat, Message: "no such feature list"}
	} else if err != nil {
		return Package{}, err
	}
	limits, err := json.Marshal(in.Limits)
	if err != nil {
		return Package{}, err
	}
	pk := &store.Package{ID: id, OwnerID: own, Name: name, FeatureListID: in.FeatureListID, Limits: limits}
	action := "package.update"
	if id == "" {
		pk.ID, action = ids.New(), "package.create"
	} else if _, err := s.pkg(ctx, p, id); err != nil {
		return Package{}, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SavePackage(ctx, tx, pk, id == ""); err != nil {
			return err
		}
		var lim map[string]any
		_ = json.NewDecoder(bytes.NewReader(limits)).Decode(&lim)
		return s.audit.RecordTx(ctx, tx, event(c, p, action, "package", pk.ID,
			map[string]any{"name": name, "feature_list_id": in.FeatureListID, "limits": lim}))
	})
	if errors.Is(err, store.ErrConflict) {
		return Package{}, apperr.NewConflict("name_taken", "a package with this name already exists")
	}
	if err != nil {
		return Package{}, err
	}
	saved, err := s.db.PackageByID(ctx, pk.ID)
	if err != nil {
		return Package{}, err
	}
	return toPackage(saved)
}

// DeletePackage removes a package.
func (s *Service) DeletePackage(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	pk, err := s.pkg(ctx, p, id)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeletePackage(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "package.delete", "package", id, map[string]any{"name": pk.Name}))
	})
}

// EnsureDefaults creates the "Default" feature list and package on a new
// installation (no admin-owned feature lists yet), so the panel is usable at once.
func (s *Service) EnsureDefaults(ctx context.Context) error {
	lists, err := s.db.FeatureLists(ctx, "")
	if err != nil || len(lists) > 0 {
		return err
	}
	// Shell access is opt-in: the default list leaves out SSH and the web terminal.
	feats := slices.DeleteFunc(AllFeatures(), func(k string) bool { return k == "ssh" || k == "terminal" })
	f := &store.FeatureList{ID: ids.New(), Name: "Default", Features: feats}
	lim := DefaultLimits()
	limits, _ := json.Marshal(lim)
	pk := &store.Package{ID: ids.New(), Name: "Default", FeatureListID: f.ID, Limits: limits}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SaveFeatureList(ctx, tx, f, true); err != nil {
			return err
		}
		if err := store.SavePackage(ctx, tx, pk, true); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(auth.Client{}, nil, "package.defaults", "package", pk.ID, map[string]any{"name": "Default"}))
	})
}
