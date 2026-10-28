package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Domain kinds.
const (
	DomainPrimary = "primary" // the account's main domain, created with it
	DomainAddon   = "addon"   // another website with its own document root
	DomainSub     = "sub"     // a name below one of the account's domains
	DomainAlias   = "alias"   // another name for the site of one of the account's domains
)

// Canonical host choices of a domain.
const (
	CanonicalBoth = ""     // serve example.com and www.example.com alike
	CanonicalWWW  = "www"  // redirect example.com to www.example.com
	CanonicalBare = "bare" // redirect www.example.com to example.com
)

// Domain is one domain of an account.
type Domain struct {
	ID        string
	AccountID string
	Name      string // "*.example.com" for a wildcard subdomain
	Kind      string
	ParentID  string // sub: the domain it is under; alias: the domain whose site it shows
	DocRoot   string // relative to the home folder; "" for an alias
	Canonical string
	CreatedAt time.Time
	UpdatedAt time.Time
}

const domainColumns = `id, account_id, name, kind, COALESCE(parent_id, ''), docroot, canonical, created_at, updated_at`

func scanDomain(s scanner) (*Domain, error) {
	var (
		d                Domain
		created, updated string
	)
	err := s.Scan(&d.ID, &d.AccountID, &d.Name, &d.Kind, &d.ParentID, &d.DocRoot, &d.Canonical, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	d.CreatedAt, errs[0] = ParseTime(created)
	d.UpdatedAt, errs[1] = ParseTime(updated)
	return &d, errors.Join(errs[:]...)
}

func queryDomains(ctx context.Context, q querier, query string, args ...any) ([]Domain, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// ListDomains returns an account's domains, the primary first, then by name.
func (db *DB) ListDomains(ctx context.Context, accountID string) ([]Domain, error) {
	return queryDomains(ctx, db.R, `SELECT `+domainColumns+` FROM domains WHERE account_id = ?
		ORDER BY kind != 'primary', name`, accountID)
}

// DomainByID returns one domain.
func (db *DB) DomainByID(ctx context.Context, id string) (*Domain, error) {
	return scanDomain(db.R.QueryRowContext(ctx, `SELECT `+domainColumns+` FROM domains WHERE id = ?`, id))
}

// DomainsUnder returns every domain, of any account, that is registrable
// itself or a name below it.
func DomainsUnder(ctx context.Context, q querier, registrable string) ([]Domain, error) {
	like := "%." + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(registrable)
	return queryDomains(ctx, q, `SELECT `+domainColumns+` FROM domains WHERE name = ? OR name LIKE ? ESCAPE '\'`,
		registrable, like)
}

// CountDomains counts an account's domains of one kind.
func CountDomains(ctx context.Context, q querier, accountID, kind string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE account_id = ? AND kind = ?`, accountID, kind).Scan(&n)
	return n, err
}

// DomainDependents counts the subdomains and aliases that point to a domain.
func DomainDependents(ctx context.Context, q querier, id string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE parent_id = ?`, id).Scan(&n)
	return n, err
}

// InsertDomain adds a domain. ErrConflict means the name is used already.
func InsertDomain(ctx context.Context, q querier, d *Domain) error {
	now := time.Now().UTC()
	d.CreatedAt, d.UpdatedAt = now, now
	_, err := q.ExecContext(ctx, `INSERT INTO domains (id, account_id, name, kind, parent_id, docroot, canonical,
		created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.AccountID, d.Name, d.Kind, nullIfEmpty(d.ParentID), d.DocRoot, d.Canonical, FormatTime(now), FormatTime(now))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateDomain saves the document root and canonical host.
func UpdateDomain(ctx context.Context, q querier, d *Domain) error {
	d.UpdatedAt = time.Now().UTC()
	return execOne(ctx, q, `UPDATE domains SET docroot = ?, canonical = ?, updated_at = ? WHERE id = ?`,
		d.DocRoot, d.Canonical, FormatTime(d.UpdatedAt), d.ID)
}

// DeleteDomain removes a domain and its redirects.
func DeleteDomain(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM domains WHERE id = ?`, id)
}

// Redirect sends requests for a path of a domain to another URL.
type Redirect struct {
	ID        string
	DomainID  string
	Path      string // "/" = the whole site
	Target    string
	Code      int
	KeepPath  bool // append the rest of the requested path to Target
	CreatedAt time.Time
}

const redirectColumns = `r.id, r.domain_id, r.path, r.target, r.code, r.keep_path, r.created_at`

func scanRedirect(s scanner) (*Redirect, error) {
	var (
		r       Redirect
		created string
	)
	err := s.Scan(&r.ID, &r.DomainID, &r.Path, &r.Target, &r.Code, &r.KeepPath, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt, err = ParseTime(created)
	return &r, err
}

// ListRedirects returns the redirects of all of an account's domains, by
// domain name, then path.
func (db *DB) ListRedirects(ctx context.Context, accountID string) ([]Redirect, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+redirectColumns+` FROM redirects r
		JOIN domains d ON d.id = r.domain_id WHERE d.account_id = ? ORDER BY d.name, r.path`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Redirect
	for rows.Next() {
		r, err := scanRedirect(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RedirectByID returns one redirect.
func (db *DB) RedirectByID(ctx context.Context, id string) (*Redirect, error) {
	return scanRedirect(db.R.QueryRowContext(ctx, `SELECT `+redirectColumns+` FROM redirects r WHERE r.id = ?`, id))
}

// CountRedirects counts the redirects of one domain.
func CountRedirects(ctx context.Context, q querier, domainID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM redirects WHERE domain_id = ?`, domainID).Scan(&n)
	return n, err
}

// InsertRedirect adds a redirect. ErrConflict means the domain has one for this path already.
func InsertRedirect(ctx context.Context, q querier, r *Redirect) error {
	r.CreatedAt = time.Now().UTC()
	_, err := q.ExecContext(ctx, `INSERT INTO redirects (id, domain_id, path, target, code, keep_path, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, r.DomainID, r.Path, r.Target, r.Code, r.KeepPath, FormatTime(r.CreatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeleteRedirect removes a redirect.
func DeleteRedirect(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM redirects WHERE id = ?`, id)
}
