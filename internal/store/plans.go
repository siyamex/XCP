package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// FeatureList is a named set of enabled feature keys.
type FeatureList struct {
	ID        string
	OwnerID   string
	Name      string
	Features  []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Package is a hosting plan: limits plus a feature list.
type Package struct {
	ID            string
	OwnerID       string
	Name          string
	FeatureListID string
	Limits        json.RawMessage
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func uniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func scanFeatureList(s scanner) (*FeatureList, error) {
	var (
		f                          FeatureList
		features, created, updated string
	)
	err := s.Scan(&f.ID, &f.OwnerID, &f.Name, &features, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [3]error
	errs[0] = json.Unmarshal([]byte(features), &f.Features)
	f.CreatedAt, errs[1] = ParseTime(created)
	f.UpdatedAt, errs[2] = ParseTime(updated)
	return &f, errors.Join(errs[:]...)
}

const featureListColumns = `id, COALESCE(owner_id, ''), name, features, created_at, updated_at`

// FeatureLists returns the lists owned by ownerID ("" = admin-owned), by name.
func (db *DB) FeatureLists(ctx context.Context, ownerID string) ([]FeatureList, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+featureListColumns+` FROM feature_lists
		WHERE COALESCE(owner_id, '') = ? ORDER BY name`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeatureList
	for rows.Next() {
		f, err := scanFeatureList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// FeatureListByID returns one list.
func (db *DB) FeatureListByID(ctx context.Context, id string) (*FeatureList, error) {
	return scanFeatureList(db.R.QueryRowContext(ctx, `SELECT `+featureListColumns+` FROM feature_lists WHERE id = ?`, id))
}

// SaveFeatureList inserts f, or replaces name and features if insert is false.
func SaveFeatureList(ctx context.Context, q querier, f *FeatureList, insert bool) error {
	feats, err := json.Marshal(f.Features)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if insert {
		f.CreatedAt = now
		_, err = q.ExecContext(ctx, `INSERT INTO feature_lists (id, owner_id, name, features, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)`, f.ID, nullIfEmpty(f.OwnerID), f.Name, string(feats), FormatTime(now), FormatTime(now))
	} else {
		err = execOne(ctx, q, `UPDATE feature_lists SET name = ?, features = ?, updated_at = ? WHERE id = ?`,
			f.Name, string(feats), FormatTime(now), f.ID)
	}
	f.UpdatedAt = now
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeleteFeatureList removes a list. It fails with ErrInUse if a package uses it.
func DeleteFeatureList(ctx context.Context, q querier, id string) error {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages WHERE feature_list_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	return execOne(ctx, q, `DELETE FROM feature_lists WHERE id = ?`, id)
}

// ErrInUse is returned when deleting something that others still reference.
var ErrInUse = errors.New("store: still in use")

const packageColumns = `id, COALESCE(owner_id, ''), name, feature_list_id, limits, created_at, updated_at`

func scanPackage(s scanner) (*Package, error) {
	var (
		p                        Package
		limits, created, updated string
	)
	err := s.Scan(&p.ID, &p.OwnerID, &p.Name, &p.FeatureListID, &limits, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Limits = json.RawMessage(limits)
	var errs [2]error
	p.CreatedAt, errs[0] = ParseTime(created)
	p.UpdatedAt, errs[1] = ParseTime(updated)
	return &p, errors.Join(errs[:]...)
}

// Packages returns the packages owned by ownerID ("" = admin-owned), by name.
func (db *DB) Packages(ctx context.Context, ownerID string) ([]Package, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+packageColumns+` FROM packages
		WHERE COALESCE(owner_id, '') = ? ORDER BY name`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PackageByID returns one package.
func (db *DB) PackageByID(ctx context.Context, id string) (*Package, error) {
	return scanPackage(db.R.QueryRowContext(ctx, `SELECT `+packageColumns+` FROM packages WHERE id = ?`, id))
}

// SavePackage inserts p, or updates name, feature list and limits if insert is false.
func SavePackage(ctx context.Context, q querier, p *Package, insert bool) error {
	now := time.Now().UTC()
	var err error
	if insert {
		p.CreatedAt = now
		_, err = q.ExecContext(ctx, `INSERT INTO packages (id, owner_id, name, feature_list_id, limits, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, p.ID, nullIfEmpty(p.OwnerID), p.Name, p.FeatureListID, string(p.Limits),
			FormatTime(now), FormatTime(now))
	} else {
		err = execOne(ctx, q, `UPDATE packages SET name = ?, feature_list_id = ?, limits = ?, updated_at = ? WHERE id = ?`,
			p.Name, p.FeatureListID, string(p.Limits), FormatTime(now), p.ID)
	}
	p.UpdatedAt = now
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeletePackage removes a package. (Accounts using it are checked once accounts exist.)
func DeletePackage(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM packages WHERE id = ?`, id)
}
