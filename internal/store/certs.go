package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Certificate sources.
const (
	CertACME   = "acme"   // issued by AutoSSL
	CertUpload = "upload" // uploaded by a user
)

// Certificate is the certificate of a domain, or of the server itself
// (DomainID ""). KeyEnc is the private key encrypted with the master key.
type Certificate struct {
	ID        string
	DomainID  string
	Source    string
	Names     []string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	CertPEM   string
	KeyEnc    []byte
	CreatedAt time.Time
}

const certColumns = `id, COALESCE(domain_id, ''), source, names, issuer, not_before, not_after, cert_pem, key_enc, created_at`

func scanCert(s scanner) (*Certificate, error) {
	var (
		c                         Certificate
		names, nb, na, createdStr string
	)
	err := s.Scan(&c.ID, &c.DomainID, &c.Source, &names, &c.Issuer, &nb, &na, &c.CertPEM, &c.KeyEnc, &createdStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [4]error
	errs[0] = json.Unmarshal([]byte(names), &c.Names)
	c.NotBefore, errs[1] = ParseTime(nb)
	c.NotAfter, errs[2] = ParseTime(na)
	c.CreatedAt, errs[3] = ParseTime(createdStr)
	return &c, errors.Join(errs[:]...)
}

// DomainCertificate returns a domain's certificate.
func (db *DB) DomainCertificate(ctx context.Context, domainID string) (*Certificate, error) {
	return scanCert(db.R.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE domain_id = ?`, domainID))
}

// ServerCertificate returns the server's own certificate (its host name).
func (db *DB) ServerCertificate(ctx context.Context) (*Certificate, error) {
	return scanCert(db.R.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE domain_id IS NULL`))
}

// AccountCertificates returns the certificates of an account's domains, by domain ID.
func (db *DB) AccountCertificates(ctx context.Context, accountID string) (map[string]Certificate, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+certColumns+` FROM certificates
		WHERE domain_id IN (SELECT id FROM domains WHERE account_id = ?)`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Certificate{}
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out[c.DomainID] = *c
	}
	return out, rows.Err()
}

// PutCertificate stores a certificate, replacing the one the domain (or
// the server) had.
func PutCertificate(ctx context.Context, q querier, c *Certificate) error {
	names, err := json.Marshal(c.Names)
	if err != nil {
		return err
	}
	c.CreatedAt = time.Now().UTC()
	if c.DomainID == "" {
		_, err = q.ExecContext(ctx, `DELETE FROM certificates WHERE domain_id IS NULL`)
	} else {
		_, err = q.ExecContext(ctx, `DELETE FROM certificates WHERE domain_id = ?`, c.DomainID)
	}
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO certificates (id, domain_id, source, names, issuer, not_before, not_after,
		cert_pem, key_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, nullIfEmpty(c.DomainID), c.Source, string(names), c.Issuer, FormatTime(c.NotBefore), FormatTime(c.NotAfter),
		c.CertPEM, c.KeyEnc, FormatTime(c.CreatedAt))
	return err
}

// DeleteDomainCertificate removes a domain's certificate.
func DeleteDomainCertificate(ctx context.Context, q querier, domainID string) error {
	return execOne(ctx, q, `DELETE FROM certificates WHERE domain_id = ?`, domainID)
}

// CertSummary is a certificate with its domain and account, for the expiry dashboard.
type CertSummary struct {
	Certificate
	Domain    string // "" for the server's own certificate
	AccountID string
	Account   string
}

// ListCertificates returns certificates, the soonest to expire first: all
// of them (accountID "*") or those of one account.
func (db *DB) ListCertificates(ctx context.Context, accountID string) ([]CertSummary, error) {
	q := `SELECT c.id, COALESCE(c.domain_id, ''), c.source, c.names, c.issuer, c.not_before, c.not_after, c.cert_pem, c.key_enc,
		c.created_at, COALESCE(d.name, ''), COALESCE(a.id, ''), COALESCE(a.username, '')
		FROM certificates c LEFT JOIN domains d ON d.id = c.domain_id LEFT JOIN accounts a ON a.id = d.account_id`
	var args []any
	if accountID != "*" {
		q += ` WHERE a.id = ?`
		args = append(args, accountID)
	}
	rows, err := db.R.QueryContext(ctx, q+` ORDER BY c.not_after`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertSummary
	for rows.Next() {
		var (
			s                         CertSummary
			names, nb, na, createdStr string
		)
		if err := rows.Scan(&s.ID, &s.DomainID, &s.Source, &names, &s.Issuer, &nb, &na, &s.CertPEM, &s.KeyEnc, &createdStr,
			&s.Domain, &s.AccountID, &s.Account); err != nil {
			return nil, err
		}
		var errs [4]error
		errs[0] = json.Unmarshal([]byte(names), &s.Names)
		s.NotBefore, errs[1] = ParseTime(nb)
		s.NotAfter, errs[2] = ParseTime(na)
		s.CreatedAt, errs[3] = ParseTime(createdStr)
		if err := errors.Join(errs[:]...); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
