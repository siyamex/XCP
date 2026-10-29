package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Mail routing of a zone (USR-DNS-03).
const (
	MailAuto   = "auto"   // decided from the zone's MX records
	MailLocal  = "local"  // this server receives the domain's mail
	MailRemote = "remote" // another provider does (Google Workspace, Microsoft 365, ...)
	MailBackup = "backup" // this server is a backup MX
)

// Zone is a DNS zone served by this server.
type Zone struct {
	ID          string
	AccountID   string
	DomainID    string // the domain it was made for; "" if that domain is gone
	Name        string
	MailRouting string
	Serving     bool // the DNS server has the zone as of its last apply
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const zoneColumns = `id, account_id, COALESCE(domain_id, ''), name, mail_routing, serving, created_at, updated_at`

func scanZone(s scanner) (*Zone, error) {
	var (
		z                Zone
		created, updated string
	)
	err := s.Scan(&z.ID, &z.AccountID, &z.DomainID, &z.Name, &z.MailRouting, &z.Serving, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	z.CreatedAt, errs[0] = ParseTime(created)
	z.UpdatedAt, errs[1] = ParseTime(updated)
	return &z, errors.Join(errs[:]...)
}

func queryZones(ctx context.Context, q querier, query string, args ...any) ([]Zone, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Zone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *z)
	}
	return out, rows.Err()
}

// AccountZones returns an account's zones by name.
func AccountZones(ctx context.Context, q querier, accountID string) ([]Zone, error) {
	return queryZones(ctx, q, `SELECT `+zoneColumns+` FROM dns_zones WHERE account_id = ? ORDER BY name`, accountID)
}

// ZoneFilter narrows ListZones.
type ZoneFilter struct {
	OwnerID string // accounts of this owner; "" = admin-owned accounts
	Search  string // part of the zone name
}

// ListZones returns the zones of the accounts of one owner, by name.
func (db *DB) ListZones(ctx context.Context, f ZoneFilter) ([]Zone, error) {
	q := `SELECT z.id, z.account_id, COALESCE(z.domain_id, ''), z.name, z.mail_routing, z.serving, z.created_at, z.updated_at
		FROM dns_zones z JOIN accounts a ON a.id = z.account_id WHERE COALESCE(a.owner_id, '') = ?`
	args := []any{f.OwnerID}
	if s := strings.TrimSpace(f.Search); s != "" {
		q += ` AND z.name LIKE ? ESCAPE '\'`
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(s))+"%")
	}
	return queryZones(ctx, db.R, q+` ORDER BY z.name`, args...)
}

// AllZones returns every zone (to re-apply them all).
func (db *DB) AllZones(ctx context.Context) ([]Zone, error) {
	return queryZones(ctx, db.R, `SELECT `+zoneColumns+` FROM dns_zones ORDER BY name`)
}

// ZonesNotServing returns the zones the DNS server does not have yet.
func (db *DB) ZonesNotServing(ctx context.Context) ([]Zone, error) {
	return queryZones(ctx, db.R, `SELECT `+zoneColumns+` FROM dns_zones WHERE serving = 0 ORDER BY name`)
}

// SetZoneServing records whether the DNS server has the zone.
func (db *DB) SetZoneServing(ctx context.Context, id string, serving bool) error {
	_, err := db.W.ExecContext(ctx, `UPDATE dns_zones SET serving = ? WHERE id = ?`, serving, id)
	return err
}

// ZoneByID returns one zone.
func ZoneByID(ctx context.Context, q querier, id string) (*Zone, error) {
	return scanZone(q.QueryRowContext(ctx, `SELECT `+zoneColumns+` FROM dns_zones WHERE id = ?`, id))
}

// DomainZones returns the zones made for a domain (zero or one).
func DomainZones(ctx context.Context, q querier, domainID string) ([]Zone, error) {
	return queryZones(ctx, q, `SELECT `+zoneColumns+` FROM dns_zones WHERE domain_id = ?`, domainID)
}

// InsertZone adds a zone. ErrConflict means a zone with that name exists.
func InsertZone(ctx context.Context, q querier, z *Zone) error {
	now := time.Now().UTC()
	z.CreatedAt, z.UpdatedAt = now, now
	if z.MailRouting == "" {
		z.MailRouting = MailAuto
	}
	_, err := q.ExecContext(ctx, `INSERT INTO dns_zones (id, account_id, domain_id, name, mail_routing, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, z.ID, z.AccountID, nullIfEmpty(z.DomainID), z.Name, z.MailRouting, FormatTime(now), FormatTime(now))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// SetZoneMailRouting changes a zone's mail routing.
func SetZoneMailRouting(ctx context.Context, q querier, id, routing string) error {
	return execOne(ctx, q, `UPDATE dns_zones SET mail_routing = ?, updated_at = ? WHERE id = ?`, routing, FormatTime(time.Now()), id)
}

// TouchZone marks a zone as changed.
func TouchZone(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `UPDATE dns_zones SET updated_at = ? WHERE id = ?`, FormatTime(time.Now()), id)
}

// ZoneRecord is a record of a zone.
type ZoneRecord struct {
	ID        string
	ZoneID    string
	DomainID  string // made for this domain; "" = added by a user
	Name      string // fully qualified, without the final dot
	Type      string
	TTL       uint32
	Content   string
	CreatedAt time.Time
}

const recordColumns = `id, zone_id, COALESCE(domain_id, ''), name, type, ttl, content, created_at`

func scanRecord(s scanner) (*ZoneRecord, error) {
	var (
		r       ZoneRecord
		created string
	)
	err := s.Scan(&r.ID, &r.ZoneID, &r.DomainID, &r.Name, &r.Type, &r.TTL, &r.Content, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt, err = ParseTime(created)
	return &r, err
}

// ZoneRecords returns a zone's records, by name and type.
func ZoneRecords(ctx context.Context, q querier, zoneID string) ([]ZoneRecord, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+recordColumns+` FROM dns_records WHERE zone_id = ?
		ORDER BY name != (SELECT name FROM dns_zones WHERE id = ?), name, type, content`, zoneID, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ZoneRecord
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RecordByID returns one record.
func RecordByID(ctx context.Context, q querier, id string) (*ZoneRecord, error) {
	return scanRecord(q.QueryRowContext(ctx, `SELECT `+recordColumns+` FROM dns_records WHERE id = ?`, id))
}

// DomainRecordZones returns the IDs of the zones holding records made for a domain.
func DomainRecordZones(ctx context.Context, q querier, domainID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT zone_id FROM dns_records WHERE domain_id = ?`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ForeignDomainRecords counts records in a zone made for other domains than domainID.
func ForeignDomainRecords(ctx context.Context, q querier, zoneID, domainID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_records WHERE zone_id = ? AND domain_id IS NOT NULL AND domain_id != ?`,
		zoneID, domainID).Scan(&n)
	return n, err
}

// InsertRecord adds a record. ErrConflict means the zone has the same record already.
func InsertRecord(ctx context.Context, q querier, r *ZoneRecord) error {
	r.CreatedAt = time.Now().UTC()
	_, err := q.ExecContext(ctx, `INSERT INTO dns_records (id, zone_id, domain_id, name, type, ttl, content, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, r.ZoneID, nullIfEmpty(r.DomainID), r.Name, r.Type, r.TTL, r.Content, FormatTime(r.CreatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateRecord replaces a record's name, type, TTL and content.
func UpdateRecord(ctx context.Context, q querier, r *ZoneRecord) error {
	_, err := q.ExecContext(ctx, `UPDATE dns_records SET name = ?, type = ?, ttl = ?, content = ? WHERE id = ?`,
		r.Name, r.Type, r.TTL, r.Content, r.ID)
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// MoveAddressRecords points every record of type typ (A or AAAA) with
// content from to the address to, in all zones. It returns how many moved.
func MoveAddressRecords(ctx context.Context, q querier, typ, from, to string) (int64, error) {
	res, err := q.ExecContext(ctx, `UPDATE OR IGNORE dns_records SET content = ? WHERE type = ? AND content = ?`, to, typ, from)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteRecord removes a record.
func DeleteRecord(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM dns_records WHERE id = ?`, id)
}
