package databases

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// States in the database map.
const (
	MapOK      = "ok"      // in MariaDB and in the panel
	MapOrphan  = "orphan"  // in MariaDB, of no account
	MapMissing = "missing" // in the panel, not in MariaDB
)

// MapDatabase is one database of the server map.
type MapDatabase struct {
	Name      string `json:"name"`
	SizeBytes *int64 `json:"size_bytes"` // nil: not in MariaDB
	AccountID string `json:"account_id,omitempty"`
	Account   string `json:"account,omitempty"`
	State     string `json:"state"`
}

// MapUser is one database user of the server map.
type MapUser struct {
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	AccountID string   `json:"account_id,omitempty"`
	Account   string   `json:"account,omitempty"`
	State     string   `json:"state"`
}

// ServerMap is every database and database user, by owner (ADM-DB-02).
type ServerMap struct {
	Databases []MapDatabase `json:"databases"`
	Users     []MapUser     `json:"users"`
}

func (s *Service) inventory(ctx context.Context) (*agentv1.MySQLInventoryResponse, error) {
	inv, err := s.agent.MySQLInventory(ctx, &agentv1.MySQLInventoryRequest{})
	if status.Code(err) == codes.NotFound {
		return nil, apperr.NewConflict("not_installed", status.Convert(err).Message())
	}
	return inv, err
}

// Map lists every database and database user of MariaDB and of the panel
// with the account each belongs to: orphans (in MariaDB, of no account)
// and missing ones (in the panel, not in MariaDB) are marked. Admins only;
// resellers' accounts are included, as it is the server's map.
func (s *Service) Map(ctx context.Context, p *auth.Principal) (ServerMap, error) {
	if err := admin(p); err != nil {
		return ServerMap{}, err
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		return ServerMap{}, err
	}
	dbOwners, err := store.AllDatabaseOwners(ctx, s.db.R)
	if err != nil {
		return ServerMap{}, err
	}
	userOwners, err := store.AllDBUserOwners(ctx, s.db.R)
	if err != nil {
		return ServerMap{}, err
	}
	m := ServerMap{Databases: []MapDatabase{}, Users: []MapUser{}}
	known := map[string]bool{}
	for _, o := range dbOwners {
		known[o.Name] = true
		d := MapDatabase{Name: o.Name, AccountID: o.AccountID, Account: o.Username, State: MapMissing}
		if size, ok := inv.GetDatabases()[o.Name]; ok {
			d.SizeBytes, d.State = &size, MapOK
		}
		m.Databases = append(m.Databases, d)
	}
	for name, size := range inv.GetDatabases() {
		if !known[name] {
			m.Databases = append(m.Databases, MapDatabase{Name: name, SizeBytes: &size, State: MapOrphan})
		}
	}
	hosts := map[string][]string{}
	for _, u := range inv.GetUsers() {
		hosts[u.GetName()] = u.GetHosts()
	}
	knownUser := map[string]bool{}
	for _, o := range userOwners {
		knownUser[o.Name] = true
		u := MapUser{Name: o.Name, Hosts: []string{}, AccountID: o.AccountID, Account: o.Username, State: MapMissing}
		if h, ok := hosts[o.Name]; ok {
			u.Hosts, u.State = h, MapOK
		}
		m.Users = append(m.Users, u)
	}
	for _, u := range inv.GetUsers() {
		if !knownUser[u.GetName()] {
			m.Users = append(m.Users, MapUser{Name: u.GetName(), Hosts: u.GetHosts(), State: MapOrphan})
		}
	}
	order := func(state string) int { return slices.Index([]string{MapOrphan, MapMissing, MapOK}, state) }
	slices.SortFunc(m.Databases, func(a, b MapDatabase) int {
		if d := order(a.State) - order(b.State); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
	slices.SortFunc(m.Users, func(a, b MapUser) int {
		if d := order(a.State) - order(b.State); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
	return m, nil
}

// DropOrphan drops a database (kind "database") or a database user on all
// its hosts (kind "user") that MariaDB has and no account owns. It checks
// again, just before, that MariaDB has it and the panel does not.
func (s *Service) DropOrphan(ctx context.Context, c auth.Client, p *auth.Principal, kind, name string) error {
	if err := admin(p); err != nil {
		return err
	}
	if kind != "database" && kind != "user" {
		return badField("kind", validate.CodeFormat, "kind is database or user")
	}
	m, err := s.Map(ctx, p)
	if err != nil {
		return err
	}
	state := ""
	if kind == "database" {
		if i := slices.IndexFunc(m.Databases, func(d MapDatabase) bool { return d.Name == name }); i >= 0 {
			state = m.Databases[i].State
		}
	} else if i := slices.IndexFunc(m.Users, func(u MapUser) bool { return u.Name == name }); i >= 0 {
		state = m.Users[i].State
	}
	switch state {
	case "":
		return store.ErrNotFound
	case MapOK, MapMissing:
		return apperr.NewConflict("not_orphan", name+" belongs to an account; remove it there")
	}
	req := &agentv1.MySQLOrphanDropRequest{Database: name}
	if kind == "user" {
		req = &agentv1.MySQLOrphanDropRequest{User: name}
	}
	if _, err := s.agent.MySQLOrphanDrop(ctx, req); err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return apperr.NewConflict("refused", status.Convert(err).Message())
		}
		return err
	}
	return s.audit.Record(ctx, event(c, p, "database.orphan.drop", "", kind, name, map[string]any{"kind": kind, "name": name}))
}

// RepairMissing queues the apply job of every account with a database or
// user the panel has and MariaDB does not, which makes them again (empty,
// for a database). It returns how many accounts were queued.
func (s *Service) RepairMissing(ctx context.Context, c auth.Client, p *auth.Principal) (int, error) {
	m, err := s.Map(ctx, p)
	if err != nil {
		return 0, err
	}
	var accounts []string
	for _, d := range m.Databases {
		if d.State == MapMissing && !slices.Contains(accounts, d.AccountID) {
			accounts = append(accounts, d.AccountID)
		}
	}
	for _, u := range m.Users {
		if u.State == MapMissing && !slices.Contains(accounts, u.AccountID) {
			accounts = append(accounts, u.AccountID)
		}
	}
	if len(accounts) == 0 {
		return 0, nil
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, id := range accounts {
			if _, err := s.enqueueApply(ctx, tx, p.Login.ID, id); err != nil {
				return err
			}
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.repair_missing", "", "server", "mysql", map[string]any{"accounts": len(accounts)}))
	})
	return len(accounts), err
}
