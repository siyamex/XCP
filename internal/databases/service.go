// Package databases manages the MariaDB databases and users of accounts
// (USR-DB-01..04, ADM-DB-08, 09; ADR-0006). The panel database is the
// source of truth; jobs make MariaDB match it through the agent (jobs.go).
package databases

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Features of the feature list that switch database management on.
const (
	FeatureMySQL      = "mysql"
	FeaturePHPMyAdmin = "phpmyadmin"
)

// Access is one user's privileges on one database.
type Access struct {
	ID         string   `json:"id"`   // the other side: the user's ID in a Database, the database's in a User
	Name       string   `json:"name"` // its name
	Privileges []string `json:"privileges"`
}

// Database is the API view of a database.
type Database struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	SizeBytes *int64    `json:"size_bytes"` // nil: the database server did not say
	Users     []Access  `json:"users"`
	CreatedAt time.Time `json:"created_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// User is the API view of a database user.
type User struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	Databases []Access  `json:"databases"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// Overview is everything the databases page shows.
type Overview struct {
	Prefix     string     `json:"prefix"` // "<username>_": every name starts with it
	Databases  []Database `json:"databases"`
	Users      []User     `json:"users"`
	Privileges []string   `json:"privileges"` // what a grant may list, besides "ALL"
	MaxDBs     *int64     `json:"max_databases"`
	MaxUsers   *int64     `json:"max_users"`
	Server     string     `json:"server"` // "ok", or why sizes are missing
	Host       string     `json:"host"`   // what applications connect to
	PHPMyAdmin bool       `json:"phpmyadmin"`
}

// GrantInput sets a user's privileges on a database.
type GrantInput struct {
	Privileges []string `json:"privileges"` // ["ALL"] or names from Overview.Privileges
}

// WizardInput creates a database and a user with privileges on it in one step (USR-DB-03).
type WizardInput struct {
	Database   string   `json:"database"`
	User       string   `json:"user"`
	Password   string   `json:"password"`
	Privileges []string `json:"privileges"` // empty: ALL
}

// WizardResult is what an application needs to connect.
type WizardResult struct {
	Database Database `json:"database"`
	User     User     `json:"user"`
	Host     string   `json:"host"`
	JobID    string   `json:"job_id"`
}

// Status is the database server as the admin sees it.
type Status struct {
	Installed  bool   `json:"installed"`
	Version    string `json:"version,omitempty"`
	PHPMyAdmin string `json:"phpmyadmin,omitempty"` // installed version
	Detail     string `json:"detail,omitempty"`
}

// ConnectHost is where applications on this server reach MariaDB.
const ConnectHost = "localhost"

// Service manages databases and database users.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	plans *plans.Service
	jobs  *jobs.Queue
	agent agentrpc.Client
	box   *secretbox.Box
}

// NewService returns a databases service. box encrypts the stored password hashes.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client, box *secretbox.Box) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, box: box}
}

func badField(field, code, msg string) error {
	return &validate.Error{Field: field, Code: code, Message: msg}
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetType, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: targetType, TargetID: targetID, AccountID: accountID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// access loads an account the caller may manage: admins the admin-owned
// accounts, users their own account if its feature list has feature.
// Anything else looks like "not found".
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID, feature string) (*store.Account, plans.Limits, error) {
	if p == nil {
		return nil, plans.Limits{}, apperr.ErrForbidden
	}
	a, err := s.db.AccountByID(ctx, accountID)
	if err != nil {
		return nil, plans.Limits{}, err
	}
	lim, features, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return nil, plans.Limits{}, err
	}
	switch p.Login.Role {
	case store.RoleAdmin:
		if a.OwnerID != "" {
			return nil, plans.Limits{}, store.ErrNotFound
		}
	case store.RoleUser:
		if p.Login.AccountID != a.ID {
			return nil, plans.Limits{}, store.ErrNotFound
		}
		if !slices.Contains(features, feature) {
			return nil, plans.Limits{}, apperr.ErrForbidden
		}
	default:
		return nil, plans.Limits{}, apperr.ErrForbidden
	}
	return a, lim, nil
}

// changeable refuses changes while the account is being set up or removed.
func changeable(a *store.Account) error {
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		return apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	return nil
}

func (s *Service) forChange(ctx context.Context, p *auth.Principal, accountID string) (*store.Account, plans.Limits, error) {
	a, lim, err := s.access(ctx, p, accountID, FeatureMySQL)
	if err != nil {
		return nil, lim, err
	}
	return a, lim, changeable(a)
}

// fullName turns what the user typed ("shop", or "alice_shop") into the
// name on the server, and checks it.
func fullName(username, in, field string, maxLen int) (string, error) {
	n := strings.ToLower(strings.TrimSpace(in))
	if n == "" {
		return "", badField(field, validate.CodeRequired, "a name is required")
	}
	if !strings.HasPrefix(n, username+"_") {
		n = username + "_" + n
	}
	if agent.CheckMySQLName(username, n, maxLen) != nil {
		return "", badField(field, validate.CodeFormat, "use a-z, 0-9 and _; with the prefix "+username+
			"_ the name has at most "+strconv.Itoa(maxLen)+" characters")
	}
	return n, nil
}

// privileges checks a privilege list; empty means ALL.
func privileges(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{agent.PrivilegeAll}, nil
	}
	all := agent.MySQLPrivileges()
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.ToUpper(strings.TrimSpace(p))
		switch {
		case p == agent.PrivilegeAll && len(in) == 1:
		case slices.Contains(all, p):
		default:
			return nil, badField("privileges", validate.CodeFormat, "unknown privilege "+p+" (or ALL alone)")
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	// Every privilege listed is ALL.
	if len(out) == len(all) {
		return []string{agent.PrivilegeAll}, nil
	}
	slices.SortFunc(out, func(a, b string) int { return slices.Index(all, a) - slices.Index(all, b) })
	return out, nil
}

func (s *Service) sealHash(userID, password string) []byte {
	return s.box.Seal([]byte(agent.NativePasswordHash(password)), []byte("db-user:"+userID))
}

// checkLimit refuses one more when the account has n and the package allows limit.
func checkLimit(n int, err error, limit *int64, what string) error {
	if err != nil || limit == nil {
		return err
	}
	if int64(n) >= *limit {
		return apperr.NewConflict("limit_reached", "the package allows no more "+what)
	}
	return nil
}

// Overview returns an account's databases, users and grants, with sizes
// from the database server when it answers.
func (s *Service) Overview(ctx context.Context, p *auth.Principal, accountID string) (Overview, error) {
	a, lim, err := s.access(ctx, p, accountID, FeatureMySQL)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{
		Prefix: a.Username + "_", Privileges: agent.MySQLPrivileges(), MaxDBs: lim.Databases, MaxUsers: lim.DBUsers,
		Host: ConnectHost, Server: "ok",
	}
	if p.Login.Role == store.RoleAdmin {
		o.PHPMyAdmin = true
	} else if _, features, err := s.plans.Entitlements(ctx, a.PackageID); err == nil {
		o.PHPMyAdmin = slices.Contains(features, FeaturePHPMyAdmin)
	}
	dbs, err := s.db.ListDatabases(ctx, a.ID)
	if err != nil {
		return o, err
	}
	users, err := store.ListDBUsers(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	grants, err := store.AccountGrants(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sizes, err := s.agent.MySQLDatabaseSizes(sctx, &agentv1.MySQLDatabaseSizesRequest{Username: a.Username})
	switch {
	case status.Code(err) == codes.NotFound:
		o.Server = "MariaDB is not installed"
	case err != nil:
		o.Server = "the database server did not answer: " + status.Convert(err).Message()
	}
	dbName, userName := map[string]string{}, map[string]string{}
	for _, d := range dbs {
		dbName[d.ID] = d.Name
	}
	for _, u := range users {
		userName[u.ID] = u.Name
	}
	byDB, byUser := map[string][]Access{}, map[string][]Access{}
	for _, g := range grants {
		byDB[g.DatabaseID] = append(byDB[g.DatabaseID], Access{ID: g.UserID, Name: userName[g.UserID], Privileges: g.Privileges})
		byUser[g.UserID] = append(byUser[g.UserID], Access{ID: g.DatabaseID, Name: dbName[g.DatabaseID], Privileges: g.Privileges})
	}
	o.Databases = make([]Database, 0, len(dbs))
	for _, d := range dbs {
		v := dbView(d, byDB[d.ID])
		if size, ok := sizes.GetSizes()[d.Name]; ok {
			v.SizeBytes = &size
		}
		o.Databases = append(o.Databases, v)
	}
	o.Users = make([]User, 0, len(users))
	for _, u := range users {
		o.Users = append(o.Users, userView(u, byUser[u.ID]))
	}
	return o, nil
}

func dbView(d store.Database, users []Access) Database {
	if users == nil {
		users = []Access{}
	}
	slices.SortFunc(users, func(a, b Access) int { return strings.Compare(a.Name, b.Name) })
	return Database{ID: d.ID, AccountID: d.AccountID, Name: d.Name, Users: users, CreatedAt: d.CreatedAt}
}

func userView(u store.DBUser, dbs []Access) User {
	if dbs == nil {
		dbs = []Access{}
	}
	slices.SortFunc(dbs, func(a, b Access) int { return strings.Compare(a.Name, b.Name) })
	return User{ID: u.ID, AccountID: u.AccountID, Name: u.Name, Databases: dbs, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}

// insertDatabase adds a database row inside tx, within the package limit.
func insertDatabase(ctx context.Context, tx *sql.Tx, a *store.Account, lim plans.Limits, d *store.Database) error {
	n, err := store.CountDatabases(ctx, tx, a.ID)
	if err := checkLimit(n, err, lim.Databases, "databases"); err != nil {
		return err
	}
	if err := store.InsertDatabase(ctx, tx, d); errors.Is(err, store.ErrConflict) {
		return apperr.NewConflict("name_taken", "the account has a database "+d.Name+" already")
	} else if err != nil {
		return err
	}
	return nil
}

// CreateDatabase adds a database.
func (s *Service) CreateDatabase(ctx context.Context, c auth.Client, p *auth.Principal, accountID, name string) (Database, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Database{}, err
	}
	d := &store.Database{ID: ids.New(), AccountID: a.ID}
	if d.Name, err = fullName(a.Username, name, "name", agent.MaxDatabaseName); err != nil {
		return Database{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := insertDatabase(ctx, tx, a, lim, d); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.create", a.ID, "database", d.ID, map[string]any{"name": d.Name}))
	})
	if err != nil {
		return Database{}, err
	}
	v := dbView(*d, nil)
	v.JobID = jobID
	return v, nil
}

func (s *Service) ownDatabase(ctx context.Context, p *auth.Principal, id string) (*store.Database, *store.Account, plans.Limits, error) {
	d, err := s.db.DatabaseByID(ctx, id)
	if err != nil {
		return nil, nil, plans.Limits{}, err
	}
	a, lim, err := s.forChange(ctx, p, d.AccountID)
	return d, a, lim, err
}

// RenameDatabase gives a database a new name. MariaDB moves the tables
// now, so the answer tells whether it worked; the job that follows moves
// the users' privileges to the new name.
func (s *Service) RenameDatabase(ctx context.Context, c auth.Client, p *auth.Principal, id, name string) (Database, error) {
	d, a, _, err := s.ownDatabase(ctx, p, id)
	if err != nil {
		return Database{}, err
	}
	to, err := fullName(a.Username, name, "name", agent.MaxDatabaseName)
	if err != nil {
		return Database{}, err
	}
	if to == d.Name {
		return dbView(*d, nil), nil
	}
	if _, err := s.db.DatabaseByName(ctx, to); err == nil {
		return Database{}, apperr.NewConflict("name_taken", "the account has a database "+to+" already")
	}
	_, err = s.agent.MySQLDatabaseRename(ctx, &agentv1.MySQLDatabaseRenameRequest{Username: a.Username, From: d.Name, To: to})
	switch {
	case status.Code(err) == codes.InvalidArgument:
		return Database{}, apperr.NewConflict("rename_refused", status.Convert(err).Message())
	case status.Code(err) == codes.NotFound:
		return Database{}, apperr.NewConflict("no_server", "MariaDB is not installed on this server")
	case err != nil:
		return Database{}, err
	}
	from := d.Name
	d.Name = to
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.RenameDatabase(ctx, tx, d.ID, to); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.rename", a.ID, "database", d.ID, map[string]any{"from": from, "to": to}))
	})
	if err != nil {
		return Database{}, err
	}
	v := dbView(*d, nil)
	v.JobID = jobID
	return v, nil
}

// DeleteDatabase removes a database with all its data.
func (s *Service) DeleteDatabase(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	d, a, _, err := s.ownDatabase(ctx, p, id)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteDatabase(ctx, tx, d.ID); err != nil { // its grants go with it
			return err
		}
		if _, err := s.enqueueDrop(ctx, tx, p.Login.ID, a.ID, d.Name); err != nil {
			return err
		}
		// The apply runs after the drop (same lock key): its end is the end.
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.delete", a.ID, "database", d.ID, map[string]any{"name": d.Name}))
	})
	return jobID, err
}

// insertUser adds a database user row inside tx, within the package limit.
func (s *Service) insertUser(ctx context.Context, tx *sql.Tx, a *store.Account, lim plans.Limits, u *store.DBUser) error {
	n, err := store.CountDBUsers(ctx, tx, a.ID)
	if err := checkLimit(n, err, lim.DBUsers, "database users"); err != nil {
		return err
	}
	if err := store.InsertDBUser(ctx, tx, u); errors.Is(err, store.ErrConflict) {
		return apperr.NewConflict("name_taken", "the account has a database user "+u.Name+" already")
	} else if err != nil {
		return err
	}
	return nil
}

func (s *Service) newUser(a *store.Account, name, password, field string) (*store.DBUser, error) {
	u := &store.DBUser{ID: ids.New(), AccountID: a.ID}
	var err error
	if u.Name, err = fullName(a.Username, name, field, agent.MaxDBUserName); err != nil {
		return nil, err
	}
	if err := validate.Password(password); err != nil {
		return nil, validate.WithField(err, "password")
	}
	u.PasswordEnc = s.sealHash(u.ID, password)
	return u, nil
}

// CreateUser adds a database user.
func (s *Service) CreateUser(ctx context.Context, c auth.Client, p *auth.Principal, accountID, name, password string) (User, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return User{}, err
	}
	u, err := s.newUser(a, name, password, "name")
	if err != nil {
		return User{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.insertUser(ctx, tx, a, lim, u); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dbuser.create", a.ID, "db_user", u.ID, map[string]any{"name": u.Name}))
	})
	if err != nil {
		return User{}, err
	}
	v := userView(*u, nil)
	v.JobID = jobID
	return v, nil
}

func (s *Service) ownUser(ctx context.Context, p *auth.Principal, id string) (*store.DBUser, *store.Account, error) {
	u, err := s.db.DBUserByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	a, _, err := s.forChange(ctx, p, u.AccountID)
	return u, a, err
}

// SetPassword changes a database user's password.
func (s *Service) SetPassword(ctx context.Context, c auth.Client, p *auth.Principal, id, password string) (string, error) {
	u, a, err := s.ownUser(ctx, p, id)
	if err != nil {
		return "", err
	}
	if err := validate.Password(password); err != nil {
		return "", validate.WithField(err, "password")
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetDBUserPassword(ctx, tx, u.ID, s.sealHash(u.ID, password)); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dbuser.password", a.ID, "db_user", u.ID, map[string]any{"name": u.Name}))
	})
	return jobID, err
}

// DeleteUser removes a database user.
func (s *Service) DeleteUser(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	u, a, err := s.ownUser(ctx, p, id)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteDBUser(ctx, tx, u.ID); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dbuser.delete", a.ID, "db_user", u.ID, map[string]any{"name": u.Name}))
	})
	return jobID, err
}

// SetGrant gives a user privileges on a database of the same account,
// replacing the ones it had there.
func (s *Service) SetGrant(ctx context.Context, c auth.Client, p *auth.Principal, userID, databaseID string, in GrantInput) (string, error) {
	u, a, err := s.ownUser(ctx, p, userID)
	if err != nil {
		return "", err
	}
	d, err := s.db.DatabaseByID(ctx, databaseID)
	if err != nil || d.AccountID != a.ID {
		return "", store.ErrNotFound
	}
	privs, err := privileges(in.Privileges)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetGrant(ctx, tx, store.DBGrant{UserID: u.ID, DatabaseID: d.ID, Privileges: privs}); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dbgrant.set", a.ID, "db_user", u.ID, map[string]any{
			"user": u.Name, "database": d.Name, "privileges": privs,
		}))
	})
	return jobID, err
}

// RevokeGrant takes a user's privileges on a database away.
func (s *Service) RevokeGrant(ctx context.Context, c auth.Client, p *auth.Principal, userID, databaseID string) (string, error) {
	u, a, err := s.ownUser(ctx, p, userID)
	if err != nil {
		return "", err
	}
	d, err := s.db.DatabaseByID(ctx, databaseID)
	if err != nil || d.AccountID != a.ID {
		return "", store.ErrNotFound
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteGrant(ctx, tx, u.ID, d.ID); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dbgrant.delete", a.ID, "db_user", u.ID, map[string]any{"user": u.Name, "database": d.Name}))
	})
	return jobID, err
}

// Wizard creates a database, a user and the user's privileges on it in one step.
func (s *Service) Wizard(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in WizardInput) (WizardResult, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return WizardResult{}, err
	}
	d := &store.Database{ID: ids.New(), AccountID: a.ID}
	if d.Name, err = fullName(a.Username, in.Database, "database", agent.MaxDatabaseName); err != nil {
		return WizardResult{}, err
	}
	u, err := s.newUser(a, in.User, in.Password, "user")
	if err != nil {
		return WizardResult{}, err
	}
	privs, err := privileges(in.Privileges)
	if err != nil {
		return WizardResult{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := insertDatabase(ctx, tx, a, lim, d); err != nil {
			return err
		}
		if err := s.insertUser(ctx, tx, a, lim, u); err != nil {
			return err
		}
		if err := store.SetGrant(ctx, tx, store.DBGrant{UserID: u.ID, DatabaseID: d.ID, Privileges: privs}); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.wizard", a.ID, "database", d.ID, map[string]any{
			"database": d.Name, "user": u.Name, "privileges": privs,
		}))
	})
	if err != nil {
		return WizardResult{}, err
	}
	return WizardResult{
		Database: dbView(*d, []Access{{ID: u.ID, Name: u.Name, Privileges: privs}}),
		User:     userView(*u, []Access{{ID: d.ID, Name: d.Name, Privileges: privs}}),
		Host:     ConnectHost, JobID: jobID,
	}, nil
}

// Signon opens phpMyAdmin for an account's databases (USR-DB-04): the
// agent makes a temporary user and a one-time ticket, whose ID it returns.
func (s *Service) Signon(ctx context.Context, c auth.Client, p *auth.Principal, accountID string) (string, error) {
	a, _, err := s.access(ctx, p, accountID, FeaturePHPMyAdmin)
	if err != nil {
		return "", err
	}
	if p.Login.Role == store.RoleUser {
		if _, _, err := s.access(ctx, p, accountID, FeatureMySQL); err != nil {
			return "", err
		}
	}
	if a.Status != store.AccountActive {
		return "", apperr.NewConflict("bad_status", "phpMyAdmin opens only for an active account")
	}
	dbs, err := s.db.ListDatabases(ctx, a.ID)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(dbs))
	for _, d := range dbs {
		names = append(names, d.Name)
	}
	res, err := s.agent.MySQLSignon(ctx, &agentv1.MySQLSignonRequest{Username: a.Username, Databases: names})
	if status.Code(err) == codes.NotFound {
		return "", apperr.NewConflict("not_installed", status.Convert(err).Message())
	}
	if err != nil {
		return "", err
	}
	_ = s.audit.Record(ctx, event(c, p, "mysql.signon", a.ID, "account", a.ID, map[string]any{"databases": len(names)}))
	return res.GetTicket(), nil
}

func admin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

// Status reports the database server and phpMyAdmin (admins only).
func (s *Service) Status(ctx context.Context, p *auth.Principal) (Status, error) {
	if err := admin(p); err != nil {
		return Status{}, err
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.agent.MySQLStatus(sctx, &agentv1.MySQLStatusRequest{})
	switch {
	case status.Code(err) == codes.NotFound:
		return Status{Detail: status.Convert(err).Message()}, nil
	case err != nil:
		return Status{Installed: true, Detail: "the database server did not answer: " + status.Convert(err).Message()}, nil
	}
	return Status{Installed: true, Version: res.GetVersion(), PHPMyAdmin: res.GetPhpmyadmin()}, nil
}

// SetRootPassword lets MariaDB's root in with this password (ADM-DB-09).
// Root on the server keeps getting in through the socket.
func (s *Service) SetRootPassword(ctx context.Context, c auth.Client, p *auth.Principal, password string) error {
	if err := admin(p); err != nil {
		return err
	}
	if err := validate.Password(password); err != nil {
		return validate.WithField(err, "password")
	}
	_, err := s.agent.MySQLRootPassword(ctx, &agentv1.MySQLRootPasswordRequest{PasswordHash: agent.NativePasswordHash(password)})
	if status.Code(err) == codes.NotFound {
		return apperr.NewConflict("not_installed", status.Convert(err).Message())
	}
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "mysql.root_password", "", "server", "mysql", nil))
}
