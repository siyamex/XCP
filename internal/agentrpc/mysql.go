package agentrpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func mysqlAccountFrom(req *agentv1.MySQLAccountApplyRequest) agent.MySQLAccount {
	a := agent.MySQLAccount{Username: req.GetUsername(), Databases: req.GetDatabases(), Locked: req.GetLocked()}
	for _, u := range req.GetUsers() {
		mu := agent.MySQLUser{Name: u.GetName(), PasswordHash: u.GetPasswordHash()}
		for _, g := range u.GetGrants() {
			mu.Grants = append(mu.Grants, agent.MySQLGrant{Database: g.GetDatabase(), Privileges: g.GetPrivileges()})
		}
		a.Users = append(a.Users, mu)
	}
	return a
}

// MySQLStatus implements agentv1.AgentServiceServer.
func (s *Server) MySQLStatus(ctx context.Context, _ *agentv1.MySQLStatusRequest) (*agentv1.MySQLStatusResponse, error) {
	st, err := s.MySQL.Status(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLStatusResponse{Version: st.Version, Phpmyadmin: st.PHPMyAdmin}, nil
}

// MySQLAccountApply implements agentv1.AgentServiceServer.
func (s *Server) MySQLAccountApply(ctx context.Context, req *agentv1.MySQLAccountApplyRequest) (*agentv1.MySQLAccountApplyResponse, error) {
	changed, err := s.MySQL.ApplyAccount(ctx, mysqlAccountFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLAccountApplyResponse{Changed: changed}, nil
}

// MySQLAccountRemove implements agentv1.AgentServiceServer.
func (s *Server) MySQLAccountRemove(ctx context.Context, req *agentv1.MySQLAccountRemoveRequest) (*agentv1.MySQLAccountRemoveResponse, error) {
	dbs, users, err := s.MySQL.RemoveAccount(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLAccountRemoveResponse{Databases: uint32(dbs), Users: uint32(users)}, nil //nolint:gosec // G115: counts of one account
}

// MySQLDatabaseSizes implements agentv1.AgentServiceServer.
func (s *Server) MySQLDatabaseSizes(ctx context.Context, req *agentv1.MySQLDatabaseSizesRequest) (*agentv1.MySQLDatabaseSizesResponse, error) {
	sizes, err := s.MySQL.DatabaseSizes(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLDatabaseSizesResponse{Sizes: sizes}, nil
}

// MySQLDatabaseDrop implements agentv1.AgentServiceServer.
func (s *Server) MySQLDatabaseDrop(ctx context.Context, req *agentv1.MySQLDatabaseDropRequest) (*agentv1.MySQLDatabaseDropResponse, error) {
	dropped, err := s.MySQL.DropDatabase(ctx, req.GetUsername(), req.GetDatabase())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLDatabaseDropResponse{Dropped: dropped}, nil
}

// MySQLDatabaseRename implements agentv1.AgentServiceServer.
func (s *Server) MySQLDatabaseRename(ctx context.Context, req *agentv1.MySQLDatabaseRenameRequest) (*agentv1.MySQLDatabaseRenameResponse, error) {
	if err := s.MySQL.RenameDatabase(ctx, req.GetUsername(), req.GetFrom(), req.GetTo()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLDatabaseRenameResponse{}, nil
}

// MySQLSignon implements agentv1.AgentServiceServer.
func (s *Server) MySQLSignon(ctx context.Context, req *agentv1.MySQLSignonRequest) (*agentv1.MySQLSignonResponse, error) {
	ticket, err := s.MySQL.Signon(ctx, req.GetUsername(), req.GetDatabases())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLSignonResponse{Ticket: ticket}, nil
}

// MySQLSignonExpire implements agentv1.AgentServiceServer.
func (s *Server) MySQLSignonExpire(ctx context.Context, _ *agentv1.MySQLSignonExpireRequest) (*agentv1.MySQLSignonExpireResponse, error) {
	n, err := s.MySQL.ExpireSignons(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLSignonExpireResponse{Dropped: uint32(n)}, nil //nolint:gosec // G115: a count
}

// MySQLRootPassword implements agentv1.AgentServiceServer.
func (s *Server) MySQLRootPassword(ctx context.Context, req *agentv1.MySQLRootPasswordRequest) (*agentv1.MySQLRootPasswordResponse, error) {
	if err := s.MySQL.SetRootPassword(ctx, req.GetPasswordHash()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MySQLRootPasswordResponse{}, nil
}

// fakeMySQL is the fake agent's MariaDB: what each account has.
type fakeMySQL struct {
	mu       sync.Mutex
	accounts map[string]*fakeMySQLAccount
	signons  []string // usernames, one per sign-on
	rootHash string
}

type fakeMySQLAccount struct {
	databases map[string]bool
	users     map[string]agent.MySQLUser
	locked    bool
}

func (f *fakeMySQL) account(username string) *fakeMySQLAccount {
	if f.accounts == nil {
		f.accounts = map[string]*fakeMySQLAccount{}
	}
	a := f.accounts[username]
	if a == nil {
		a = &fakeMySQLAccount{databases: map[string]bool{}, users: map[string]agent.MySQLUser{}}
		f.accounts[username] = a
	}
	return a
}

// MySQLAccount returns what the fake MariaDB holds for an account, for tests.
func (f *Fake) MySQLAccount(username string) (databases []string, users []agent.MySQLUser, locked bool) {
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	a := f.mysql.account(username)
	return slices.Sorted(maps.Keys(a.databases)), slices.SortedFunc(maps.Values(a.users), func(x, y agent.MySQLUser) int {
		return strings.Compare(x.Name, y.Name)
	}), a.locked
}

// MySQLSignons returns the accounts the fake agent made sign-on users for, for tests.
func (f *Fake) MySQLSignons() []string {
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	return slices.Clone(f.mysql.signons)
}

// MySQLRootHash returns the root password hash set through the fake agent, for tests.
func (f *Fake) MySQLRootHash() string {
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	return f.mysql.rootHash
}

func (f *Fake) recordf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(format, args...)
}

func fakeInvalid(err error) error { return status.Error(codes.InvalidArgument, err.Error()) }

// MySQLStatus implements Client.
func (f *Fake) MySQLStatus(context.Context, *agentv1.MySQLStatusRequest, ...grpc.CallOption) (*agentv1.MySQLStatusResponse, error) {
	f.recordf("MySQLStatus")
	return &agentv1.MySQLStatusResponse{Version: "10.11.0-MariaDB-fake", Phpmyadmin: "5.2.3"}, nil
}

// MySQLAccountApply implements Client.
func (f *Fake) MySQLAccountApply(_ context.Context, req *agentv1.MySQLAccountApplyRequest, _ ...grpc.CallOption) (*agentv1.MySQLAccountApplyResponse, error) {
	f.recordf("MySQLAccountApply %s (%d databases, %d users)", req.GetUsername(), len(req.GetDatabases()), len(req.GetUsers()))
	in := mysqlAccountFrom(req)
	if err := agent.CheckMySQLAccount(in); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	a := f.mysql.account(in.Username)
	for _, d := range in.Databases {
		a.databases[d] = true
	}
	a.users = map[string]agent.MySQLUser{}
	for _, u := range in.Users {
		a.users[u.Name] = u
	}
	a.locked = in.Locked
	return &agentv1.MySQLAccountApplyResponse{Changed: true}, nil
}

// MySQLAccountRemove implements Client.
func (f *Fake) MySQLAccountRemove(_ context.Context, req *agentv1.MySQLAccountRemoveRequest, _ ...grpc.CallOption) (*agentv1.MySQLAccountRemoveResponse, error) {
	f.recordf("MySQLAccountRemove %s", req.GetUsername())
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	a := f.mysql.account(req.GetUsername())
	res := &agentv1.MySQLAccountRemoveResponse{Databases: uint32(len(a.databases)), Users: uint32(len(a.users))} //nolint:gosec // G115: small counts
	delete(f.mysql.accounts, req.GetUsername())
	return res, nil
}

// MySQLDatabaseSizes implements Client: every database is empty.
func (f *Fake) MySQLDatabaseSizes(_ context.Context, req *agentv1.MySQLDatabaseSizesRequest, _ ...grpc.CallOption) (*agentv1.MySQLDatabaseSizesResponse, error) {
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	sizes := map[string]int64{}
	for d := range f.mysql.account(req.GetUsername()).databases {
		sizes[d] = 0
	}
	return &agentv1.MySQLDatabaseSizesResponse{Sizes: sizes}, nil
}

// MySQLDatabaseDrop implements Client.
func (f *Fake) MySQLDatabaseDrop(_ context.Context, req *agentv1.MySQLDatabaseDropRequest, _ ...grpc.CallOption) (*agentv1.MySQLDatabaseDropResponse, error) {
	f.recordf("MySQLDatabaseDrop %s", req.GetDatabase())
	if err := agent.CheckMySQLName(req.GetUsername(), req.GetDatabase(), agent.MaxDatabaseName); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	a := f.mysql.account(req.GetUsername())
	dropped := a.databases[req.GetDatabase()]
	delete(a.databases, req.GetDatabase())
	return &agentv1.MySQLDatabaseDropResponse{Dropped: dropped}, nil
}

// MySQLDatabaseRename implements Client.
func (f *Fake) MySQLDatabaseRename(_ context.Context, req *agentv1.MySQLDatabaseRenameRequest, _ ...grpc.CallOption) (*agentv1.MySQLDatabaseRenameResponse, error) {
	f.recordf("MySQLDatabaseRename %s %s", req.GetFrom(), req.GetTo())
	for _, n := range []string{req.GetFrom(), req.GetTo()} {
		if err := agent.CheckMySQLName(req.GetUsername(), n, agent.MaxDatabaseName); err != nil {
			return nil, fakeInvalid(err)
		}
	}
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	a := f.mysql.account(req.GetUsername())
	switch {
	case !a.databases[req.GetFrom()]:
		return nil, status.Errorf(codes.InvalidArgument, "database %s does not exist", req.GetFrom())
	case a.databases[req.GetTo()]:
		return nil, status.Errorf(codes.InvalidArgument, "database %s exists already", req.GetTo())
	}
	delete(a.databases, req.GetFrom())
	a.databases[req.GetTo()] = true
	return &agentv1.MySQLDatabaseRenameResponse{}, nil
}

// MySQLSignon implements Client.
func (f *Fake) MySQLSignon(_ context.Context, req *agentv1.MySQLSignonRequest, _ ...grpc.CallOption) (*agentv1.MySQLSignonResponse, error) {
	f.recordf("MySQLSignon %s (%d databases)", req.GetUsername(), len(req.GetDatabases()))
	for _, d := range req.GetDatabases() {
		if err := agent.CheckMySQLName(req.GetUsername(), d, agent.MaxDatabaseName); err != nil {
			return nil, fakeInvalid(err)
		}
	}
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	f.mysql.signons = append(f.mysql.signons, req.GetUsername())
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &agentv1.MySQLSignonResponse{Ticket: hex.EncodeToString(b)}, nil
}

// MySQLSignonExpire implements Client.
func (f *Fake) MySQLSignonExpire(context.Context, *agentv1.MySQLSignonExpireRequest, ...grpc.CallOption) (*agentv1.MySQLSignonExpireResponse, error) {
	f.recordf("MySQLSignonExpire")
	return &agentv1.MySQLSignonExpireResponse{}, nil
}

// MySQLRootPassword implements Client.
func (f *Fake) MySQLRootPassword(_ context.Context, req *agentv1.MySQLRootPasswordRequest, _ ...grpc.CallOption) (*agentv1.MySQLRootPasswordResponse, error) {
	f.recordf("MySQLRootPassword")
	if err := agent.CheckNativeHash(req.GetPasswordHash()); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mysql.mu.Lock()
	defer f.mysql.mu.Unlock()
	f.mysql.rootHash = req.GetPasswordHash()
	return &agentv1.MySQLRootPasswordResponse{}, nil
}
