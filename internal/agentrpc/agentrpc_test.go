package agentrpc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

var ctx = context.Background()

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fixedPeer pretends every connection comes from uid (stands in for SO_PEERCRED).
type fixedPeer struct{ uid uint32 }

func (p fixedPeer) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, newPeerCreds(p.uid, p.uid, 4242), nil
}

func (p fixedPeer) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	panic("server only")
}
func (p fixedPeer) Info() credentials.ProtocolInfo          { return credentials.ProtocolInfo{} }
func (p fixedPeer) Clone() credentials.TransportCredentials { return p }
func (p fixedPeer) OverrideServerName(string) error         { return nil }

type stubManager struct{}

func (stubManager) Status(context.Context, string) (agent.UnitStatus, error) {
	return agent.UnitStatus{ActiveState: "active", SubState: "running", MainPID: 10, Enabled: true}, nil
}
func (stubManager) Do(context.Context, string, agent.Action) error { return nil }

type testServer struct {
	client  Client
	managed string // managed dir on the local OS
	check   *string
}

// startServer runs the real Server over an in-memory connection. Calls appear
// to come from peerUID; allowedUID is what the interceptor accepts.
func startServer(t *testing.T, peerUID, allowedUID uint32) *testServer {
	t.Helper()
	managed := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(managed, 0o755); err != nil {
		t.Fatal(err)
	}
	failOutput := ""
	check := func(context.Context, agent.Validator) error {
		if failOutput != "" {
			return &agent.ValidationFailedError{Output: failOutput}
		}
		return nil
	}
	files, err := agent.NewFiles([]string{managed}, check)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Services: agent.Services{Registry: agent.NewServiceRegistry(agent.UbuntuServices()), Manager: stubManager{}},
		Files:    files,
		Version:  "test",
		Log:      discardLog(),
	}
	gs := grpc.NewServer(grpc.Creds(fixedPeer{peerUID}), grpc.UnaryInterceptor(ServerInterceptor(discardLog(), []uint32{allowedUID})))
	agentv1.RegisterAgentServiceServer(gs, srv)
	lis := bufconn.Listen(1 << 20)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)

	cc, err := grpc.NewClient("passthrough:///agent",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return &testServer{client: agentv1.NewAgentServiceClient(cc), managed: managed, check: &failOutput}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("code = %v (%v), want %v", got, err, want)
	}
}

func TestServerEndToEnd(t *testing.T) {
	s := startServer(t, 1001, 1001)

	ping, err := s.client.Ping(ctx, &agentv1.PingRequest{})
	if err != nil || ping.GetVersion() != "test" {
		t.Fatalf("Ping = %v, %v", ping, err)
	}
	st, err := s.client.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: "php-fpm@8.3"})
	if err != nil || st.GetUnit() != "php8.3-fpm.service" || st.GetActiveState() != "active" {
		t.Fatalf("ServiceStatus = %v, %v", st, err)
	}
	_, err = s.client.ServiceAction(ctx, &agentv1.ServiceActionRequest{Service: "web", Action: agentv1.ServiceActionKind_SERVICE_ACTION_KIND_RELOAD})
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(s.managed, "vhosts", "alice.conf")
	w, err := s.client.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: path, Content: []byte("ok"), Mode: 0o644})
	if err != nil || !w.GetChanged() {
		t.Fatalf("write = %v, %v", w, err)
	}

	*s.check = "AH00526: Syntax error on line 1"
	_, err = s.client.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{
		Path: path, Content: []byte("broken"), Mode: 0o644, Validator: agentv1.Validator_VALIDATOR_APACHE,
	})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "AH00526") {
		t.Fatalf("validator output missing from error: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "ok" {
		t.Fatalf("file not rolled back: %q", b)
	}
}

func TestInterceptorRefusesOtherUIDs(t *testing.T) {
	s := startServer(t, 1002, 1001)
	_, err := s.client.Ping(ctx, &agentv1.PingRequest{})
	wantCode(t, err, codes.PermissionDenied)
}

// The fake must reject the same requests with the same codes as the real server.
func TestFakeMatchesServerErrors(t *testing.T) {
	real := startServer(t, 1001, 1001)
	fake := NewFake()
	fakeDir := agent.DefaultManagedDirs[0]

	type call func(c Client, dir string, join func(...string) string) error
	cases := map[string]struct {
		call call
		want codes.Code
	}{
		"unknown service": {func(c Client, _ string, _ func(...string) string) error {
			_, err := c.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: "sshd; reboot"})
			return err
		}, codes.InvalidArgument},
		"unspecified action": {func(c Client, _ string, _ func(...string) string) error {
			_, err := c.ServiceAction(ctx, &agentv1.ServiceActionRequest{Service: "web"})
			return err
		}, codes.InvalidArgument},
		"setuid mode": {func(c Client, dir string, join func(...string) string) error {
			_, err := c.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: join(dir, "x.conf"), Content: []byte("x"), Mode: 0o4644})
			return err
		}, codes.InvalidArgument},
		"unknown validator": {func(c Client, dir string, join func(...string) string) error {
			_, err := c.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: join(dir, "x.conf"), Mode: 0o644, Validator: 99})
			return err
		}, codes.InvalidArgument},
		"outside managed dir": {func(c Client, dir string, join func(...string) string) error {
			_, err := c.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: join(dir+"-evil", "x.conf"), Mode: 0o644})
			return err
		}, codes.InvalidArgument},
		"hidden file": {func(c Client, dir string, join func(...string) string) error {
			_, err := c.FileRemoveManaged(ctx, &agentv1.FileRemoveManagedRequest{Path: join(dir, ".xcp-tmp-x")})
			return err
		}, codes.InvalidArgument},
		"valid write": {func(c Client, dir string, join func(...string) string) error {
			_, err := c.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: join(dir, "ok.conf"), Content: []byte("x"), Mode: 0o640})
			return err
		}, codes.OK},
	}
	slashJoin := func(p ...string) string { return strings.Join(p, "/") }
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wantCode(t, tc.call(real.client, real.managed, filepath.Join), tc.want)
			wantCode(t, tc.call(fake, fakeDir, slashJoin), tc.want)
		})
	}
}

func TestFakeRecordsAndSimulatesValidationFailure(t *testing.T) {
	f := NewFake()
	p := "/etc/apache2/xcp/vhosts/alice.conf"
	if _, err := f.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: p, Content: []byte("v1"), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	f.FailValidation("Syntax error")
	_, err := f.FileWriteManaged(ctx, &agentv1.FileWriteManagedRequest{Path: p, Content: []byte("v2"), Mode: 0o644, Validator: agentv1.Validator_VALIDATOR_APACHE})
	wantCode(t, err, codes.FailedPrecondition)
	if b, _ := f.File(p); string(b) != "v1" {
		t.Fatalf("fake kept broken content: %q", b)
	}
	if _, err := f.ServiceAction(ctx, &agentv1.ServiceActionRequest{Service: "web", Action: agentv1.ServiceActionKind_SERVICE_ACTION_KIND_STOP}); err != nil {
		t.Fatal(err)
	}
	st, _ := f.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: "web"})
	if st.GetActiveState() != "inactive" {
		t.Fatalf("state = %s", st.GetActiveState())
	}
	if calls := f.Calls(); len(calls) != 4 || !strings.HasPrefix(calls[2], "ServiceAction web stop") {
		t.Fatalf("calls = %q", calls)
	}
}
