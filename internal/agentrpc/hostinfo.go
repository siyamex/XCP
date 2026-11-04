package agentrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// ServerStatus implements agentv1.AgentServiceServer.
func (s *Server) ServerStatus(ctx context.Context, _ *agentv1.ServerStatusRequest) (*agentv1.ServerStatusResponse, error) {
	st, err := s.HostInfo.Status(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	return statusToProto(st), nil
}

// ServiceLog implements agentv1.AgentServiceServer.
func (s *Server) ServiceLog(ctx context.Context, req *agentv1.ServiceLogRequest) (*agentv1.ServiceLogResponse, error) {
	unit, text, err := s.Services.Log(ctx, req.GetService(), int(req.GetLines()))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.ServiceLogResponse{Unit: unit, Text: text}, nil
}

func statusToProto(st agent.HostStatus) *agentv1.ServerStatusResponse {
	r := &agentv1.ServerStatusResponse{
		Hostname: st.Hostname, Os: st.OS, Kernel: st.Kernel, Arch: st.Arch, CpuModel: st.CPUModel, Cores: int32(st.Cores), //nolint:gosec // G115: a core count
		UptimeSeconds: int64(st.Uptime.Seconds()), Load1: st.Load[0], Load5: st.Load[1], Load15: st.Load[2], CpuPercent: st.CPUPercent,
		MemTotal: st.MemTotal, MemAvailable: st.MemAvailable, SwapTotal: st.SwapTotal, SwapFree: st.SwapFree,
		AccountsComputing: st.AccountsComputing, Versions: st.Versions, XcpVersion: st.XCPVersion, Timezone: st.Timezone,
	}
	if !st.AccountsAt.IsZero() {
		r.AccountsAtUnix = st.AccountsAt.Unix()
	}
	for _, d := range st.Disks {
		r.Disks = append(r.Disks, &agentv1.HostDisk{Mount: d.Mount, Device: d.Device, Fs: d.FS, Total: d.Total, Used: d.Used, Files: d.Files, FilesUsed: d.FilesUsed})
	}
	for _, n := range st.Net {
		r.Net = append(r.Net, &agentv1.HostNet{Name: n.Name, RxBytes: n.RxBytes, TxBytes: n.TxBytes})
	}
	for _, p := range st.Procs {
		r.Procs = append(r.Procs, &agentv1.HostProc{Pid: int32(p.PID), Name: p.Name, User: p.User, CpuPercent: p.CPUPercent, Rss: p.RSS}) //nolint:gosec // G115: a pid
	}
	for _, a := range st.Accounts {
		r.Accounts = append(r.Accounts, &agentv1.HostAccount{Username: a.Username, Bytes: a.Bytes, Partial: a.Partial})
	}
	return r
}

// ServerStatus implements Client with a fixed host, for tests and development.
func (f *Fake) ServerStatus(context.Context, *agentv1.ServerStatusRequest, ...grpc.CallOption) (*agentv1.ServerStatusResponse, error) {
	f.recordf("ServerStatus")
	return statusToProto(agent.HostStatus{
		Hostname: "fake-host", OS: "Fake Linux 1", Kernel: "6.0.0-fake", Arch: "amd64", CPUModel: "Fake CPU", Cores: 4,
		Uptime: 90 * time.Minute, Load: [3]float64{0.5, 0.4, 0.3}, CPUPercent: 12.5,
		MemTotal: 8 << 30, MemAvailable: 6 << 30, SwapTotal: 2 << 30, SwapFree: 2 << 30,
		Disks:    []agent.HostDisk{{Mount: "/", Device: "/dev/fake1", FS: "ext4", Total: 100 << 30, Used: 40 << 30, Files: 1000000, FilesUsed: 250000}},
		Net:      []agent.HostNet{{Name: "eth0", RxBytes: 1 << 30, TxBytes: 2 << 30}},
		Procs:    []agent.HostProc{{PID: 1, Name: "systemd", User: "root", CPUPercent: 0.1, RSS: 20 << 20}},
		Accounts: []agent.HostAccount{{Username: "alice", Bytes: 5 << 30}}, AccountsAt: time.Now(),
		Versions: map[string]string{"apache2": "2.4.58-fake"}, XCPVersion: "dev", Timezone: "UTC",
	}), nil
}

// ServiceLog implements Client.
func (f *Fake) ServiceLog(_ context.Context, req *agentv1.ServiceLogRequest, _ ...grpc.CallOption) (*agentv1.ServiceLogResponse, error) {
	f.recordf("ServiceLog %s", req.GetService())
	return &agentv1.ServiceLogResponse{Unit: req.GetService() + ".service", Text: strings.Repeat("line\n", 3)}, nil
}
