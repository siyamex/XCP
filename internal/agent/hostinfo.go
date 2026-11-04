package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/userfs"
)

// HostInfo reports the server's state for the admin dashboard and server
// information page (ADM-SVC-03, 05, 08; ADR-0014): read from /proc and the
// dpkg database, never by running commands.
type HostInfo struct {
	Proc       string        // /proc
	OSRelease  string        // /etc/os-release
	DpkgStatus string        // /var/lib/dpkg/status
	HomesRoot  string        // /home
	Version    string        // XCP's
	Sample     time.Duration // how long CPU use is measured; 0: 300 ms
	Localtime  string        // /etc/localtime, which points to the time zone

	mu      sync.Mutex
	usage   []HostAccount
	usageAt time.Time
	running bool
}

// Paths of the host files.
const (
	ProcDir        = "/proc"
	OSReleaseFile  = "/etc/os-release"
	DpkgStatusFile = "/var/lib/dpkg/status"
	JournalctlPath = "/usr/bin/journalctl"
	usageTTL       = 15 * time.Minute
	topProcs       = 12
	clockTicks     = 100 // USER_HZ on Linux
	pageSize       = 4096
)

// HostDisk is a mounted file system.
type HostDisk struct {
	Mount, Device, FS string
	Total, Used       uint64
	Files, FilesUsed  uint64
}

// HostNet is a network interface's counters since boot.
type HostNet struct {
	Name             string
	RxBytes, TxBytes uint64
}

// HostProc is a running process.
type HostProc struct {
	PID        int
	Name, User string
	CPUPercent float64
	RSS        uint64
}

// HostAccount is how much disk an account's home uses.
type HostAccount struct {
	Username string
	Bytes    int64
	Partial  bool // the walk stopped at its limit
}

// HostStatus is everything the agent reports about the host.
type HostStatus struct {
	Hostname, OS, Kernel, Arch, CPUModel string
	Cores                                int
	Uptime                               time.Duration
	Load                                 [3]float64
	CPUPercent                           float64
	MemTotal, MemAvailable               uint64
	SwapTotal, SwapFree                  uint64
	Disks                                []HostDisk
	Net                                  []HostNet
	Procs                                []HostProc
	Accounts                             []HostAccount
	AccountsAt                           time.Time
	AccountsComputing                    bool
	Versions                             map[string]string
	XCPVersion                           string
	Timezone                             string
}

func (h *HostInfo) read(name string) []byte {
	b, _ := os.ReadFile(filepath.Join(h.Proc, name)) //nolint:gosec // G304: fixed names under /proc
	return b
}

// Status measures the host (about 300 ms for CPU use).
func (h *HostInfo) Status(ctx context.Context) (HostStatus, error) {
	st := HostStatus{Arch: runtime.GOARCH, Cores: runtime.NumCPU(), XCPVersion: h.Version, Versions: map[string]string{}}
	st.Hostname, _ = os.Hostname()
	idle1, total1 := cpuTimes(h.read("stat"))
	procs1 := h.processes()
	sample := h.Sample
	if sample <= 0 {
		sample = 300 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return st, ctx.Err()
	case <-time.After(sample):
	}
	idle2, total2 := cpuTimes(h.read("stat"))
	if d := total2 - total1; d > 0 {
		st.CPUPercent = 100 * (1 - float64(idle2-idle1)/float64(d))
	}
	st.Procs = h.topProcesses(procs1, h.processes(), sample)

	mem := parseMeminfo(h.read("meminfo"))
	st.MemTotal, st.MemAvailable, st.SwapTotal, st.SwapFree = mem["MemTotal"], mem["MemAvailable"], mem["SwapTotal"], mem["SwapFree"]
	st.Load = parseLoadavg(h.read("loadavg"))
	if f := strings.Fields(string(h.read("uptime"))); len(f) > 0 {
		secs, _ := strconv.ParseFloat(f[0], 64)
		st.Uptime = time.Duration(secs * float64(time.Second))
	}
	st.Kernel = strings.TrimSpace(string(h.read("sys/kernel/osrelease")))
	st.CPUModel = cpuModel(h.read("cpuinfo"))
	st.Timezone = timezoneName(h.Localtime)
	if b, err := os.ReadFile(h.OSRelease); err == nil {
		st.OS = osName(b)
	}
	st.Net = parseNetDev(h.read("net/dev"))
	for _, m := range parseMounts(h.read("mounts")) {
		if d, ok := statDisk(m); ok {
			st.Disks = append(st.Disks, d)
		}
	}
	if f, err := os.Open(h.DpkgStatus); err == nil {
		st.Versions = parseDpkg(f, wantPackage)
		f.Close()
	}
	st.Accounts, st.AccountsAt, st.AccountsComputing = h.accounts()
	return st, nil
}

// cpuTimes returns the idle and total jiffies of the first "cpu" line of /proc/stat.
func cpuTimes(stat []byte) (idle, total uint64) {
	line, _, _ := bytes.Cut(stat, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		if i < 8 { // user nice system idle iowait irq softirq steal
			total += n
		}
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return idle, total
}

func parseMeminfo(b []byte) map[string]uint64 {
	out := map[string]uint64{}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(f[0], 10, 64)
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		out[k] = n
	}
	return out
}

func parseLoadavg(b []byte) (l [3]float64) {
	f := strings.Fields(string(b))
	for i := range l {
		if i < len(f) {
			l[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	return l
}

func cpuModel(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func osName(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func parseNetDev(b []byte) []HostNet {
	var out []HostNet
	for _, l := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(l, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		out = append(out, HostNet{Name: name, RxBytes: rx, TxBytes: tx})
	}
	return out
}

type mount struct{ Device, Mount, FS string }

var realFS = map[string]bool{"ext4": true, "ext3": true, "ext2": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "vfat": true, "overlay": true, "jfs": true}

// parseMounts lists the real file systems, once per device (a bind mount
// of the same device is not another disk).
func parseMounts(b []byte) []mount {
	var out []mount
	seen := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || !realFS[f[2]] || strings.HasPrefix(f[0], "/dev/loop") {
			continue
		}
		key := f[0]
		if f[2] == "overlay" {
			if f[1] != "/" {
				continue // a container's root is its disk; other overlays are plumbing (WSL, Docker)
			}
			key = "overlay:/"
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, mount{Device: f[0], Mount: strings.ReplaceAll(f[1], `\040`, " "), FS: f[2]})
	}
	return out
}

var phpFPMPkg = regexp.MustCompile(`^php[0-9.]+-fpm$`)

var packages = []string{"apache2", "mariadb-server", "postfix", "dovecot-core", "pdns-server", "pure-ftpd", "rspamd", "openssh-server", "redis-server", "systemd"}

func wantPackage(name string) bool {
	return slices.Contains(packages, name) || phpFPMPkg.MatchString(name)
}

// parseDpkg returns the versions of the installed packages want accepts.
func parseDpkg(r io.Reader, want func(string) bool) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var name, version string
	installed := false
	flush := func() {
		if installed && name != "" && version != "" && want(name) {
			out[name] = version
		}
		name, version, installed = "", "", false
	}
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "Package: "):
			name = l[len("Package: "):]
		case strings.HasPrefix(l, "Status: "):
			installed = strings.HasSuffix(l, " installed")
		case strings.HasPrefix(l, "Version: "):
			version = l[len("Version: "):]
		}
	}
	flush()
	return out
}

type procSample struct {
	name  string
	ticks uint64
	rss   uint64
}

// processes reads every process's name, CPU ticks and resident memory.
func (h *HostInfo) processes() map[int]procSample {
	out := map[int]procSample{}
	ents, err := os.ReadDir(h.Proc)
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(h.Proc, e.Name(), "stat")) //nolint:gosec // G304: /proc
		if err != nil {
			continue
		}
		if s, ok := parseProcStat(b); ok {
			out[pid] = s
		}
	}
	return out
}

// parseProcStat reads "pid (comm) state ... utime stime ... rss ..." (the
// name may hold spaces and parentheses, so it is cut at the last ")").
func parseProcStat(b []byte) (procSample, bool) {
	s := string(b)
	open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return procSample{}, false
	}
	f := strings.Fields(s[end+1:])
	if len(f) < 22 {
		return procSample{}, false
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	rss, _ := strconv.ParseInt(f[21], 10, 64)
	return procSample{name: s[open+1 : end], ticks: ut + st, rss: uint64(max(rss, 0)) * pageSize}, true
}

func (h *HostInfo) topProcesses(a, b map[int]procSample, elapsed time.Duration) []HostProc {
	var list []HostProc
	for pid, s2 := range b {
		s1, ok := a[pid]
		if !ok {
			continue
		}
		cpu := 100 * float64(s2.ticks-min(s1.ticks, s2.ticks)) / clockTicks / elapsed.Seconds()
		list = append(list, HostProc{PID: pid, Name: s2.name, CPUPercent: cpu, RSS: s2.rss})
	}
	slices.SortFunc(list, func(x, y HostProc) int {
		switch {
		case x.CPUPercent != y.CPUPercent:
			if x.CPUPercent > y.CPUPercent {
				return -1
			}
			return 1
		case x.RSS != y.RSS:
			if x.RSS > y.RSS {
				return -1
			}
			return 1
		}
		return x.PID - y.PID
	})
	if len(list) > topProcs {
		list = list[:topProcs]
	}
	users := map[string]string{}
	for i := range list {
		list[i].User = h.procUser(list[i].PID, users)
	}
	return list
}

// procUser names the owner of a process.
func (h *HostInfo) procUser(pid int, cache map[string]string) string {
	b, err := os.ReadFile(filepath.Join(h.Proc, strconv.Itoa(pid), "status")) //nolint:gosec // G304: /proc
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) == 0 {
				return ""
			}
			if n, ok := cache[f[0]]; ok {
				return n
			}
			name := f[0]
			if u, err := user.LookupId(f[0]); err == nil {
				name = u.Username
			}
			cache[f[0]] = name
			return name
		}
	}
	return ""
}

// accounts returns the cached disk use of the accounts' homes, and starts a
// new measurement in the background when it is older than usageTTL.
func (h *HostInfo) accounts() ([]HostAccount, time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running && time.Since(h.usageAt) > usageTTL {
		h.running = true
		go h.measure()
	}
	return slices.Clone(h.usage), h.usageAt, h.running
}

// measure walks every account's home (through fsx, never following links)
// and keeps the result.
func (h *HostInfo) measure() {
	var list []HostAccount
	ents, _ := os.ReadDir(h.HomesRoot)
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if u, err := lookup(e.Name()); err != nil || u == nil || u.Name != AccountMarker {
			continue
		}
		fs, err := userfs.Open(filepath.Join(h.HomesRoot, e.Name()))
		if err != nil {
			continue
		}
		u, err := fs.DiskUsage("")
		fs.Close()
		if err == nil {
			list = append(list, HostAccount{Username: e.Name(), Bytes: u.Total, Partial: u.Partial})
		}
	}
	slices.SortFunc(list, func(a, b HostAccount) int {
		switch {
		case a.Bytes > b.Bytes:
			return -1
		case a.Bytes < b.Bytes:
			return 1
		}
		return strings.Compare(a.Username, b.Username)
	})
	h.mu.Lock()
	h.usage, h.usageAt, h.running = list, time.Now(), false
	h.mu.Unlock()
}

// Log returns the last lines of a service's journal (ADM-SVC-01).
func (s Services) Log(ctx context.Context, id string, lines int) (unit, text string, err error) {
	if lines < 1 || lines > 500 {
		return "", "", invalid("lines: 1 to 500")
	}
	if unit, err = s.Registry.Unit(id); err != nil {
		return "", "", err
	}
	if s.Run == nil {
		return unit, "", fmt.Errorf("no command runner: %w", ErrNotInstalled)
	}
	res, err := s.Run.Run(ctx, execxCmd(JournalctlPath, "--no-pager", "--output=short-iso", "--lines="+strconv.Itoa(lines), "--unit="+unit))
	return unit, string(res.Stdout), err
}
