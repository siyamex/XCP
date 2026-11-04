package agent

import (
	"strings"
	"testing"
)

func TestHostParsers(t *testing.T) {
	idle, total := cpuTimes([]byte("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 1 1 1 1\n"))
	if idle != 850 || total != 1000 {
		t.Errorf("cpuTimes = %d, %d", idle, total)
	}
	m := parseMeminfo([]byte("MemTotal:       8000 kB\nMemAvailable:   6000 kB\nSwapTotal:      0 kB\nHugePages_Total:   0\n"))
	if m["MemTotal"] != 8000*1024 || m["MemAvailable"] != 6000*1024 || m["HugePages_Total"] != 0 {
		t.Errorf("meminfo %v", m)
	}
	if l := parseLoadavg([]byte("0.52 0.40 0.30 1/200 1234\n")); l != [3]float64{0.52, 0.40, 0.30} {
		t.Errorf("load %v", l)
	}
	if got := osName([]byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n")); got != "Ubuntu 24.04.5 LTS" {
		t.Errorf("os %q", got)
	}
	net := parseNetDev([]byte("Inter-|   Receive\n face |bytes\n    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"))
	if len(net) != 1 || net[0].Name != "eth0" || net[0].RxBytes != 1000 || net[0].TxBytes != 2000 {
		t.Errorf("net %+v", net)
	}
	mounts := parseMounts([]byte("proc /proc proc rw 0 0\n/dev/sda1 / ext4 rw 0 0\n/dev/sda1 /etc/hosts ext4 rw 0 0\n/dev/loop3 /snap/x squashfs ro 0 0\n/dev/sdb1 /data xfs rw 0 0\ntmpfs /run tmpfs rw 0 0\n"))
	if len(mounts) != 2 || mounts[0].Mount != "/" || mounts[1].Device != "/dev/sdb1" {
		t.Errorf("mounts %+v", mounts)
	}
}

func TestParseDpkg(t *testing.T) {
	status := "Package: apache2\nStatus: install ok installed\nVersion: 2.4.58-1ubuntu8\n\nPackage: postfix\nStatus: deinstall ok config-files\nVersion: 3.8\n\n" +
		"Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.5\n\nPackage: unrelated\nStatus: install ok installed\nVersion: 1\n\nPackage: rspamd\nStatus: install ok installed\nVersion: 3.8.4"
	got := parseDpkg(strings.NewReader(status), wantPackage)
	if len(got) != 3 || got["apache2"] != "2.4.58-1ubuntu8" || got["php8.3-fpm"] != "8.3.6-0ubuntu0.24.04.5" || got["rspamd"] != "3.8.4" {
		t.Errorf("versions %v (removed or unrelated packages must not show; the last record has no blank line after it)", got)
	}
}

func TestParseProcStat(t *testing.T) {
	// A name with spaces and parentheses; utime 7, stime 3, rss 25 pages.
	line := "1234 (my (odd) app) S 1 1234 1234 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 100 5000000 25 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	s, ok := parseProcStat([]byte(line))
	if !ok || s.name != "my (odd) app" || s.ticks != 10 || s.rss != 25*4096 {
		t.Errorf("%+v %v", s, ok)
	}
	if _, ok := parseProcStat([]byte("garbage")); ok {
		t.Error("garbage parsed")
	}
}

func TestOnlyARootOverlayIsADisk(t *testing.T) {
	m := parseMounts([]byte("overlay / overlay rw 0 0\nnone /usr/lib/wsl/lib overlay ro 0 0\nnone /mnt/wslg/doc overlay ro 0 0\n/dev/sdc /etc/hosts ext4 rw 0 0\n"))
	if len(m) != 2 || m[0].Mount != "/" || m[1].Device != "/dev/sdc" {
		t.Errorf("mounts %+v", m)
	}
}
