package agent

import "testing"

func TestParseFTPWho(t *testing.T) {
	out := []byte("4321|deploy@alice.example|12|IDLE|-|203.0.113.5|192.0.2.1|21|0|0|0|0\n" +
		"4400|amy@bob.example|3|DL|big.zip|203.0.113.6|192.0.2.1|21|1024|4096|25|512\n" +
		"garbage line\n" +
		"x|bad|pid|IDLE|-|a|b|21|0|0|0|0\n" +
		"1|init|1|IDLE|-|a|b|21|0|0|0|0\n")
	l := ParseFTPWho(out)
	if len(l) != 2 || l[0].PID != 4321 || l[0].Login != "deploy@alice.example" || l[0].Seconds != 12 || l[1].File != "big.zip" || l[1].Percent != 25 || l[1].BytesSec != 512 {
		t.Errorf("%+v", l)
	}
}

func TestFTPKillNeedsAListing(t *testing.T) {
	var killed []int
	f := &FTP{kill: func(pid int) error { killed = append(killed, pid); return nil }}
	if _, err := f.Kill(t.Context(), 4321, "x@y.example"); err == nil {
		t.Error("kill without a way to list sessions")
	}
	if len(killed) != 0 {
		t.Errorf("killed %v", killed)
	}
}
