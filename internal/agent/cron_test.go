package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestDue(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		schedule, at string
		due          bool
	}{
		{"* * * * *", "2026-11-02 10:07", true},
		{"*/15 * * * *", "2026-11-02 10:15", true},
		{"*/15 * * * *", "2026-11-02 10:16", false},
		{"30 3 * * *", "2026-11-02 03:30", true},
		{"30 3 * * *", "2026-11-02 04:30", false},
		{"0 0 1 * *", "2026-12-01 00:00", true},
		{"0 9 * * 1-5", "2026-11-07 09:00", false}, // a Saturday
		{"0 9 * * 1-5", "2026-11-09 09:00", true},  // a Monday
		{"@daily", "2026-11-02 00:00", true},
		{"bad", "2026-11-02 00:00", false},
	} {
		if got := Due(c.schedule, at(c.at)); got != c.due {
			t.Errorf("Due(%q, %s) = %v", c.schedule, c.at, got)
		}
	}
	next := Next("0 */6 * * *", at("2026-11-02 10:07"), 3)
	if len(next) != 3 || !next[0].Equal(at("2026-11-02 12:00")) || !next[2].Equal(at("2026-11-03 00:00")) {
		t.Errorf("Next = %v", next)
	}
}

func TestCheckCronAccount(t *testing.T) {
	ok := CronAccount{Username: "alice", Jobs: []CronJob{
		{ID: "01abc", Schedule: "*/5 * * * *", Command: "php cron.php"},
		{ID: "01abd", Schedule: "0 3 * * *", Command: "echo 100% done", MailTo: "ops@alice.example"},
	}}
	if err := CheckCronAccount(ok); err != nil {
		t.Fatal(err)
	}
	for name, j := range map[string]CronJob{
		"upper-case id":  {ID: "01ABC", Schedule: "* * * * *", Command: "true"},
		"id with a dash": {ID: "a-b", Schedule: "* * * * *", Command: "true"},
		"bad schedule":   {ID: "a", Schedule: "* * *", Command: "true"},
		"unclean":        {ID: "a", Schedule: "*  * * * *", Command: "true"},
		"reboot":         {ID: "a", Schedule: "@reboot", Command: "true"},
		"two lines":      {ID: "a", Schedule: "* * * * *", Command: "true\nrm -rf ~"},
		"empty command":  {ID: "a", Schedule: "* * * * *", Command: ""},
		"bad mail":       {ID: "a", Schedule: "* * * * *", Command: "true", MailTo: "x"},
		"header in mail": {ID: "a", Schedule: "* * * * *", Command: "true", MailTo: "a@b.example\nBcc: c@d.example"},
		"padded command": {ID: "a", Schedule: "* * * * *", Command: " true"},
	} {
		if err := CheckCronAccount(CronAccount{Username: "alice", Jobs: []CronJob{j}}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	twice := CronAccount{Username: "alice", Jobs: []CronJob{ok.Jobs[0], ok.Jobs[0]}}
	if err := CheckCronAccount(twice); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("an id twice: %v", err)
	}
}

func TestCronRunsAreRecorded(t *testing.T) {
	c := &Cron{StateDir: t.TempDir(), FragmentDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	start := time.Date(2026, 11, 2, 10, 7, 0, 0, time.UTC)
	c.record("alice", "a", CronRun{Start: start, Duration: 2 * time.Second, ExitCode: 3, Output: "boom"})
	c.record("alice", "b", CronRun{Start: start, Skipped: "the previous run is still going"})
	runs, err := c.Status(context.Background(), "alice")
	if err != nil || len(runs) != 2 || runs["a"].ExitCode != 3 || runs["a"].Output != "boom" || runs["b"].Skipped == "" {
		t.Fatalf("%+v %v", runs, err)
	}
	if _, err := c.RemoveAccount(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if runs, _ := c.Status(context.Background(), "alice"); len(runs) != 0 {
		t.Errorf("runs left after removal: %+v", runs)
	}
	if got := tail(strings.Repeat("x", 10)+"end", 3); got != "end" {
		t.Errorf("tail = %q", got)
	}
}
