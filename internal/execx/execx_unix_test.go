//go:build unix

package execx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const sh = "/bin/sh"

func runner(t *testing.T) *Runner {
	t.Helper()
	r, err := NewRunner(sh)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunCapturesOutputAndUsesArgvNotShellParsing(t *testing.T) {
	// The argument contains shell metacharacters; it must arrive as one literal argv entry.
	arg := "a; touch /tmp/pwned $(id)"
	res, err := runner(t).Run(context.Background(), Cmd{Path: sh, Args: []string{"-c", `printf '%s' "$1"`, "x", arg}})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != arg {
		t.Fatalf("stdout = %q, want %q", res.Stdout, arg)
	}
}

func TestRunDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("XCP_SECRET_TEST", "leak")
	res, err := runner(t).Run(context.Background(), Cmd{Path: sh, Args: []string{"-c", "env"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), "XCP_SECRET_TEST") {
		t.Fatal("parent environment leaked into child")
	}
}

func TestRunNonZeroExit(t *testing.T) {
	res, err := runner(t).Run(context.Background(), Cmd{Path: sh, Args: []string{"-c", "echo boom >&2; exit 3"}})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.ExitCode != 3 || ee.Stderr != "boom" || res.ExitCode != 3 {
		t.Fatalf("err = %#v res = %+v", err, res)
	}
}

func TestRunTimeoutKillsProcessTree(t *testing.T) {
	start := time.Now()
	_, err := runner(t).Run(context.Background(), Cmd{
		Path:    sh,
		Args:    []string{"-c", "sleep 30 & sleep 30"},
		Timeout: 200 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout did not kill the process group promptly")
	}
}

func TestRunTruncatesLargeOutput(t *testing.T) {
	res, err := runner(t).Run(context.Background(), Cmd{
		Path:      sh,
		Args:      []string{"-c", "yes | head -c 100000"},
		MaxOutput: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 1000 || !res.Truncated {
		t.Fatalf("len = %d truncated = %v", len(res.Stdout), res.Truncated)
	}
}
