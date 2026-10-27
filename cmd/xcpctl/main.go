// Command xcpctl is the XCP admin command line.
//
// Local commands run on the server and use the config and database directly
// (as root they first switch to the service user):
//
//	xcpctl admin create --username NAME [--email X] [--must-change]
//	xcpctl doctor
//
// Remote commands use the REST API, like the web UI:
//
//	xcpctl login [--server URL] [--username NAME] [--ca-file FILE | --insecure]
//	xcpctl me
//	xcpctl sessions list
//	xcpctl sessions revoke ID
//	xcpctl logout
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/siyamex/XCP/internal/app"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/config"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/version"
)

const usage = `xcpctl - XCP admin command line

Local (on the server):
  admin create --username NAME [--email X] [--must-change]   create an admin login
  doctor                                                     check this installation

Remote (REST API):
  login [--server URL] [--username NAME] [--ca-file F | --insecure]
  me                     show the logged-in identity
  sessions list          list your sessions
  sessions revoke ID     end one session
  logout

  version                print the version

Local commands accept --config FILE (default /etc/xcp/xcp.toml).
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "xcpctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintln(out, version.Version)
		return nil
	case "admin":
		if len(rest) == 0 || rest[0] != "create" {
			return errors.New("usage: xcpctl admin create --username NAME")
		}
		return adminCreate(rest[1:], stdin, out)
	case "doctor":
		return doctor(rest, out)
	case "login":
		return login(rest, stdin, out)
	case "logout":
		return logout(out)
	case "me":
		return me(out)
	case "sessions":
		return sessions(rest, out)
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (run xcpctl help)", cmd)
}

// openLocal opens the config and database as the service user.
func openLocal(configPath string) (*app.App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	// Drop root before touching the database, so new files (WAL, journal)
	// belong to the user xcp-api runs as.
	if err := app.DropPrivileges(cfg.Agent.APIUser); err != nil {
		return nil, err
	}
	return app.Open(context.Background(), configPath)
}

func adminCreate(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to xcp.toml")
	username := fs.String("username", "", "login name for the new admin")
	email := fs.String("email", "", "contact email (optional)")
	mustChange := fs.Bool("must-change", false, "require a password change at first login")
	ifNone := fs.Bool("if-none", false, "do nothing if any login exists already (used by the installer)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("--username is required")
	}
	password, err := newInput(stdin).secret("Password: ", true)
	if err != nil {
		return err
	}
	a, err := openLocal(*configPath)
	if err != nil {
		return err
	}
	defer a.Close()
	if *ifNone {
		n, err := a.DB.CountLogins(context.Background())
		if err != nil {
			return err
		}
		if n > 0 {
			fmt.Fprintf(out, "skipped: %d login(s) already exist\n", n)
			return nil
		}
	}
	l, err := a.Auth.CreateLogin(context.Background(), auth.Client{UserAgent: "xcpctl admin create"}, nil, auth.NewLogin{
		Username: *username, Password: password, Role: store.RoleAdmin, Email: *email, MustChangePassword: *mustChange,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "created admin login %q (id %s)\n", l.Username, l.ID)
	return nil
}

// input reads prompts from a terminal (secrets without echo) or, when stdin
// is piped (scripts, installer), one line per value from a single buffer so
// no line is lost between prompts.
type input struct {
	r   *bufio.Reader
	tty bool
	fd  int
}

func newInput(stdin io.Reader) *input {
	in := &input{r: bufio.NewReader(stdin)}
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // fd fits in int
		in.tty, in.fd = true, int(f.Fd()) //nolint:gosec // fd fits in int
	}
	return in
}

// line prompts for a visible value (username, 2FA code).
func (in *input) line(prompt string) (string, error) {
	if in.tty {
		fmt.Fprint(os.Stderr, prompt)
	}
	l, err := in.r.ReadString('\n')
	if err != nil && l == "" {
		return "", fmt.Errorf("read %s: %w", strings.TrimSuffix(strings.ToLower(prompt), ": "), err)
	}
	return strings.TrimSpace(l), nil
}

// secret reads a value without echo on a terminal, asking twice when confirm is set.
func (in *input) secret(prompt string, confirm bool) (string, error) {
	if !in.tty {
		l, err := in.r.ReadString('\n')
		if err != nil && l == "" {
			return "", fmt.Errorf("read %s from stdin: %w", strings.TrimSuffix(strings.ToLower(prompt), ": "), err)
		}
		return strings.TrimRight(l, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	s1, err := term.ReadPassword(in.fd)
	fmt.Fprintln(os.Stderr)
	if err != nil || !confirm {
		return string(s1), err
	}
	fmt.Fprint(os.Stderr, "Repeat "+strings.ToLower(prompt))
	s2, err := term.ReadPassword(in.fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(s1) != string(s2) {
		return "", errors.New("the two entries do not match")
	}
	return string(s1), nil
}
