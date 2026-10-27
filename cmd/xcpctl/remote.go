package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// state is the saved login. The session token is a credential: the file is
// written 0600 in the user's own config directory.
type state struct {
	Server     string `json:"server"`
	CookieName string `json:"cookie_name"`
	Token      string `json:"token"`
	CSRF       string `json:"csrf"`
	CAFile     string `json:"ca_file,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

// stateDir can be overridden in tests.
var stateDir = func() (string, error) {
	d, err := os.UserConfigDir()
	return filepath.Join(d, "xcp"), err
}

func statePath() (string, error) {
	d, err := stateDir()
	return filepath.Join(d, "xcpctl.json"), err
}

func loadState() (*state, error) {
	p, err := statePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // our own state file
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("not logged in (run xcpctl login)")
	}
	if err != nil {
		return nil, err
	}
	var s state
	return &s, json.Unmarshal(b, &s)
}

func saveState(s *state) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //nolint:forbidigo // xcpctl's own state, not user content
		return err
	}
	return os.Rename(tmp, p)
}

type client struct {
	s    *state
	http *http.Client
}

func newClient(s *state) (*client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.Insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // explicit --insecure, warned at login
	} else if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no PEM certificate", s.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &client{s: s, http: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
		// Never follow redirects with credentials attached.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// apiError is a problem+json response.
type apiError struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Errors []struct {
		Field, Message string
	} `json:"errors"`
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("%s (%s)", e.Detail, e.Code)
	for _, f := range e.Errors {
		msg += fmt.Sprintf("\n  %s: %s", f.Field, f.Message)
	}
	return msg
}

func (c *client) do(method, path string, body, out any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.s.Server, "/")+"/api/v1"+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "xcpctl")
	if c.s.Token != "" {
		req.AddCookie(&http.Cookie{Name: c.s.CookieName, Value: c.s.Token})
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", c.s.CSRF)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		ae := &apiError{Status: resp.StatusCode, Code: "http_error", Detail: resp.Status}
		_ = json.NewDecoder(resp.Body).Decode(ae)
		return resp, ae
	}
	if out != nil {
		return resp, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp, nil
}

func login(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	server := fs.String("server", "https://127.0.0.1:2443", "panel URL")
	username := fs.String("username", "", "login name (prompted if empty)")
	caFile := fs.String("ca-file", "", "trust this certificate (default: /etc/xcp/ssl/panel.crt when it exists)")
	insecure := fs.Bool("insecure", false, "skip TLS certificate checks (unsafe)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s := &state{Server: *server, CAFile: *caFile, Insecure: *insecure}
	if s.CAFile == "" && strings.HasPrefix(s.Server, "https://") {
		if _, err := os.Stat("/etc/xcp/ssl/panel.crt"); err == nil {
			s.CAFile = "/etc/xcp/ssl/panel.crt"
		}
	}
	if s.Insecure {
		fmt.Fprintln(os.Stderr, "warning: --insecure disables TLS certificate checks")
	}
	in := newInput(stdin)
	if *username == "" {
		u, err := in.line("Username: ")
		if err != nil {
			return err
		}
		*username = u
	}
	password, err := in.secret("Password: ", false)
	if err != nil {
		return err
	}
	c, err := newClient(s)
	if err != nil {
		return err
	}
	var res struct {
		MFARequired        bool   `json:"mfa_required"`
		MustChangePassword bool   `json:"must_change_password"`
		CSRFToken          string `json:"csrf_token"`
	}
	resp, err := c.do("POST", "/auth/login", map[string]string{"username": *username, "password": password}, &res)
	if err != nil {
		return err
	}
	for _, ck := range resp.Cookies() {
		if strings.HasSuffix(ck.Name, "xcp_session") && ck.Value != "" {
			s.CookieName, s.Token = ck.Name, ck.Value
		}
	}
	if s.Token == "" {
		return errors.New("server did not set a session cookie")
	}
	s.CSRF = res.CSRFToken
	if res.MFARequired {
		code, err := in.line("2FA code (or recovery code): ")
		if err != nil {
			return err
		}
		if _, err := c.do("POST", "/auth/2fa/verify", map[string]string{"code": code}, nil); err != nil {
			return err
		}
	}
	if err := saveState(s); err != nil {
		return err
	}
	fmt.Fprintf(out, "logged in to %s as %s\n", s.Server, *username)
	if res.MustChangePassword {
		fmt.Fprintln(out, "note: you must change your password in the web UI before doing anything else")
	}
	return nil
}

func remoteClient() (*client, error) {
	s, err := loadState()
	if err != nil {
		return nil, err
	}
	return newClient(s)
}

func me(out io.Writer) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	var m struct {
		ID, Username, Role, Email string
		TOTPEnabled               bool `json:"totp_enabled"`
	}
	if _, err := c.do("GET", "/me", nil, &m); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "server\t%s\nusername\t%s\nrole\t%s\nemail\t%s\n2fa\t%v\nid\t%s\n", c.s.Server, m.Username, m.Role, m.Email, m.TOTPEnabled, m.ID)
	return tw.Flush()
}

func sessions(args []string, out io.Writer) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	switch {
	case len(args) == 1 && args[0] == "list":
		var list struct {
			Items []struct {
				ID         string    `json:"id"`
				IP         string    `json:"ip"`
				UserAgent  string    `json:"user_agent"`
				LastSeenAt time.Time `json:"last_seen_at"`
				Current    bool      `json:"current"`
			} `json:"items"`
		}
		if _, err := c.do("GET", "/me/sessions", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tIP\tLAST ACTIVE\tCLIENT")
		for _, s := range list.Items {
			ua := s.UserAgent
			if len(ua) > 40 {
				ua = ua[:40] + "..."
			}
			if s.Current {
				ua += " (this)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.ID, s.IP, s.LastSeenAt.Local().Format(time.DateTime), ua)
		}
		return tw.Flush()
	case len(args) == 2 && args[0] == "revoke":
		if _, err := c.do("DELETE", "/me/sessions/"+args[1], nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(out, "session ended")
		return nil
	}
	return errors.New("usage: xcpctl sessions list | xcpctl sessions revoke ID")
}

func logout(out io.Writer) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	_, apiErr := c.do("POST", "/auth/logout", nil, nil)
	p, err := statePath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if apiErr != nil {
		fmt.Fprintln(out, "local session removed (server said:", apiErr.Error()+")")
		return nil
	}
	fmt.Fprintln(out, "logged out")
	return nil
}
