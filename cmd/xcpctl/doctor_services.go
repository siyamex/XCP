package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/config"
)

// serviceChecks are the hosting services and how to test that each one
// answers, beyond systemd's view (12. Monitoring in 06-service-drivers.md).
var serviceChecks = []struct {
	id, name string
	probe    func(ctx context.Context) error
}{
	{"web", "web server (Apache)", probeHTTP("https://127.0.0.1/phpmyadmin/xcp-signon.php", "phpMyAdmin")},
	{"dns", "DNS server (PowerDNS)", probeDNS},
	{"db", "database server (MariaDB)", nil},
	{"mta", "mail: SMTP (Postfix)", probeBanner("127.0.0.1:25", "220 ")},
	{"imap", "mail: IMAP (Dovecot)", probeIMAP},
	{"spam", "mail: filter and DKIM (Rspamd)", probeTCP("127.0.0.1:11332")},
	{"ftp", "FTP server (Pure-FTPd)", probeBanner("127.0.0.1:21", "220")},
}

// checkServices asks the agent about each hosting service, then tests the
// running ones. A service that is not installed is a warning: xcp-install
// can leave parts out.
func checkServices(cfg config.Agent) []checkResult {
	if cfg.Fake {
		return nil
	}
	c, closer, err := agentrpc.Dial(cfg.Socket)
	if err != nil {
		return []checkResult{{"services", statusFail, err.Error()}}
	}
	defer closer.Close()
	var out []checkResult
	for _, s := range serviceChecks {
		ctx, cancel := context.WithTimeout(context.Background(), probeWait+5*time.Second)
		out = append(out, checkService(ctx, c, s.id, s.name, s.probe))
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return append(out, checkMySQL(ctx, c), checkWebmail(ctx))
}

func checkService(ctx context.Context, c agentrpc.Client, id, name string, probe func(context.Context) error) checkResult {
	st, err := c.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: id})
	switch {
	case status.Code(err) == codes.NotFound:
		return checkResult{name, statusWarn, "not installed"}
	case err != nil:
		return checkResult{name, statusFail, err.Error()}
	case st.GetActiveState() != "active":
		return checkResult{name, statusFail, fmt.Sprintf("%s is %s (%s); see: journalctl -u %s", st.GetUnit(), st.GetActiveState(), st.GetSubState(), st.GetUnit())}
	}
	if probe != nil {
		if err := retry(ctx, probe); err != nil {
			return checkResult{name, statusFail, fmt.Sprintf("%s runs but does not answer: %v", st.GetUnit(), err)}
		}
	}
	return checkResult{name, statusOK, st.GetUnit() + " active"}
}

// probeWait is how long a service that systemd calls active may take to
// answer: right after a (re)start, as when the installer has just run,
// it may not listen yet.
const probeWait = 20 * time.Second

// retry runs probe until it succeeds or probeWait has passed.
func retry(ctx context.Context, probe func(context.Context) error) error {
	deadline := time.Now().Add(probeWait)
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := probe(pctx)
		cancel()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Second):
		}
	}
}

// checkMySQL checks that the agent can work in MariaDB (root over the socket).
func checkMySQL(ctx context.Context, c agentrpc.Client) checkResult {
	st, err := c.MySQLStatus(ctx, &agentv1.MySQLStatusRequest{})
	switch {
	case status.Code(err) == codes.NotFound:
		return checkResult{"databases", statusWarn, "MariaDB not installed"}
	case err != nil:
		return checkResult{"databases", statusFail, "xcp-agent cannot work in MariaDB: " + status.Convert(err).Message()}
	case st.GetPhpmyadmin() == "":
		return checkResult{"databases", statusWarn, "MariaDB " + st.GetVersion() + "; phpMyAdmin not installed"}
	}
	return checkResult{"databases", statusOK, "MariaDB " + st.GetVersion() + ", phpMyAdmin " + st.GetPhpmyadmin()}
}

func checkWebmail(ctx context.Context) checkResult {
	if err := probeHTTP("https://127.0.0.1/webmail/", "Roundcube")(ctx); err != nil {
		return checkResult{"webmail", statusWarn, "not answering at /webmail/: " + err.Error()}
	}
	return checkResult{"webmail", statusOK, "Roundcube at /webmail/"}
}

// insecureLocal is for probes of this server's own services over
// 127.0.0.1, whose certificates are for its host name.
var insecureLocal = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: a local liveness probe, nothing is sent

func probeHTTP(url, want string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: insecureLocal}}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s answered %s (is %s installed?)", url, resp.Status, want)
		}
		return nil
	}
}

func probeTCP(addr string) func(context.Context) error {
	return func(ctx context.Context) error {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}

// probeBanner reads a server's greeting and checks how it starts.
func probeBanner(addr, prefix string) func(context.Context) error {
	return func(ctx context.Context) error {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, prefix) {
			return fmt.Errorf("unexpected greeting %q", strings.TrimSpace(line))
		}
		return nil
	}
}

// probeIMAP checks Dovecot's IMAPS greeting (TLS on 993).
func probeIMAP(ctx context.Context) error {
	conn, err := (&tls.Dialer{Config: insecureLocal}).DialContext(ctx, "tcp", "127.0.0.1:993")
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "* OK") {
		return fmt.Errorf("unexpected greeting %q", strings.TrimSpace(line))
	}
	return nil
}

// probeDNS asks PowerDNS for a name it is not authoritative for: any
// answer (REFUSED included) shows it serves queries.
func probeDNS(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion("xcp-doctor.invalid.", dns.TypeSOA)
	c := &dns.Client{Timeout: 3 * time.Second}
	_, _, err := c.ExchangeContext(ctx, m, "127.0.0.1:53")
	return err
}
