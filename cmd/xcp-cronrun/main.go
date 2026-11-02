// Command xcp-cronrun runs one cron job as the account's user (ADR-0011).
// xcp-agent starts it in a transient unit in the account's slice; it runs
// the command with /bin/sh, passes the output on, and mails the output when
// the job has an address and printed something.
//
//	xcp-cronrun [--mail-to ADDR --mail-subject S] -- COMMAND
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"
)

const (
	sendmailPath = "/usr/sbin/sendmail"
	maxMail      = 256 << 10 // output mailed at most
)

func main() {
	os.Exit(run())
}

// capped keeps the first n bytes written to it.
type capped struct {
	buf bytes.Buffer
	n   int
	cut bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	if c.buf.Len() >= c.n {
		c.cut = true
	}
	return len(p), nil
}

// header keeps a mail header value on one line of printable text.
func header(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func run() int {
	mailTo := flag.String("mail-to", "", "mail the output here when there is some")
	subject := flag.String("mail-subject", "Cron job output", "the mail's subject")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "xcp-cronrun: want exactly one command after --")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "xcp-cronrun: must not run as root: it runs as the account's user")
		return 2
	}
	mail := &capped{n: maxMail}
	out := io.MultiWriter(os.Stdout, mail)
	cmd := exec.Command("/bin/sh", "-c", flag.Arg(0)) //nolint:gosec // G204: the account's own cron command, run as the account's user
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Stdin = nil // /dev/null
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	case err != nil:
		fmt.Fprintln(out, "xcp-cronrun:", err)
		code = 127
	}
	if *mailTo != "" && mail.buf.Len() > 0 {
		body := mail.buf.Bytes()
		if mail.cut {
			body = append(body, []byte("\n[output cut]\n")...)
		}
		if err := send(*mailTo, *subject, code, body); err != nil {
			fmt.Fprintln(os.Stdout, "xcp-cronrun: mail the output:", err)
		}
	}
	return code
}

// send mails the output with sendmail as the account's user. The sender is
// the bare user name, which Postfix completes with its own domain (left
// out, Postfix would name the user after its GECOS field, the XCP marker).
func send(to, subject string, code int, body []byte) error {
	var msg bytes.Buffer
	if u, err := user.Current(); err == nil {
		fmt.Fprintf(&msg, "From: Cron <%s>\n", header(u.Username))
	}
	fmt.Fprintf(&msg, "To: %s\nSubject: %s\nDate: %s\nContent-Type: text/plain; charset=utf-8\nX-Cron-Exit-Code: %d\n\n",
		header(to), header(subject), time.Now().Format(time.RFC1123Z), code)
	msg.Write(body)
	cmd := exec.Command(sendmailPath, "-i", "--", to) //nolint:gosec // G204: fixed binary; the address was checked by the panel and the agent
	cmd.Stdin = &msg
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(b)))
	}
	return nil
}
