package messages

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/validate"
)

// SMTP sends through the server's own Postfix on localhost, which accepts
// mail from this machine.
type SMTP struct {
	Addr string // 127.0.0.1:25
}

// Send implements Mailer.
func (m SMTP) Send(ctx context.Context, from, to, subject, body string) error {
	f, err := validate.Email(from)
	if err != nil {
		return fmt.Errorf("sender address: %w", err)
	}
	t, err := validate.Email(to)
	if err != nil {
		return fmt.Errorf("recipient address: %w", err)
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	domain := f[strings.LastIndex(f, "@")+1:]
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", f)
	h("To", t)
	h("Subject", mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "base64")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return m.deliver(ctx, f, t, b.Bytes())
}

// deliver talks to the local mail server without TLS: the connection never
// leaves this machine, and its certificate (made for the host name) would not
// match "localhost" anyway.
func (m SMTP) deliver(ctx context.Context, from, to string, msg []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", m.addr())
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m SMTP) addr() string {
	if m.Addr != "" {
		return m.Addr
	}
	return net.JoinHostPort("127.0.0.1", "25")
}
