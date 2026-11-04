package messages

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

// tinySMTP accepts one message and returns what it was sent.
func tinySMTP(t *testing.T) (addr string, got func() string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	done := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		w("220 test ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- data.String()
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case inData && line == ".":
				inData = false
				w("250 queued")
			case inData:
				data.WriteString(line + "\n")
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				w("250 test") // no STARTTLS offered
			case strings.HasPrefix(line, "DATA"):
				inData = true
				w("354 go ahead")
			case strings.HasPrefix(line, "QUIT"):
				w("221 bye")
				done <- data.String()
				return
			default:
				w("250 ok")
			}
		}
	}()
	return l.Addr().String(), func() string { return <-done }
}

func TestSMTPSend(t *testing.T) {
	addr, got := tinySMTP(t)
	err := SMTP{Addr: addr}.Send(ctx, "hosting@host.example", "alice@customer.example", "Hello\r\nBcc: evil@example.test", "Line one\nLine two with ünïcode\n")
	if err != nil {
		t.Fatal(err)
	}
	msg := got()
	head, body, _ := strings.Cut(msg, "\n\n")
	for _, want := range []string{"From: hosting@host.example", "To: alice@customer.example", "Content-Transfer-Encoding: base64", "MIME-Version: 1.0", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(head, want) {
			t.Errorf("headers lack %q:\n%s", want, head)
		}
	}
	// A line break in the subject must not start a new header.
	if strings.Contains(head, "\nBcc:") || strings.Contains(strings.ToLower(head), "\nbcc") {
		t.Errorf("header injection:\n%s", head)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(body), "\n", ""))
	if err != nil || string(dec) != "Line one\nLine two with ünïcode\n" {
		t.Errorf("body %q: %v", dec, err)
	}
}

func TestSMTPRefusesBadAddresses(t *testing.T) {
	addr, _ := tinySMTP(t)
	m := SMTP{Addr: addr}
	for _, c := range [][2]string{{"not an address", "a@b.example"}, {"a@b.example", "x y@z.example"}, {"a@b.example", "a@b.example\nRCPT TO:<evil@x.example>"}} {
		if err := m.Send(ctx, c[0], c[1], "s", "b"); err == nil {
			t.Errorf("%q -> %q accepted", c[0], c[1])
		}
	}
}
