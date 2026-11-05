package mailpolicy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLimiterWindow(t *testing.T) {
	l := NewLimiter()
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if ok, _ := l.Allow("a", 3, 5, t0); !ok {
		t.Fatal("3 of 5")
	}
	if ok, used := l.Allow("a", 3, 5, t0.Add(time.Minute)); ok || used != 3 {
		t.Errorf("3 more over 5: ok=%v used=%d", ok, used)
	}
	// A refused message is not counted, so a smaller one still fits.
	if ok, _ := l.Allow("a", 2, 5, t0.Add(2*time.Minute)); !ok {
		t.Error("2 more fit")
	}
	if ok, _ := l.Allow("a", 1, 5, t0.Add(3*time.Minute)); ok {
		t.Error("the sixth recipient fits")
	}
	// Another account is separate; no limit means no counting.
	if ok, _ := l.Allow("b", 100, 5, t0); ok {
		t.Error("100 recipients over 5")
	}
	if ok, _ := l.Allow("c", 1000, 0, t0); !ok {
		t.Error("no limit")
	}
	// The hour slides: after 62 minutes everything has aged out.
	if ok, used := l.Allow("a", 5, 5, t0.Add(62*time.Minute)); !ok || used != 0 {
		t.Errorf("after the hour: ok=%v used=%d", ok, used)
	}
	// Counts leave one minute at a time.
	l2 := NewLimiter()
	l2.Allow("x", 2, 4, t0)
	l2.Allow("x", 2, 4, t0.Add(30*time.Minute))
	if ok, _ := l2.Allow("x", 1, 4, t0.Add(59*time.Minute)); ok {
		t.Error("full at 59 minutes")
	}
	if ok, _ := l2.Allow("x", 2, 4, t0.Add(61*time.Minute)); !ok {
		t.Error("the first two left at 61 minutes")
	}
}

type fixed struct {
	limit int64
	err   error
}

func (f fixed) Limit(_ context.Context, login string) (string, int64, error) {
	return "account:" + login, f.limit, f.err
}

func TestDecide(t *testing.T) {
	s := &Server{Decider: fixed{limit: 3}, Limiter: NewLimiter(), Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	ctx := context.Background()
	eom := func(user, rcpts string) map[string]string {
		return map[string]string{"protocol_state": "END-OF-MESSAGE", "sasl_username": user, "recipient_count": rcpts}
	}
	if a := s.Decide(ctx, map[string]string{"protocol_state": "RCPT", "sasl_username": "a@x.example"}); a != "dunno" {
		t.Errorf("another stage: %s", a)
	}
	if a := s.Decide(ctx, eom("", "50")); a != "dunno" {
		t.Errorf("not signed in (inbound mail is not limited): %s", a)
	}
	if a := s.Decide(ctx, eom("a@x.example", "2")); a != "dunno" {
		t.Errorf("2 of 3: %s", a)
	}
	if a := s.Decide(ctx, eom("a@x.example", "2")); !strings.HasPrefix(a, "450 4.7.1 ") || !strings.Contains(a, "3 recipients") {
		t.Errorf("2 more over 3: %s", a)
	}
	if a := s.Decide(ctx, eom("a@x.example", "1")); a != "dunno" {
		t.Errorf("the last one: %s", a)
	}
	if a := s.Decide(ctx, eom("a@x.example", "")); !strings.HasPrefix(a, "450") {
		t.Errorf("a message with no count counts as one: %s", a)
	}
	// When the lookup fails, mail flows.
	s.Decider = fixed{err: errors.New("database is locked")}
	if a := s.Decide(ctx, eom("b@x.example", "9")); a != "dunno" {
		t.Errorf("lookup failure: %s", a)
	}
}

func TestPolicyProtocol(t *testing.T) {
	s := &Server{Decider: fixed{limit: 1}, Limiter: NewLimiter(), Now: time.Now}
	l, err := net.Listen("unix", t.TempDir()+"/p.sock")
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, l)
	c, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	ask := func(attrs string) string {
		if _, err := c.Write([]byte(attrs + "\n\n")); err != nil {
			t.Fatal(err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if blank, _ := r.ReadString('\n'); blank != "\n" {
			t.Fatalf("reply not ended by an empty line: %q", blank)
		}
		return strings.TrimSpace(reply)
	}
	req := "request=smtpd_access_policy\nprotocol_state=END-OF-MESSAGE\nsasl_username=a@x.example\nrecipient_count=1"
	if a := ask(req); a != "action=dunno" {
		t.Errorf("first: %s", a)
	}
	// The same connection serves the next request, as Postfix expects.
	if a := ask(req); !strings.HasPrefix(a, "action=450 4.7.1 ") {
		t.Errorf("second: %s", a)
	}
	// Attribute lines that are not name=value are ignored.
	if a := ask("garbage\nprotocol_state=RCPT"); a != "action=dunno" {
		t.Errorf("garbage: %s", a)
	}
}
