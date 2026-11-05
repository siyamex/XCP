// Package mailpolicy is the Postfix policy service that limits how much mail
// an account may send per hour (ADR-0028). Postfix asks it at the end of each
// message from a client that signed in (submission and smtps); it counts the
// recipients of the account and defers the message once the package's
// mail_per_hour is used up.
package mailpolicy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limiter counts recipients per key over the last hour, in one-minute steps.
type Limiter struct {
	mu   sync.Mutex
	keys map[string]*window
}

type window struct {
	minute int64 // the newest minute counted
	counts [60]int64
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter { return &Limiter{keys: map[string]*window{}} }

func (w *window) advance(minute int64) {
	if minute <= w.minute {
		return
	}
	if minute-w.minute >= 60 {
		w.counts = [60]int64{}
	} else {
		for m := w.minute + 1; m <= minute; m++ {
			w.counts[m%60] = 0
		}
	}
	w.minute = minute
}

func (w *window) total() int64 {
	var n int64
	for _, c := range w.counts {
		n += c
	}
	return n
}

// Allow adds n recipients for key at now when that keeps the last hour
// within limit, and reports how many were counted before. A limit of 0 or
// less means no limit. The message that would cross the limit is refused
// whole and not counted, so a retry later can still succeed.
func (l *Limiter) Allow(key string, n int64, limit int64, now time.Time) (ok bool, used int64) {
	if limit <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.keys) > 100000 { // a bound on memory, not a feature: start over
		l.keys = map[string]*window{}
	}
	minute := now.Unix() / 60
	w := l.keys[key]
	if w == nil {
		w = &window{minute: minute}
		l.keys[key] = w
	}
	w.advance(minute)
	used = w.total()
	if used+n > limit {
		return false, used
	}
	w.counts[minute%60] += n
	return true, used
}

// Decider tells how much an authenticated sender may send.
type Decider interface {
	// Limit returns the account's key and its recipients-per-hour limit
	// (0: none) for the login that signed in.
	Limit(ctx context.Context, saslUsername string) (key string, limit int64, err error)
}

// Server answers Postfix's policy requests.
type Server struct {
	Decider Decider
	Limiter *Limiter
	Now     func() time.Time
	Log     func(msg string, args ...any)
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err() //nolint:nilerr // the listener closed because we were asked to stop
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

// The attributes of one request, which Postfix ends with an empty line.
func readRequest(r *bufio.Reader) (map[string]string, error) {
	attrs := map[string]string{}
	for n := 0; ; n++ {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && len(attrs) == 0 {
				return nil, io.EOF
			}
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return attrs, nil
		}
		if n > 200 || len(line) > 4096 {
			return nil, errors.New("request too large")
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			attrs[k] = v
		}
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		attrs, err := readRequest(r)
		if err != nil {
			return
		}
		action := s.Decide(ctx, attrs)
		if _, err := fmt.Fprintf(c, "action=%s\n\n", action); err != nil {
			return
		}
	}
}

// Decide returns the action for one request: "dunno" lets Postfix go on,
// anything else is a reply code and text.
func (s *Server) Decide(ctx context.Context, attrs map[string]string) string {
	if attrs["protocol_state"] != "END-OF-MESSAGE" || attrs["sasl_username"] == "" {
		return "dunno"
	}
	key, limit, err := s.Decider.Limit(ctx, attrs["sasl_username"])
	if err != nil {
		if s.Log != nil {
			s.Log("look up the sending limit", "user", attrs["sasl_username"], "err", err)
		}
		return "dunno" // never stop mail because the panel database is busy
	}
	n, _ := strconv.ParseInt(attrs["recipient_count"], 10, 64)
	if n < 1 {
		n = 1
	}
	ok, used := s.Limiter.Allow(key, n, limit, s.Now())
	if ok {
		return "dunno"
	}
	if s.Log != nil {
		s.Log("sending limit reached", "user", attrs["sasl_username"], "limit", limit, "used", used, "wanted", n)
	}
	return fmt.Sprintf("450 4.7.1 The hourly sending limit of %d recipients of this account is reached: try again later", limit)
}
