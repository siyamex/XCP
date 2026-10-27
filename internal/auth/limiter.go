package auth

import (
	"sync"
	"time"
)

// Limiter counts failures per key (an IP or a username) in a fixed window
// and locks the key once max failures are reached. It is in memory: a
// restart clears it, and xcp-logd adds firewall bans for persistent attackers
// (ADM-SEC-01).
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*limitEntry
	max     int
	window  time.Duration
	lockFor time.Duration
	now     func() time.Time
}

type limitEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// maxLimiterEntries bounds memory under an attack from many IPs.
const maxLimiterEntries = 100_000

// NewLimiter locks a key for lockFor after max failures within window.
func NewLimiter(max int, window, lockFor time.Duration) *Limiter {
	return &Limiter{entries: map[string]*limitEntry{}, max: max, window: window, lockFor: lockFor, now: time.Now}
}

// Allowed reports whether key may try again, and if not, for how long it is locked.
func (l *Limiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	if wait := e.lockedUntil.Sub(l.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail records a failure for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok || now.Sub(e.windowStart) > l.window {
		if !ok && len(l.entries) >= maxLimiterEntries {
			l.prune(now)
		}
		e = &limitEntry{windowStart: now}
		l.entries[key] = e
	}
	e.failures++
	if e.failures >= l.max {
		e.lockedUntil = now.Add(l.lockFor)
		e.failures = 0
		e.windowStart = now
	}
}

// Reset forgets key (after a successful login).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *Limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.windowStart) > l.window && now.After(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}
