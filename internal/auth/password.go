// Package auth handles panel logins: passwords, sessions, 2FA, rate limits
// and re-authentication (07-security.md §2).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost settings.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// DefaultArgon2 meets 07-security.md §2 (memory ≥ 64 MiB).
var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 2}

const (
	saltLen = 16
	keyLen  = 32
)

var errBadHash = errors.New("auth: malformed password hash")

// Hasher hashes and verifies passwords. It limits how many hashes run at
// once, because each one uses Memory KiB of RAM: without a limit, a burst of
// login attempts could exhaust the server's memory.
type Hasher struct {
	params Argon2Params
	sem    chan struct{}
}

// NewHasher returns a hasher running at most concurrency hashes in parallel.
func NewHasher(p Argon2Params, concurrency int) *Hasher {
	return &Hasher{params: p, sem: make(chan struct{}, max(concurrency, 1))}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-format string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	key := argon2.IDKey([]byte(password), salt, h.params.Time, h.params.Memory, h.params.Threads, keyLen)
	return encodeHash(h.params, salt, key), nil
}

// Verify reports whether password matches encoded. needsRehash is true when
// the hash used other parameters than the hasher's current ones, so the
// caller can upgrade it after a successful login.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want))) //nolint:gosec // G115: decodeHash bounds len(want) to 16..64
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && p != h.params, nil
}

var b64 = base64.RawStdEncoding

func encodeHash(p Argon2Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decodeHash(s string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return p, nil, nil, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, errBadHash
	}
	// Bounds stop a corrupted or planted hash from making Verify allocate gigabytes.
	if p.Memory < 8*1024 || p.Memory > 1024*1024 || p.Time < 1 || p.Time > 16 || p.Threads < 1 {
		return p, nil, nil, errBadHash
	}
	salt, err1 := b64.DecodeString(parts[4])
	key, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, errBadHash
	}
	return p, salt, key, nil
}
