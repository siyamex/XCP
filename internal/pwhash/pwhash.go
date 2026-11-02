// Package pwhash makes and checks the {ARGON2ID} password hashes that
// mailboxes (Dovecot, ADR-0007) and FTP logins (xcp-ftpauth, ADR-0010)
// use: libsodium's format at its "interactive" cost.
package pwhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"golang.org/x/crypto/argon2"
)

var idKey = argon2.IDKey

// Prefix starts every hash.
const Prefix = "{ARGON2ID}"

// The cost of new hashes: 2 passes over 64 MiB, one thread.
const (
	time    = 2
	memory  = 64 * 1024 // KiB
	threads = 1
	keyLen  = 32
)

// Hash limits for checking: a hash with a higher cost is refused instead of
// letting a bad file make every login allocate gigabytes.
const (
	maxTime   = 10
	maxMemory = 256 * 1024
)

var hashRe = regexp.MustCompile(`^\{ARGON2ID\}\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$`)

// Hash returns a new hash of password.
func Hash(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // never fails (crypto/rand)
	key := idKey([]byte(password), salt, time, memory, threads, keyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf(Prefix+"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// Valid reports whether h is a hash this package can check.
func Valid(h string) bool {
	_, err := parse(h)
	return err == nil
}

type params struct {
	m, t      uint32
	p         uint8
	salt, key []byte
}

func parse(h string) (params, error) {
	sm := hashRe.FindStringSubmatch(h)
	if sm == nil {
		return params{}, fmt.Errorf("not an %s hash", Prefix)
	}
	m, err1 := strconv.ParseUint(sm[1], 10, 32)
	t, err2 := strconv.ParseUint(sm[2], 10, 32)
	p, err3 := strconv.ParseUint(sm[3], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil || m < 8 || m > maxMemory || t < 1 || t > maxTime || p < 1 || p > 16 {
		return params{}, fmt.Errorf("%s hash with unusable cost m=%s t=%s p=%s", Prefix, sm[1], sm[2], sm[3])
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(sm[4])
	key, err2 := enc.DecodeString(sm[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return params{}, fmt.Errorf("%s hash with a bad salt or key", Prefix)
	}
	return params{m: uint32(m), t: uint32(t), p: uint8(p), salt: salt, key: key}, nil
}

// Check reports whether password matches hash h. A malformed hash never matches.
func Check(h, password string) bool {
	pr, err := parse(h)
	if err != nil {
		return false
	}
	got := idKey([]byte(password), pr.salt, pr.t, pr.m, pr.p, uint32(len(pr.key))) //nolint:gosec // G115: at most 64
	return subtle.ConstantTimeCompare(got, pr.key) == 1
}

// Dummy returns a valid hash of a random password, for spending the same
// time on unknown logins as on known ones. It is made on first use.
var Dummy = sync.OnceValue(func() string { return Hash(rand.Text()) })
