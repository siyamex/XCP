// Package ids creates ULIDs: 26-character, time-sortable, URL-safe IDs
// used for every API-visible object (02-tech-stack-and-repo.md §4).
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Crockford base32 alphabet (no I, L, O, U).
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a ULID for the current time.
func New() string { return At(time.Now()) }

// At returns a ULID with the given timestamp (millisecond precision) and
// 80 random bits.
func At(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	// 48-bit timestamp split into 16 + 32 bits: the truncations are intended.
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32)) //nolint:gosec // G115: intended
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))     //nolint:gosec // G115: intended
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ids: crypto/rand failed: " + err.Error()) // never happens on supported OSes
	}
	return encode(b)
}

func encode(b [16]byte) string {
	// 128 bits -> 26 base32 chars; the first char carries only 3 bits.
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = alphabet[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// Valid reports whether s looks like a ULID produced by this package.
func Valid(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		digit, upper := c >= '0' && c <= '9', c >= 'A' && c <= 'Z'
		if !digit && !upper || c == 'I' || c == 'L' || c == 'O' || c == 'U' {
			return false
		}
	}
	return true
}
