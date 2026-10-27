package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP settings understood by all common authenticator apps.
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept codes from one step before or after (clock drift)
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() []byte {
	s := make([]byte, 20) // 160 bits, as RFC 4226 recommends
	if _, err := rand.Read(s); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return s
}

// hotp computes an RFC 4226 one-time password.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// verifyTOTP checks code against the steps around now and returns the
// matching step. Steps ≤ lastStep are refused, so a code can be used once.
func verifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := totpStep(now)
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if s <= lastStep || s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s), totpDigits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// otpauthURI is the QR-code payload for authenticator apps.
func otpauthURI(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", b32.EncodeToString(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}
