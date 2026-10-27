package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// cheap parameters keep tests fast; production uses DefaultArgon2.
var testArgon = Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}

func TestPasswordHashVerify(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(testArgon, 2)
	enc, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if enc2, _ := h.Hash(ctx, "correct horse battery"); enc2 == enc {
		t.Fatal("same salt used twice")
	}
	ok, rehash, err := h.Verify(ctx, "correct horse battery", enc)
	if err != nil || !ok || rehash {
		t.Fatalf("Verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify(ctx, "wrong", enc); ok {
		t.Fatal("wrong password accepted")
	}
	stronger := NewHasher(Argon2Params{Memory: 16 * 1024, Time: 1, Threads: 1}, 1)
	if ok, rehash, _ := stronger.Verify(ctx, "correct horse battery", enc); !ok || !rehash {
		t.Fatal("old parameters must verify and ask for a rehash")
	}
}

func TestPasswordDecodeRejectsMalformedOrAbusiveHashes(t *testing.T) {
	h := NewHasher(testArgon, 1)
	for _, bad := range []string{
		"",
		"$2y$10$abcdefghijklmnopqrstuv", // bcrypt
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",      // not argon2id
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memory bomb
		"$argon2id$v=19$m=8192,t=1000,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",  // time bomb
		"$argon2id$v=19$m=8192,t=1,p=1$!!!$aGFzaA",
	} {
		if _, _, err := h.Verify(context.Background(), "x", bad); err == nil {
			t.Errorf("Verify accepted hash %q", bad)
		}
	}
}

func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for ts, want := range vectors {
		if got := hotp(secret, uint64(ts/totpPeriod), 8); got != want {
			t.Errorf("T=%d: got %s, want %s", ts, got, want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := newTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := totpStep(now)
	code := hotp(secret, uint64(cur), totpDigits)

	step, ok := verifyTOTP(secret, code[:3]+" "+code[3:], now, 0)
	if !ok || step != cur {
		t.Fatalf("current code rejected: %v %d", ok, step)
	}
	if _, ok := verifyTOTP(secret, code, now, cur); ok {
		t.Fatal("replayed code accepted")
	}
	prev := hotp(secret, uint64(cur-1), totpDigits)
	if _, ok := verifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("code from previous step (clock drift) rejected")
	}
	old := hotp(secret, uint64(cur-3), totpDigits)
	if _, ok := verifyTOTP(secret, old, now, 0); ok {
		t.Fatal("code from 90s ago accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := verifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	uri := otpauthURI("XCP", "alice", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/XCP:alice?") || !strings.Contains(uri, "secret="+b32.EncodeToString(secret)) {
		t.Fatalf("uri = %s", uri)
	}
}

func TestLimiterLocksAndResets(t *testing.T) {
	l := NewLimiter(3, time.Minute, 10*time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }

	l.Fail("ip:1")
	l.Fail("ip:1")
	if ok, _ := l.Allowed("ip:1"); !ok {
		t.Fatal("locked too early")
	}
	l.Fail("ip:1")
	ok, wait := l.Allowed("ip:1")
	if ok || wait != 10*time.Minute {
		t.Fatalf("Allowed = %v, %v; want locked for 10m", ok, wait)
	}
	if ok, _ := l.Allowed("ip:2"); !ok {
		t.Fatal("other key affected")
	}
	now = now.Add(10 * time.Minute)
	if ok, _ := l.Allowed("ip:1"); !ok {
		t.Fatal("lock did not expire")
	}

	l.Fail("user:bob")
	l.Fail("user:bob")
	now = now.Add(2 * time.Minute) // window passed: count starts again
	l.Fail("user:bob")
	if ok, _ := l.Allowed("user:bob"); !ok {
		t.Fatal("failures outside the window were counted")
	}
	l.Fail("user:bob")
	l.Reset("user:bob")
	l.Fail("user:bob")
	if ok, _ := l.Allowed("user:bob"); !ok {
		t.Fatal("Reset did not clear failures")
	}
}
