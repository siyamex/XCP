package secretbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpen(t *testing.T) {
	b := newBox(t)
	ad := []byte("login:01ABC:totp")
	s1 := b.Seal([]byte("secret"), ad)
	s2 := b.Seal([]byte("secret"), ad)
	if bytes.Equal(s1, s2) {
		t.Fatal("nonce reused: same plaintext sealed to identical output")
	}
	pt, err := b.Open(s1, ad)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
}

func TestOpenRejectsTamperingAndWrongContext(t *testing.T) {
	b := newBox(t)
	sealed := b.Seal([]byte("secret"), []byte("login:A:totp"))

	if _, err := b.Open(sealed, []byte("login:B:totp")); !errors.Is(err, ErrDecrypt) {
		t.Error("ciphertext opened for another record")
	}
	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	if _, err := b.Open(flipped, []byte("login:A:totp")); !errors.Is(err, ErrDecrypt) {
		t.Error("tampered ciphertext accepted")
	}
	other, _ := New(bytes.Repeat([]byte{8}, KeySize))
	if _, err := other.Open(sealed, []byte("login:A:totp")); !errors.Is(err, ErrDecrypt) {
		t.Error("opened with another key")
	}
	for _, bad := range [][]byte{nil, {1}, {2, 0, 0}} {
		if _, err := b.Open(bad, nil); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Open(%v) accepted", bad)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "master.key")
	k1, err := LoadOrCreateKey(path)
	if err != nil || len(k1) != KeySize {
		t.Fatalf("create: %v", err)
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("key changed on second load")
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("short key accepted")
	}
}
