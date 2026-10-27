// Package secretbox encrypts secrets stored in the panel database (TOTP
// secrets, DKIM keys, ...) with the server's master key, using
// XChaCha20-Poly1305 (08-data-model-and-api.md §1, 07-security.md §8).
package secretbox

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the master key length in bytes.
const KeySize = chacha20poly1305.KeySize

const version byte = 1

// ErrDecrypt means the ciphertext is corrupt, was made with another key,
// or belongs to another record (associated data mismatch).
var ErrDecrypt = errors.New("secretbox: decryption failed")

// Box seals and opens values with one key.
type Box struct {
	aead cipher.AEAD
}

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext. ad binds the ciphertext to its context (for
// example "login:<id>:totp"), so it cannot be copied to another record.
func (b *Box) Seal(plaintext, ad []byte) []byte {
	out := make([]byte, 1+chacha20poly1305.NonceSizeX, 1+chacha20poly1305.NonceSizeX+len(plaintext)+b.aead.Overhead())
	out[0] = version
	if _, err := rand.Read(out[1:]); err != nil {
		panic("secretbox: crypto/rand failed: " + err.Error())
	}
	return b.aead.Seal(out, out[1:], plaintext, ad)
}

// Open decrypts a value produced by Seal with the same ad.
func (b *Box) Open(sealed, ad []byte) ([]byte, error) {
	if len(sealed) < 1+chacha20poly1305.NonceSizeX+b.aead.Overhead() || sealed[0] != version {
		return nil, ErrDecrypt
	}
	nonce := sealed[1 : 1+chacha20poly1305.NonceSizeX]
	pt, err := b.aead.Open(nil, nonce, sealed[1+chacha20poly1305.NonceSizeX:], ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// LoadOrCreateKey reads the master key file, creating it (mode 0600) with a
// random key if it does not exist. A key file with the wrong size is an error.
func LoadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err == nil {
		if len(key) != KeySize {
			return nil, fmt.Errorf("secretbox: %s: key must be %d bytes, got %d", path, KeySize, len(key))
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("secretbox: read key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secretbox: create key dir: %w", err)
	}
	key = make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// O_EXCL: if another process created it meanwhile, fail rather than overwrite.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, fmt.Errorf("secretbox: create key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}
