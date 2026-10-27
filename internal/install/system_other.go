//go:build !linux

package install

import (
	"errors"
)

// NewLinuxSystem is only available on Linux; the installer does not run elsewhere.
func NewLinuxSystem() (System, error) {
	return nil, errors.New("xcp-install runs only on Linux")
}
