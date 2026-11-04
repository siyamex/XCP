package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSetSSHDRefusals(t *testing.T) {
	dir := t.TempDir()
	h := &HostConfig{SSHDConfDir: dir, SSHKeysGlob: filepath.Join(dir, "home", "*", "authorized_keys"), SSHRootKeys: filepath.Join(dir, "root_keys")}
	ctx := context.Background()
	if _, err := h.SetSSHD(ctx, SSHSettings{PasswordAuth: true, RootLogin: "maybe"}); err == nil {
		t.Error("an unknown root login rule was accepted")
	}
	if _, err := h.SetSSHD(ctx, SSHSettings{PasswordAuth: false, RootLogin: "no"}); err == nil {
		t.Error("passwords were switched off with no authorized key anywhere")
	}
	if _, err := os.Stat(filepath.Join(dir, sshdConfName)); err == nil {
		t.Error("a refused change left a file behind")
	}
	// An empty key file is no key.
	if err := os.WriteFile(h.SSHRootKeys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if h.hasAuthorizedKeys() {
		t.Error("an empty authorized_keys counted")
	}
	if err := os.WriteFile(h.SSHRootKeys, []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !h.hasAuthorizedKeys() {
		t.Error("a key was not found")
	}
}

func TestSSHState(t *testing.T) {
	s, ok := SSHState("# x\nPasswordAuthentication no\nPermitRootLogin prohibit-password\n")
	if !ok || s.PasswordAuth || s.RootLogin != "prohibit-password" {
		t.Errorf("%+v %v", s, ok)
	}
}
