package auth

import (
	"testing"

	"github.com/siyamex/XCP/internal/store"
)

func TestMFAEnrollmentRequired(t *testing.T) {
	s := &Service{}
	login := func(role string, totp bool) *store.Login {
		l := &store.Login{Role: role}
		if totp {
			l.TOTPSecretEnc = []byte("x")
		}
		return l
	}
	cases := []struct {
		policy string
		role   string
		totp   bool
		want   bool
	}{
		{MFANone, store.RoleAdmin, false, false},
		{"", store.RoleAdmin, false, false},
		{MFAAdmins, store.RoleAdmin, false, true},
		{MFAAdmins, store.RoleAdmin, true, false},
		{MFAAdmins, store.RoleReseller, false, false},
		{MFAResellers, store.RoleReseller, false, true},
		{MFAResellers, store.RoleUser, false, false},
		{MFAAll, store.RoleUser, false, true},
		{MFAAll, store.RoleUser, true, false},
	}
	for _, c := range cases {
		s.SetMFAPolicy(c.policy)
		if got := s.MFAEnrollmentRequired(login(c.role, c.totp)); got != c.want {
			t.Errorf("policy %q role %s totp %v = %v, want %v", c.policy, c.role, c.totp, got, c.want)
		}
	}
}
