package auth

import "github.com/siyamex/XCP/internal/store"

// Two-factor policies (ADM-SEC-08): who must have 2FA to use the panel.
const (
	MFANone      = "none"
	MFAAdmins    = "admins"    // admins
	MFAResellers = "resellers" // admins and resellers
	MFAAll       = "all"       // everyone
)

// SetMFAPolicy sets who must use two-factor sign-in, from now on. Logins
// that must and have not set it up can only reach the pages to do so.
func (s *Service) SetMFAPolicy(policy string) {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	s.mfaPolicy = policy
}

// MFAEnrollmentRequired reports whether the login must set up 2FA before
// it may use the panel.
func (s *Service) MFAEnrollmentRequired(l *store.Login) bool {
	s.limMu.RLock()
	policy := s.mfaPolicy
	s.limMu.RUnlock()
	if l.TOTPEnabled() {
		return false
	}
	switch policy {
	case MFAAdmins:
		return l.Role == store.RoleAdmin
	case MFAResellers:
		return l.Role == store.RoleAdmin || l.Role == store.RoleReseller
	case MFAAll:
		return true
	}
	return false
}
