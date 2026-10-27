package httpapi

import (
	"net/http"
	"time"

	"github.com/siyamex/XCP/internal/auth"
)

func (s *Server) health(w http.ResponseWriter, _ *http.Request) error {
	// Deliberately minimal: no version, so unauthenticated scanners learn nothing.
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	MFARequired        bool   `json:"mfa_required"`
	MustChangePassword bool   `json:"must_change_password"`
	CSRFToken          string `json:"csrf_token"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	res, err := s.Auth.Login(r.Context(), client(r), req.Username, req.Password)
	if err != nil {
		return err
	}
	// End the session this browser had before, instead of leaving it orphaned.
	if old, err := r.Cookie(s.cookieName); err == nil && old.Value != "" {
		_ = s.Auth.Logout(r.Context(), client(r), old.Value)
	}
	s.setSessionCookie(w, res.Token)
	writeJSON(w, http.StatusOK, loginResponse{
		MFARequired: res.MFARequired, MustChangePassword: res.MustChangePassword, CSRFToken: auth.CSRFToken(res.Token),
	})
	return nil
}

type codeRequest struct {
	Code string `json:"code"`
}

func (s *Server) verify2FA(w http.ResponseWriter, r *http.Request) error {
	var req codeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := s.Auth.VerifyMFA(r.Context(), client(r), sessionToken(r), req.Code); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	if err := s.Auth.Logout(r.Context(), client(r), sessionToken(r)); err != nil {
		return err
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type meResponse struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	Email              string `json:"email"`
	Locale             string `json:"locale"`
	TOTPEnabled        bool   `json:"totp_enabled"`
	MustChangePassword bool   `json:"must_change_password"`
	ImpersonatorID     string `json:"impersonator_id,omitempty"`
	CSRFToken          string `json:"csrf_token"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	writeJSON(w, http.StatusOK, meResponse{
		ID: p.Login.ID, Username: p.Login.Username, Role: p.Login.Role, Email: p.Login.Email,
		Locale: p.Login.Locale, TOTPEnabled: p.Login.TOTPEnabled(), MustChangePassword: p.Login.MustChangePassword,
		ImpersonatorID: p.Session.ImpersonatorID, CSRFToken: auth.CSRFToken(sessionToken(r)),
	})
	return nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) error {
	var req changePasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := s.Auth.ChangePassword(r.Context(), client(r), principal(r), req.CurrentPassword, req.NewPassword); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type passwordRequest struct {
	Password string `json:"password"`
}

func (s *Server) reauth(w http.ResponseWriter, r *http.Request) error {
	var req passwordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := s.Auth.Reauth(r.Context(), client(r), principal(r), req.Password); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type sessionJSON struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Current    bool      `json:"current"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) error {
	list, err := s.Auth.Sessions(r.Context(), principal(r))
	if err != nil {
		return err
	}
	items := make([]sessionJSON, 0, len(list))
	for _, x := range list {
		items = append(items, sessionJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) error {
	if err := s.Auth.RevokeSession(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) setup2FA(w http.ResponseWriter, r *http.Request) error {
	setup, err := s.Auth.BeginTOTP(r.Context(), client(r), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": setup.Secret, "otpauth_uri": setup.URI})
	return nil
}

func (s *Server) confirm2FA(w http.ResponseWriter, r *http.Request) error {
	var req codeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	codes, err := s.Auth.ConfirmTOTP(r.Context(), client(r), principal(r), req.Code)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
	return nil
}

func (s *Server) disable2FA(w http.ResponseWriter, r *http.Request) error {
	var req passwordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := s.Auth.DisableTOTP(r.Context(), client(r), principal(r), req.Password); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
