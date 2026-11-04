package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/auth"
)

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) error {
	ts, err := s.Auth.ListTokens(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ts})
	return nil
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) error {
	var in auth.TokenInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := s.Auth.CreateToken(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, t)
	return nil
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) error {
	if err := s.Auth.RevokeToken(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
