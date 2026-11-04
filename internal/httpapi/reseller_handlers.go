package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/resellers"
)

func (s *Server) listResellers(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Resellers.List(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) createReseller(w http.ResponseWriter, r *http.Request) error {
	var in resellers.CreateInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.Resellers.Create(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, v)
	return nil
}

func (s *Server) setResellerLimits(w http.ResponseWriter, r *http.Request) error {
	var in resellers.Limits
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.Resellers.SetLimits(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) suspendReseller(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Resellers.SetStatus(r.Context(), client(r), principal(r), r.PathValue("id"), true)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) unsuspendReseller(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Resellers.SetStatus(r.Context(), client(r), principal(r), r.PathValue("id"), false)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) resellerOverview(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Resellers.Overview(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}
