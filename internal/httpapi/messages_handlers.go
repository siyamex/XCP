package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/messages"
)

func (s *Server) getWelcome(w http.ResponseWriter, r *http.Request) error {
	t, err := s.Messages.Welcome(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) putWelcome(w http.ResponseWriter, r *http.Request) error {
	var in messages.BroadcastInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := s.Messages.SetWelcome(r.Context(), client(r), principal(r), in.Subject, in.Body)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) broadcast(w http.ResponseWriter, r *http.Request) error {
	var in messages.BroadcastInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	id, err := s.Messages.Broadcast(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	return nil
}
