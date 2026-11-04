package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/agent"
)

func (s *Server) mailQueue(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Mail.Queue(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "limit": agent.MaxQueueList})
	return nil
}

func (s *Server) mailQueueAction(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Action string   `json:"action"`
		IDs    []string `json:"ids"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := s.Mail.QueueAction(r.Context(), client(r), principal(r), in.Action, in.IDs); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
