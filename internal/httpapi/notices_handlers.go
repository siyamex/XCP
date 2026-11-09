package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/messages"
)

func (s *Server) listNotices(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Messages.Notices(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "variables": messages.Variables})
	return nil
}

func (s *Server) putNotice(w http.ResponseWriter, r *http.Request) error {
	var in messages.BroadcastInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := s.Messages.SetNotice(r.Context(), client(r), principal(r), r.PathValue("kind"), in.Subject, in.Body)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}
