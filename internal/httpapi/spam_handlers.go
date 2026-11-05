package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/mail"
)

func (s *Server) getSpam(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Mail.Spam(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) putSpam(w http.ResponseWriter, r *http.Request) error {
	var in mail.Spam
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.Mail.SetSpam(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, v)
	return nil
}
