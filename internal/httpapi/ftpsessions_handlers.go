package httpapi

import (
	"net/http"
	"strconv"

	"github.com/siyamex/XCP/internal/validate"
)

func (s *Server) ftpSessions(w http.ResponseWriter, r *http.Request) error {
	items, err := s.FTP.Sessions(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) endFTPSession(w http.ResponseWriter, r *http.Request) error {
	pid, err := strconv.ParseInt(r.PathValue("pid"), 10, 32)
	if err != nil || pid <= 1 {
		return validate.WithField(&validate.Error{Code: validate.CodeFormat, Message: "not a session number"}, "pid")
	}
	if err := s.FTP.EndSession(r.Context(), client(r), principal(r), r.PathValue("id"), int32(pid)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
