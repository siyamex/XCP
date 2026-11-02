package httpapi

import (
	"net/http"
	"strconv"
	"time"
)

func (s *Server) bandwidth(w http.ResponseWriter, r *http.Request) error {
	b, err := s.Stats.Bandwidth(r.Context(), principal(r), r.PathValue("id"), r.URL.Query().Get("month"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, b)
	return nil
}

func (s *Server) tailLog(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	lines := 100
	if v := q.Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			n = -1 // refused by the service with the field's message
		}
		lines = n
	}
	l, err := s.Stats.Tail(r.Context(), principal(r), r.PathValue("id"), r.PathValue("kind"), lines, q.Get("q"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string][]string{"lines": l})
	return nil
}

func (s *Server) downloadLog(w http.ResponseWriter, r *http.Request) error {
	kind := r.PathValue("kind")
	start := func() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+kind+`.log"`)
		w.Header().Set("Cache-Control", "no-store")
		// Big logs take longer than the server's usual write timeout.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		w.WriteHeader(http.StatusOK)
	}
	return s.Stats.Download(r.Context(), principal(r), r.PathValue("id"), kind, start, w)
}
