package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/siyamex/XCP/internal/backups"
)

func (s *Server) backupsOverview(w http.ResponseWriter, r *http.Request) error {
	o, err := s.Backups.Overview(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) error {
	b, err := s.Backups.Create(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, b)
	return nil
}

func (s *Server) deleteBackup(w http.ResponseWriter, r *http.Request) error {
	if err := s.Backups.Delete(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) error {
	start := func(name string, size int64) {
		w.Header().Set("Content-Type", "application/zstd")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Cache-Control", "no-store")
		// Backups take longer than the server's usual write timeout.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		w.WriteHeader(http.StatusOK)
	}
	return s.Backups.Download(r.Context(), client(r), principal(r), r.PathValue("id"), start, w)
}

func (s *Server) getBackupSchedule(w http.ResponseWriter, r *http.Request) error {
	sched, err := s.Backups.GetSchedule(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, sched)
	return nil
}

func (s *Server) putBackupSchedule(w http.ResponseWriter, r *http.Request) error {
	var in backups.Schedule
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	sched, err := s.Backups.SetSchedule(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, sched)
	return nil
}
