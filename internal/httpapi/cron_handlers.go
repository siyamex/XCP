package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/cronjobs"
)

func (s *Server) cronOverview(w http.ResponseWriter, r *http.Request) error {
	o, err := s.Cron.Overview(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) createCronJob(w http.ResponseWriter, r *http.Request) error {
	var in cronjobs.Input
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	j, err := s.Cron.Create(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, j)
	return nil
}

func (s *Server) updateCronJob(w http.ResponseWriter, r *http.Request) error {
	var in cronjobs.Input
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	j, err := s.Cron.Update(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, j)
	return nil
}

func (s *Server) deleteCronJob(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Cron.Delete(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}
