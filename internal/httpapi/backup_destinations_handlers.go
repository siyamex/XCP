package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/backups"
)

func (s *Server) listDestinations(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Backups.Destinations(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) createDestination(w http.ResponseWriter, r *http.Request) error {
	var in backups.DestinationInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Backups.CreateDestination(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, d)
	return nil
}

func (s *Server) updateDestination(w http.ResponseWriter, r *http.Request) error {
	var in backups.DestinationInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Backups.UpdateDestination(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, d)
	return nil
}

func (s *Server) deleteDestination(w http.ResponseWriter, r *http.Request) error {
	if err := s.Backups.DeleteDestination(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) testDestination(w http.ResponseWriter, r *http.Request) error {
	if err := s.Backups.TestDestination(r.Context(), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) destinationFiles(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Backups.DestinationFiles(r.Context(), principal(r), r.PathValue("id"), r.URL.Query().Get("username"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) fetchFromDestination(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Username string `json:"username"`
		File     string `json:"file"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	id, err := s.Backups.FetchFromDestination(r.Context(), client(r), principal(r), r.PathValue("id"), in.Username, in.File)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	return nil
}

func (s *Server) sendToDestination(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		DestinationID string `json:"destination_id"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	id, err := s.Backups.SendToDestination(r.Context(), client(r), principal(r), r.PathValue("id"), in.DestinationID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	return nil
}
