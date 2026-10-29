package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/zones"
)

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	items, err := s.Zones.List(r.Context(), principal(r), q.Get("account_id"), q.Get("search"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) getZone(w http.ResponseWriter, r *http.Request) error {
	z, err := s.Zones.Get(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, z)
	return nil
}

func (s *Server) updateZone(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		MailRouting string `json:"mail_routing"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	z, err := s.Zones.SetMailRouting(r.Context(), client(r), principal(r), r.PathValue("id"), in.MailRouting)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, z)
	return nil
}

func (s *Server) addRecord(w http.ResponseWriter, r *http.Request) error {
	var in zones.RecordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	rec, err := s.Zones.AddRecord(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, rec) // served once the job in rec.job_id has run
	return nil
}

func (s *Server) updateRecord(w http.ResponseWriter, r *http.Request) error {
	var in zones.RecordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	rec, err := s.Zones.UpdateRecord(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, rec)
	return nil
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Zones.DeleteRecord(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) getDNSSettings(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Zones.GetSettings(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) saveDNSSettings(w http.ResponseWriter, r *http.Request) error {
	var in zones.Settings
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	set, queued, err := s.Zones.SaveSettings(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": set, "zones_queued": queued})
	return nil
}
