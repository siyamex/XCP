package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/backups"
	"github.com/siyamex/XCP/internal/serversettings"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Settings.Items(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Values map[string]any `json:"values"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	items, err := s.Settings.Update(r.Context(), client(r), principal(r), in.Values)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Settings.GetSetup(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) putSetup(w http.ResponseWriter, r *http.Request) error {
	var in serversettings.SetupInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.Settings.SaveSetup(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) putHostname(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Hostname string `json:"hostname"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.Settings.ChangeHostname(r.Context(), client(r), principal(r), in.Hostname)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Settings.CheckUpdates(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) postReboot(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Mode     string `json:"mode"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := s.ServerInfo.Reboot(r.Context(), client(r), principal(r), in.Mode, in.Password); err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"rebooting": true})
	return nil
}

func (s *Server) postRebuild(w http.ResponseWriter, r *http.Request) error {
	res, err := s.ServerInfo.Rebuild(r.Context(), client(r), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": res})
	return nil
}

func (s *Server) orphanBackups(w http.ResponseWriter, r *http.Request) error {
	l, err := s.Backups.Orphans(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
	return nil
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) error {
	var in backups.RestoreInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Backups.Restore(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}
