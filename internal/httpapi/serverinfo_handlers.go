package httpapi

import (
	"net/http"
	"strconv"
)

func intQuery(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1 // refused by the service with the field's message
	}
	return n
}

func (s *Server) serverStatus(w http.ResponseWriter, r *http.Request) error {
	st, err := s.ServerInfo.Status(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, st)
	return nil
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) error {
	l, err := s.ServerInfo.Services(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
	return nil
}

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) error {
	v, err := s.ServerInfo.ServiceAction(r.Context(), client(r), principal(r), r.PathValue("id"), r.PathValue("action"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) serviceLog(w http.ResponseWriter, r *http.Request) error {
	text, err := s.ServerInfo.ServiceLog(r.Context(), principal(r), r.PathValue("id"), intQuery(r, "lines", 100))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text})
	return nil
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	l, err := s.ServerInfo.Jobs(r.Context(), principal(r), q.Get("status"), q.Get("kind"), intQuery(r, "limit", 50))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
	return nil
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) error {
	j, err := s.ServerInfo.CancelJob(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, j)
	return nil
}

func (s *Server) retryJob(w http.ResponseWriter, r *http.Request) error {
	j, err := s.ServerInfo.RetryJob(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, j)
	return nil
}

func (s *Server) allSessions(w http.ResponseWriter, r *http.Request) error {
	l, err := s.ServerInfo.Sessions(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
	return nil
}

func (s *Server) revokeAnySession(w http.ResponseWriter, r *http.Request) error {
	if err := s.ServerInfo.RevokeSession(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) loginHistory(w http.ResponseWriter, r *http.Request) error {
	l, err := s.ServerInfo.Logins(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
	return nil
}
