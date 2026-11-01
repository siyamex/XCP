package httpapi

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/siyamex/XCP/internal/databases"
)

type nameInput struct {
	Name string `json:"name"`
}

type passwordInput struct {
	Password string `json:"password"`
}

func (s *Server) databasesOverview(w http.ResponseWriter, r *http.Request) error {
	o, err := s.Databases.Overview(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) error {
	var in nameInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Databases.CreateDatabase(r.Context(), client(r), principal(r), r.PathValue("id"), in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, d) // created by the job in d.job_id
	return nil
}

func (s *Server) databaseWizard(w http.ResponseWriter, r *http.Request) error {
	var in databases.WizardInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := s.Databases.Wizard(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, res)
	return nil
}

func (s *Server) renameDatabase(w http.ResponseWriter, r *http.Request) error {
	var in nameInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Databases.RenameDatabase(r.Context(), client(r), principal(r), r.PathValue("id"), in.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, d)
	return nil
}

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Databases.DeleteDatabase(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) createDBUser(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	u, err := s.Databases.CreateUser(r.Context(), client(r), principal(r), r.PathValue("id"), in.Name, in.Password)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, u)
	return nil
}

func (s *Server) setDBUserPassword(w http.ResponseWriter, r *http.Request) error {
	var in passwordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Databases.SetPassword(r.Context(), client(r), principal(r), r.PathValue("id"), in.Password)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) deleteDBUser(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Databases.DeleteUser(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) setDBGrant(w http.ResponseWriter, r *http.Request) error {
	var in databases.GrantInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Databases.SetGrant(r.Context(), client(r), principal(r), r.PathValue("id"), r.PathValue("database_id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) revokeDBGrant(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Databases.RevokeGrant(r.Context(), client(r), principal(r), r.PathValue("id"), r.PathValue("database_id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

// phpMyAdminURL is where the browser signs in to phpMyAdmin: the host it
// reached the panel by, on Apache's HTTPS port (ADR-0006).
func phpMyAdminURL(r *http.Request, ticket string) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host + "/phpmyadmin/xcp-signon.php?ticket=" + url.QueryEscape(ticket)
}

func (s *Server) phpMyAdminSignon(w http.ResponseWriter, r *http.Request) error {
	ticket, err := s.Databases.Signon(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": phpMyAdminURL(r, ticket)})
	return nil
}

func (s *Server) mysqlStatus(w http.ResponseWriter, r *http.Request) error {
	st, err := s.Databases.Status(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, st)
	return nil
}

func (s *Server) setMySQLRootPassword(w http.ResponseWriter, r *http.Request) error {
	var in passwordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := s.Databases.SetRootPassword(r.Context(), client(r), principal(r), in.Password); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
