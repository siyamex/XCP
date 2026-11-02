package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/ftp"
)

func (s *Server) ftpOverview(w http.ResponseWriter, r *http.Request) error {
	o, err := s.FTP.Overview(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) createFTPAccount(w http.ResponseWriter, r *http.Request) error {
	var in ftp.Input
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	l, err := s.FTP.Create(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, l)
	return nil
}

func (s *Server) updateFTPAccount(w http.ResponseWriter, r *http.Request) error {
	var in ftp.Update
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	l, err := s.FTP.Update(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, l)
	return nil
}

func (s *Server) setFTPPassword(w http.ResponseWriter, r *http.Request) error {
	var in passwordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.FTP.SetPassword(r.Context(), client(r), principal(r), r.PathValue("id"), in.Password)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) deleteFTPAccount(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.FTP.Delete(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}
