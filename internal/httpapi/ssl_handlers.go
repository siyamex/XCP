package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/ssl"
)

func (s *Server) getSSLSettings(w http.ResponseWriter, r *http.Request) error {
	v, err := s.SSL.GetSettings(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) saveSSLSettings(w http.ResponseWriter, r *http.Request) error {
	var in ssl.SettingsInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.SSL.SaveSettings(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) runAutoSSL(w http.ResponseWriter, r *http.Request) error {
	id, err := s.SSL.Run(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	return nil
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) error {
	items, err := s.SSL.Certificates(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) accountSSL(w http.ResponseWriter, r *http.Request) error {
	items, err := s.SSL.AccountSSL(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) setDomainSSL(w http.ResponseWriter, r *http.Request) error {
	var in ssl.OptionsInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.SSL.SetOptions(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, v)
	return nil
}

func (s *Server) uploadCertificate(w http.ResponseWriter, r *http.Request) error {
	var in ssl.UploadInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := s.SSL.Upload(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, v)
	return nil
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) error {
	id, err := s.SSL.DeleteCertificate(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
	return nil
}
