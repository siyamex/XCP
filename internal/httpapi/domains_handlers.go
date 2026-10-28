package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/domains"
)

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Domains.List(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) error {
	var in domains.AddInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Domains.Add(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, d) // configured by the job in d.job_id
	return nil
}

func (s *Server) domainVerification(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Domains.Verification(r.Context(), principal(r), r.PathValue("id"), r.URL.Query().Get("name"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) updateDomain(w http.ResponseWriter, r *http.Request) error {
	var in domains.UpdateInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := s.Domains.Update(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, d)
	return nil
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Domains.Delete(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) listRedirects(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Domains.ListRedirects(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) addRedirect(w http.ResponseWriter, r *http.Request) error {
	var in domains.RedirectInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	rd, err := s.Domains.AddRedirect(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, rd)
	return nil
}

func (s *Server) deleteRedirect(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Domains.DeleteRedirect(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}
