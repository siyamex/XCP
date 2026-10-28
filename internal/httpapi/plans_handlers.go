package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/plans"
)

func (s *Server) listFeatures(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]any{"items": plans.Catalog})
	return nil
}

func (s *Server) listFeatureLists(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Plans.ListFeatureLists(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) getFeatureList(w http.ResponseWriter, r *http.Request) error {
	f, err := s.Plans.GetFeatureList(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, f)
	return nil
}

func (s *Server) saveFeatureList(w http.ResponseWriter, r *http.Request, id string, status int) error {
	var in plans.FeatureListInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	f, err := s.Plans.SaveFeatureList(r.Context(), client(r), principal(r), id, in)
	if err != nil {
		return err
	}
	writeJSON(w, status, f)
	return nil
}

func (s *Server) createFeatureList(w http.ResponseWriter, r *http.Request) error {
	return s.saveFeatureList(w, r, "", http.StatusCreated)
}

func (s *Server) updateFeatureList(w http.ResponseWriter, r *http.Request) error {
	return s.saveFeatureList(w, r, r.PathValue("id"), http.StatusOK)
}

func (s *Server) deleteFeatureList(w http.ResponseWriter, r *http.Request) error {
	if err := s.Plans.DeleteFeatureList(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Plans.ListPackages(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) error {
	p, err := s.Plans.GetPackage(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, p)
	return nil
}

func (s *Server) savePackage(w http.ResponseWriter, r *http.Request, id string, status int) error {
	var in plans.PackageInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := s.Plans.SavePackage(r.Context(), client(r), principal(r), id, in)
	if err != nil {
		return err
	}
	writeJSON(w, status, p)
	return nil
}

func (s *Server) createPackage(w http.ResponseWriter, r *http.Request) error {
	return s.savePackage(w, r, "", http.StatusCreated)
}

func (s *Server) updatePackage(w http.ResponseWriter, r *http.Request) error {
	return s.savePackage(w, r, r.PathValue("id"), http.StatusOK)
}

func (s *Server) deletePackage(w http.ResponseWriter, r *http.Request) error {
	if err := s.Plans.DeletePackage(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
