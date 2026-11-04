package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/firewall"
	"github.com/siyamex/XCP/internal/fwcfg"
)

func (s *Server) getFirewall(w http.ResponseWriter, r *http.Request) error {
	o, err := s.Firewall.Get(r.Context(), client(r), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) putFirewall(w http.ResponseWriter, r *http.Request) error {
	var in fwcfg.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := s.Firewall.Save(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) banIP(w http.ResponseWriter, r *http.Request) error {
	var in firewall.BanInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	b, err := s.Firewall.BanIP(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, b)
	return nil
}

func (s *Server) unbanIP(w http.ResponseWriter, r *http.Request) error {
	if err := s.Firewall.Unban(r.Context(), client(r), principal(r), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
