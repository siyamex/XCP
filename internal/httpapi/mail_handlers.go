package httpapi

import (
	"net/http"

	"github.com/siyamex/XCP/internal/mail"
)

func (s *Server) mailOverview(w http.ResponseWriter, r *http.Request) error {
	o, err := s.Mail.Overview(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, o)
	return nil
}

func (s *Server) createMailbox(w http.ResponseWriter, r *http.Request) error {
	var in mail.MailboxInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	m, err := s.Mail.CreateMailbox(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, m)
	return nil
}

func (s *Server) updateMailbox(w http.ResponseWriter, r *http.Request) error {
	var in mail.MailboxUpdate
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	m, err := s.Mail.UpdateMailbox(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, m)
	return nil
}

func (s *Server) setMailboxPassword(w http.ResponseWriter, r *http.Request) error {
	var in passwordInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Mail.SetMailboxPassword(r.Context(), client(r), principal(r), r.PathValue("id"), in.Password)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) deleteMailbox(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Mail.DeleteMailbox(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) createForwarder(w http.ResponseWriter, r *http.Request) error {
	var in mail.ForwarderInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	f, err := s.Mail.CreateForwarder(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, f)
	return nil
}

func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Mail.DeleteForwarder(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) setCatchAll(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		To []string `json:"to"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Mail.SetCatchAll(r.Context(), client(r), principal(r), r.PathValue("id"), in.To)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) mailDeliverability(w http.ResponseWriter, r *http.Request) error {
	d, err := s.Mail.Deliverability(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, d)
	return nil
}

func (s *Server) repairMailDNS(w http.ResponseWriter, r *http.Request) error {
	changed, err := s.Mail.Repair(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{"changed": changed})
	return nil
}

func (s *Server) getMailSettings(w http.ResponseWriter, r *http.Request) error {
	set, err := s.Mail.Settings(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, set)
	return nil
}

func (s *Server) putMailSettings(w http.ResponseWriter, r *http.Request) error {
	var in mail.SettingsInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	set, jobID, err := s.Mail.SaveSettings(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"settings": set, "job_id": jobID})
	return nil
}
