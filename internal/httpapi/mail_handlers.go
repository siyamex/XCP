package httpapi

import (
	"net/http"
	"strings"

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

func (s *Server) mailboxUsage(w http.ResponseWriter, r *http.Request) error {
	u, err := s.Mail.Usage(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, u)
	return nil
}

func (s *Server) mailboxCleanup(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Folder string `json:"folder"`
		Days   int    `json:"days"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Mail.Cleanup(r.Context(), client(r), principal(r), r.PathValue("id"), in.Folder, in.Days)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) setDomainForward(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		To string `json:"to"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Mail.SetDomainForward(r.Context(), client(r), principal(r), r.PathValue("id"), in.To)
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

func (s *Server) mailDeliverabilityAll(w http.ResponseWriter, r *http.Request) error {
	rep, err := s.Mail.DeliverabilityAll(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, rep)
	return nil
}

func (s *Server) mailDeliveries(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	items, err := s.Mail.Deliveries(r.Context(), principal(r), r.PathValue("id"), q.Get("search"), q.Get("status"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) allMailDeliveries(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	items, err := s.Mail.AllDeliveries(r.Context(), principal(r), q.Get("search"), q.Get("status"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) repairAllMailDNS(w http.ResponseWriter, r *http.Request) error {
	res, err := s.Mail.RepairAll(r.Context(), client(r), principal(r))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
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

func (s *Server) setAutoresponder(w http.ResponseWriter, r *http.Request) error {
	var in mail.Autoresponder
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	jobID, err := s.Mail.SetAutoresponder(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) deleteAutoresponder(w http.ResponseWriter, r *http.Request) error {
	jobID, err := s.Mail.DeleteAutoresponder(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

// webmailSignon returns where the browser signs in to webmail: like
// phpMyAdmin, the host it reached the panel by, on Apache's HTTPS port.
func (s *Server) webmailSignon(w http.ResponseWriter, r *http.Request) error {
	ticket, err := s.Mail.Webmail(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	u := strings.Replace(phpMyAdminURL(r, ticket), "/phpmyadmin/xcp-signon.php?ticket=", "/webmail/?_xcp_ticket=", 1)
	writeJSON(w, http.StatusOK, map[string]string{"url": u})
	return nil
}
