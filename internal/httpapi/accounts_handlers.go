package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/store"
)

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	items, err := s.Accounts.List(r.Context(), principal(r), q.Get("search"), q.Get("status"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) error {
	a, err := s.Accounts.Get(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) error {
	var in accounts.CreateInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	a, err := s.Accounts.Create(r.Context(), client(r), principal(r), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, a) // the Linux side is set up by the job in a.job_id
	return nil
}

func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request) error {
	var in accounts.UpdateInput
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	a, err := s.Accounts.Update(r.Context(), client(r), principal(r), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, a)
	return nil
}

func (s *Server) suspendAccount(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	a, err := s.Accounts.Suspend(r.Context(), client(r), principal(r), r.PathValue("id"), in.Reason)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, a)
	return nil
}

func (s *Server) unsuspendAccount(w http.ResponseWriter, r *http.Request) error {
	a, err := s.Accounts.Unsuspend(r.Context(), client(r), principal(r), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, a)
	return nil
}

func (s *Server) setAccountPassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Password   string `json:"password"`
		MustChange bool   `json:"must_change"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := s.Accounts.SetPassword(r.Context(), client(r), principal(r), r.PathValue("id"), in.Password, in.MustChange); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) terminateAccount(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	a, err := s.Accounts.Terminate(r.Context(), client(r), principal(r), r.PathValue("id"), in.Confirm)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, a)
	return nil
}

type jobJSON struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Status     string          `json:"status"`
	Progress   int             `json:"progress"`
	Attempts   int             `json:"attempts"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	AccountID  string          `json:"account_id,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) error {
	if principal(r).Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	j, err := s.Jobs.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, jobJSON{
		ID: j.ID, Kind: j.Kind, Status: string(j.Status), Progress: j.Progress, Attempts: j.Attempts,
		Error: j.Error, Result: j.Result, AccountID: j.AccountID, CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt,
	})
	return nil
}
