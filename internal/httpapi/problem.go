// Package httpapi is xcp-api's HTTP layer: routing, middleware, JSON and
// errors. Handlers stay thin; rules live in the service packages
// (02-tech-stack-and-repo.md §4).
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Problem is an RFC 9457 error body. Code is the stable, machine-readable
// value clients should switch on; Title and Detail are for people.
type Problem struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Code      string       `json:"code"`
	Detail    string       `json:"detail,omitempty"`
	Errors    []FieldError `json:"errors,omitempty"`
	RequestID string       `json:"request_id,omitempty"`
}

// FieldError points at one invalid input field.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// apiError is an error with a fixed HTTP status and code, raised by handlers.
type apiError struct {
	status int
	code   string
	detail string
}

func (e *apiError) Error() string { return e.detail }

func newAPIError(status int, code, detail string) *apiError {
	return &apiError{status: status, code: code, detail: detail}
}

var (
	errCSRF          = newAPIError(http.StatusForbidden, "csrf_failed", "missing or invalid X-CSRF-Token header")
	errCrossOrigin   = newAPIError(http.StatusForbidden, "cross_origin", "cross-origin request refused")
	errMustChangePwd = newAPIError(http.StatusForbidden, "password_change_required", "change your password to continue")
	errMediaType     = newAPIError(http.StatusUnsupportedMediaType, "unsupported_media_type", "send Content-Type: application/json")
	errNotFound      = newAPIError(http.StatusNotFound, "not_found", "not found")
)

// toProblem maps any error to a Problem. Unknown errors become a generic 500
// so internal details never reach clients; they are logged instead.
func toProblem(err error, log *slog.Logger) (Problem, http.Header) {
	h := http.Header{}
	var (
		api *apiError
		ve  *validate.Error
		rl  *auth.RateLimitedError
		mbe *http.MaxBytesError
	)
	p := func(status int, code, detail string) Problem {
		return Problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, Detail: detail}
	}
	switch {
	case errors.As(err, &api):
		return p(api.status, api.code, api.detail), h
	case errors.As(err, &ve):
		pr := p(http.StatusBadRequest, "validation_failed", "some fields are invalid")
		pr.Errors = []FieldError{{Field: ve.Field, Code: ve.Code, Message: ve.Message}}
		return pr, h
	case errors.As(err, &rl):
		h.Set("Retry-After", strconv.Itoa(int(rl.RetryAfter.Seconds())+1))
		return p(http.StatusTooManyRequests, "rate_limited", err.Error()), h
	case errors.As(err, &mbe):
		return p(http.StatusRequestEntityTooLarge, "body_too_large", fmt.Sprintf("request body larger than %d bytes", mbe.Limit)), h
	case errors.Is(err, auth.ErrInvalidCredentials):
		return p(http.StatusUnauthorized, "invalid_credentials", err.Error()), h
	case errors.Is(err, auth.ErrUnauthenticated):
		return p(http.StatusUnauthorized, "unauthenticated", err.Error()), h
	case errors.Is(err, auth.ErrMFARequired):
		return p(http.StatusUnauthorized, "mfa_required", err.Error()), h
	case errors.Is(err, auth.ErrInvalidCode):
		return p(http.StatusUnauthorized, "invalid_code", err.Error()), h
	case errors.Is(err, auth.ErrLoginDisabled):
		return p(http.StatusForbidden, "login_disabled", err.Error()), h
	case errors.Is(err, auth.ErrReauthRequired):
		return p(http.StatusForbidden, "reauth_required", err.Error()), h
	case errors.Is(err, auth.ErrTOTPState):
		return p(http.StatusConflict, "totp_state", err.Error()), h
	case errors.Is(err, store.ErrNotFound):
		return p(http.StatusNotFound, "not_found", "not found"), h
	}
	log.Error("internal error", "err", err)
	return p(http.StatusInternalServerError, "internal", "internal error; see the server log for the request ID"), h
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger) {
	pr, h := toProblem(err, log.With("request_id", requestID(r)))
	pr.RequestID = requestID(r)
	for k, v := range h {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(pr.Status)
	_ = json.NewEncoder(w).Encode(pr)
}
