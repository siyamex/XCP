// Package apperr holds domain errors shared by the service packages. The
// HTTP layer maps them to status codes (internal/httpapi/problem.go).
package apperr

import "errors"

// ErrForbidden means the caller's role or scope does not allow the action.
var ErrForbidden = errors.New("you are not allowed to do this")

// Conflict is a 409 error with a stable machine-readable code, such as
// "name_taken" or "in_use".
type Conflict struct {
	Code    string
	Message string
}

func (e *Conflict) Error() string { return e.Message }

// NewConflict returns a *Conflict.
func NewConflict(code, message string) *Conflict { return &Conflict{Code: code, Message: message} }
