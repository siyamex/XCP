package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// maxJSONBody limits API request bodies. Uploads get their own endpoints later.
const maxJSONBody = 1 << 20

// decodeJSON reads exactly one JSON object into dst. It requires
// Content-Type: application/json, which cross-site HTML forms cannot send
// without a CORS preflight (that we never allow), and rejects unknown fields
// so typos fail loudly instead of being ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return errMediaType
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return newAPIError(http.StatusBadRequest, "bad_json", "invalid JSON body: "+err.Error())
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return newAPIError(http.StatusBadRequest, "bad_json", "body must contain a single JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
