package httpapi

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// spa serves the web UI: real files when they exist, otherwise index.html,
// so client-side routes like /account/security work on reload.
func (s *Server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.UI == nil {
			http.Error(w, "web UI not built: run `npm ci && npm run build` in web/, then rebuild xcp-api", http.StatusServiceUnavailable)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if fi, err := fs.Stat(s.UI, name); err == nil && !fi.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite puts a content hash in every asset name, so they never change.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, s.UI, name) //nolint:gosec // G703: name is cleaned and fs.FS cannot leave its root
				return
			}
			if strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r) // a missing asset must not turn into index.html
				return
			}
		}
		index, err := fs.ReadFile(s.UI, "index.html")
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "web UI not built: run `npm ci && npm run build` in web/, then rebuild xcp-api", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
