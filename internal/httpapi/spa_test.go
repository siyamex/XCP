package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func spaServer(ui fstest.MapFS) *Server {
	d := Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if ui != nil {
		d.UI = ui
	}
	return New(d)
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestSPAServesFilesAndFallsBackToIndex(t *testing.T) {
	s := spaServer(fstest.MapFS{
		"index.html":          {Data: []byte("<html>app</html>")},
		"assets/index-abc.js": {Data: []byte("console.log(1)")},
		"favicon.svg":         {Data: []byte("<svg/>")},
		"assets/sub/.keep":    {Data: nil},
	})

	rec := get(t, s, "GET", "/")
	if rec.Code != 200 || rec.Body.String() != "<html>app</html>" || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("/ = %d %q cache=%q", rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
	}
	rec = get(t, s, "GET", "/account/security")
	if rec.Code != 200 || rec.Body.String() != "<html>app</html>" {
		t.Fatalf("client route = %d %q", rec.Code, rec.Body)
	}
	rec = get(t, s, "GET", "/assets/index-abc.js")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") ||
		!strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("asset = %d %v", rec.Code, rec.Header())
	}
	if rec := get(t, s, "GET", "/assets/missing.js"); rec.Code != 404 {
		t.Fatalf("missing asset = %d, want 404 (not index.html)", rec.Code)
	}
	// ServeMux cleans the path and redirects; the clean path only ever maps into the UI FS.
	if rec := get(t, s, "GET", "/../../etc/passwd"); rec.Code != 307 || rec.Header().Get("Location") != "/etc/passwd" {
		t.Fatalf("traversal attempt = %d %v", rec.Code, rec.Header())
	}
	if rec := get(t, s, "GET", "/etc/passwd"); rec.Code != 200 || rec.Body.String() != "<html>app</html>" {
		t.Fatalf("/etc/passwd = %d %q", rec.Code, rec.Body)
	}
	if rec := get(t, s, "POST", "/"); rec.Code != 405 {
		t.Fatalf("POST / = %d", rec.Code)
	}
	if rec := get(t, s, "GET", "/api/v1/unknown"); rec.Code != 404 || !strings.Contains(rec.Body.String(), "not_found") {
		t.Fatalf("unknown API path served the UI: %d %q", rec.Code, rec.Body)
	}
	if !strings.Contains(get(t, s, "GET", "/").Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("UI served without CSP")
	}
}

func TestSPANotBuilt(t *testing.T) {
	for name, s := range map[string]*Server{"nil FS": spaServer(nil), "empty FS": spaServer(fstest.MapFS{".gitkeep": {}})} {
		rec := get(t, s, "GET", "/")
		if rec.Code != 503 || !strings.Contains(rec.Body.String(), "npm run build") {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Body)
		}
	}
}
