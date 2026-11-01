package httpapi

import (
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/files"
	"github.com/siyamex/XCP/internal/userfs"
)

// maxUpload is the largest single upload; the account's disk quota counts too.
const maxUpload = 4 << 30

// inlineTypes are the file types the browser may show instead of saving:
// images that cannot run script on the panel's origin (SVG can).
var inlineTypes = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
}

func (s *Server) filesAccount(r *http.Request) (*files.Account, error) {
	return s.Files.Access(r.Context(), principal(r), r.PathValue("id"))
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	l, err := s.Files.List(r.Context(), a, r.URL.Query().Get("path"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, l)
	return nil
}

func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	resp, err := s.Files.Download(r.Context(), client(r), a, r.URL.Query().Get("path"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	name, _ := url.PathUnescape(resp.Header.Get("X-Entry-Name"))
	ctype, inline := inlineTypes[strings.ToLower(path.Ext(name))]
	disposition := "attachment"
	if inline && r.URL.Query().Get("inline") == "1" {
		disposition = "inline"
	} else {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": name}))
	w.Header().Set("Content-Length", resp.Header.Get("Content-Length"))
	w.Header().Set("Cache-Control", "no-store")
	// Large files take longer than the server's usual write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	_, _ = io.Copy(w, resp.Body)
	return nil
}

func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	body := http.MaxBytesReader(w, r.Body, maxUpload)
	overwrite, _ := strconv.ParseBool(r.URL.Query().Get("overwrite"))
	e, err := s.Files.Upload(r.Context(), client(r), a, r.URL.Query().Get("path"), overwrite, body)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, e)
	return nil
}

func (s *Server) fileOp(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	var in map[string]any
	if err := decodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := s.Files.Op(r.Context(), client(r), a, r.PathValue("op"), in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) searchFiles(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	out, err := s.Files.Search(r.Context(), a, r.URL.Query().Get("path"), r.URL.Query().Get("q"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) fileUsage(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	u, err := s.Files.Usage(r.Context(), a, r.URL.Query().Get("path"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, u)
	return nil
}

func (s *Server) readFileText(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	t, err := s.Files.ReadText(r.Context(), a, r.URL.Query().Get("path"), r.URL.Query().Get("encoding"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) writeFileText(w http.ResponseWriter, r *http.Request) error {
	a, err := s.filesAccount(r)
	if err != nil {
		return err
	}
	var t userfs.Text
	// JSON escapes can make the text up to six times its size.
	if err := decodeJSONLimit(w, r, &t, 6*userfs.MaxTextFile+1024); err != nil {
		return err
	}
	e, err := s.Files.WriteText(r.Context(), client(r), a, r.URL.Query().Get("path"), t)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, e)
	return nil
}
