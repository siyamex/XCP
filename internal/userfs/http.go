package userfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Error codes between xcp-userd and xcp-api.
const (
	CodeNotFound = "not_found"
	CodeExists   = "exists"
	CodeInvalid  = "invalid"
	CodeTooLarge = "too_large"
	CodeTooMany  = "too_many"
	CodeInternal = "internal"
)

// Error is a failed operation as xcp-api sees it.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"error"`
}

func (e *Error) Error() string { return e.Message }

func toError(err error) *Error {
	msg := err.Error()
	for _, p := range []string{ErrInvalid.Error() + ": ", ErrNotFound.Error() + ": "} {
		msg = strings.TrimPrefix(msg, p)
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return &Error{http.StatusNotFound, CodeNotFound, "not found"}
	case errors.Is(err, ErrExists):
		return &Error{http.StatusConflict, CodeExists, "something with that name exists already"}
	case errors.Is(err, ErrInvalid):
		return &Error{http.StatusBadRequest, CodeInvalid, msg}
	case errors.Is(err, ErrTooLarge):
		return &Error{http.StatusRequestEntityTooLarge, CodeTooLarge, msg}
	case errors.Is(err, ErrTooMany):
		return &Error{http.StatusUnprocessableEntity, CodeTooMany, msg}
	case errors.Is(err, fs.ErrPermission):
		return &Error{http.StatusForbidden, CodeInvalid, "permission denied (the file belongs to someone else or is read-only)"}
	}
	return &Error{http.StatusInternalServerError, CodeInternal, msg}
}

// Handler serves an FS over HTTP for xcp-api. touch is called on every
// request, so the helper can exit when idle.
func Handler(f *FS, touch func()) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			e := toError(err)
			w.WriteHeader(e.Status)
			_ = json.NewEncoder(w).Encode(e)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	body := func(r *http.Request, v any) error {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
			return invalid("bad request body: %v", err)
		}
		return nil
	}
	q := func(r *http.Request, k string) string { return r.URL.Query().Get(k) }
	mux.HandleFunc("GET /v1/list", func(w http.ResponseWriter, r *http.Request) {
		dir, err := f.Stat(q(r, "path"))
		if err != nil {
			reply(w, nil, err)
			return
		}
		items, err := f.List(q(r, "path"))
		reply(w, map[string]any{"dir": dir, "items": items}, err)
	})
	mux.HandleFunc("GET /v1/stat", func(w http.ResponseWriter, r *http.Request) {
		e, err := f.Stat(q(r, "path"))
		reply(w, e, err)
	})
	mux.HandleFunc("GET /v1/download", func(w http.ResponseWriter, r *http.Request) {
		file, e, err := f.OpenRead(q(r, "path"))
		if err != nil {
			reply(w, nil, err)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Length", strconv.FormatInt(e.Size, 10))
		w.Header().Set("X-Entry-Name", url.PathEscape(e.Name))
		w.Header().Set("Last-Modified", e.ModTime.Format(http.TimeFormat))
		_, _ = io.Copy(w, file)
	})
	mux.HandleFunc("PUT /v1/upload", func(w http.ResponseWriter, r *http.Request) {
		e, err := f.Write(q(r, "path"), r.Body, q(r, "overwrite") == "1", -1)
		reply(w, e, err)
	})
	mux.HandleFunc("POST /v1/mkdir", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Path string }
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		e, err := f.Mkdir(in.Path)
		reply(w, e, err)
	})
	mux.HandleFunc("POST /v1/rename", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ From, To string }
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		e, err := f.Rename(in.From, in.To)
		reply(w, e, err)
	})
	mux.HandleFunc("POST /v1/copy", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ From, To string }
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		e, err := f.Copy(in.From, in.To)
		reply(w, e, err)
	})
	mux.HandleFunc("POST /v1/trash", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Paths []string }
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		dir, err := f.Trash(in.Paths)
		reply(w, map[string]string{"trash": dir}, err)
	})
	mux.HandleFunc("POST /v1/chmod", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Path      string
			Mode      string
			Recursive bool
		}
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		m, perr := strconv.ParseUint(in.Mode, 8, 32)
		if perr != nil {
			reply(w, nil, invalid("permissions are three octal digits, like 644"))
			return
		}
		err := f.Chmod(in.Path, fs.FileMode(m), in.Recursive)
		if err == nil {
			e, serr := f.Stat(in.Path)
			reply(w, e, serr)
			return
		}
		reply(w, nil, err)
	})
	mux.HandleFunc("POST /v1/compress", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Paths      []string
			To, Format string
		}
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		e, err := f.Compress(in.Paths, in.To, in.Format)
		reply(w, e, err)
	})
	mux.HandleFunc("POST /v1/extract", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Path, To string }
		if err := body(r, &in); err != nil {
			reply(w, nil, err)
			return
		}
		e, err := f.Extract(in.Path, in.To)
		reply(w, e, err)
	})
	mux.HandleFunc("GET /v1/search", func(w http.ResponseWriter, r *http.Request) {
		hits, more, err := f.Search(q(r, "path"), q(r, "q"))
		reply(w, map[string]any{"items": hits, "more": more}, err)
	})
	mux.HandleFunc("GET /v1/usage", func(w http.ResponseWriter, r *http.Request) {
		u, err := f.DiskUsage(q(r, "path"))
		reply(w, u, err)
	})
	mux.HandleFunc("GET /v1/text", func(w http.ResponseWriter, r *http.Request) {
		t, err := f.ReadText(q(r, "path"), q(r, "encoding"))
		reply(w, t, err)
	})
	mux.HandleFunc("PUT /v1/text", func(w http.ResponseWriter, r *http.Request) {
		var t Text
		if err := json.NewDecoder(io.LimitReader(r.Body, 4*MaxTextFile)).Decode(&t); err != nil {
			reply(w, nil, invalid("bad request body: %v", err))
			return
		}
		e, err := f.WriteText(q(r, "path"), t)
		reply(w, e, err)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		touch()
		mux.ServeHTTP(w, r)
	})
}

// Client talks to one account's xcp-userd over its socket.
type Client struct {
	hc *http.Client
}

// NewClient returns a client for the helper listening on socket.
func NewClient(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
	}
	return &Client{hc: &http.Client{Transport: tr}}
}

// Do sends a request and decodes a JSON reply into out (nil: none). The
// caller closes nothing; for downloads use Stream.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	resp, err := c.Stream(ctx, method, path, query, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Stream sends a request (in is JSON, or an io.Reader sent as is) and
// returns the successful response for the caller to read and close.
func (c *Client) Stream(ctx context.Context, method, path string, query url.Values, in any) (*http.Response, error) {
	var rd io.Reader
	switch v := in.(type) {
	case nil:
	case io.Reader:
		rd = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := "http://userd" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		e := &Error{Status: resp.StatusCode}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(e); err != nil || e.Message == "" {
			e.Code, e.Message = CodeInternal, fmt.Sprintf("file helper answered %s", resp.Status)
		}
		return nil, e
	}
	return resp, nil
}
