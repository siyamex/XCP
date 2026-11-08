package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestCheckRemote(t *testing.T) {
	good := []RemoteSpec{
		{Kind: RemoteFolder, Path: "/mnt/backup"},
		{Kind: RemoteSFTP, Host: "backup.example.com", Port: 22, User: "xcp", Path: "backups/xcp", Password: "x"},
		{Kind: RemoteSFTP, Host: "192.0.2.5", Port: 2222, User: "xcp", PrivateKey: "-----BEGIN-----", HostKey: "SHA256:" + strings.Repeat("A", 43)},
		{Kind: RemoteS3, Bucket: "my-backups", Region: "eu-west-1", AccessKey: "AKIA123", SecretKey: "s", Path: "xcp"},
		{Kind: RemoteS3, Endpoint: "minio.example.com:9000", Bucket: "bkt", AccessKey: "abc", SecretKey: "s", UseTLS: true},
	}
	for i, s := range good {
		if err := CheckRemote(s); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}
	bad := map[string]RemoteSpec{
		"unknown kind":    {Kind: "ftp"},
		"relative folder": {Kind: RemoteFolder, Path: "mnt/backup"},
		"root":            {Kind: RemoteFolder, Path: "/"},
		"dotdot":          {Kind: RemoteFolder, Path: "/mnt/../etc"},
		"system folder":   {Kind: RemoteFolder, Path: "/etc/xcp"},
		"sftp host":       {Kind: RemoteSFTP, Host: "a b", Port: 22, User: "x", Password: "x"},
		"sftp port":       {Kind: RemoteSFTP, Host: "h.example", Port: 0, User: "x", Password: "x"},
		"sftp user":       {Kind: RemoteSFTP, Host: "h.example", Port: 22, User: "x;y", Password: "x"},
		"sftp no secret":  {Kind: RemoteSFTP, Host: "h.example", Port: 22, User: "x"},
		"sftp path":       {Kind: RemoteSFTP, Host: "h.example", Port: 22, User: "x", Password: "x", Path: "../up"},
		"sftp hostkey":    {Kind: RemoteSFTP, Host: "h.example", Port: 22, User: "x", Password: "x", HostKey: "md5:abc"},
		"s3 bucket":       {Kind: RemoteS3, Bucket: "UPPER", AccessKey: "abc", SecretKey: "s"},
		"s3 endpoint":     {Kind: RemoteS3, Endpoint: "bad host", Bucket: "bkt", AccessKey: "abc", SecretKey: "s"},
		"s3 no secret":    {Kind: RemoteS3, Bucket: "bkt", AccessKey: "abc"},
		"s3 prefix":       {Kind: RemoteS3, Bucket: "bkt", AccessKey: "abc", SecretKey: "s", Path: "a/../b"},
	}
	for name, s := range bad {
		if CheckRemote(s) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// remoteWith returns a Remote whose local backups are in dir.
func remoteWith(t *testing.T, accounts map[string]map[string]string) *Remote {
	t.Helper()
	dir := t.TempDir()
	for acct, files := range accounts {
		if err := os.MkdirAll(filepath.Join(dir, acct), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, acct, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &Remote{Backups: &Backups{Dir: dir}}
}

const (
	fileA = "alice-20260101T020000Z.tar.zst"
	fileB = "alice-20260102T020000Z.tar.zst"
)

func runCycle(t *testing.T, r *Remote, spec RemoteSpec) {
	t.Helper()
	ctx := context.Background()
	if _, err := r.Test(ctx, spec); err != nil {
		t.Fatalf("test: %v", err)
	}
	n, err := r.Upload(ctx, spec, "alice", fileA)
	if err != nil || n != int64(len("first backup")) {
		t.Fatalf("upload: %d %v", n, err)
	}
	if _, err := r.Upload(ctx, spec, "alice", fileB); err != nil {
		t.Fatal(err)
	}
	objs, err := r.List(ctx, spec, "alice")
	if err != nil || len(objs) != 2 || objs[0].File != fileA || objs[1].Size != int64(len("second backup")) {
		t.Fatalf("list: %+v %v", objs, err)
	}
	all, err := r.List(ctx, spec, "")
	if err != nil || len(all) != 2 || all[0].Account != "alice" {
		t.Fatalf("list all: %+v %v", all, err)
	}
	if err := r.Delete(ctx, spec, "alice", fileA); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, spec, "alice", fileA); err != nil {
		t.Errorf("deleting twice: %v", err)
	}
	if objs, _ := r.List(ctx, spec, "alice"); len(objs) != 1 || objs[0].File != fileB {
		t.Errorf("after delete: %+v", objs)
	}
	// Fetch back into a second server's folder, and refuse to overwrite.
	r2 := &Remote{Backups: &Backups{Dir: t.TempDir()}}
	if n, err := r2.Fetch(ctx, spec, "alice", fileB); err != nil || n != int64(len("second backup")) {
		t.Fatalf("fetch: %d %v", n, err)
	}
	got, _ := os.ReadFile(filepath.Join(r2.Backups.Dir, "alice", fileB))
	if string(got) != "second backup" {
		t.Errorf("fetched %q", got)
	}
	if _, err := r2.Fetch(ctx, spec, "alice", fileB); err == nil {
		t.Error("a fetch replaced a backup that is there")
	}
	fi, _ := os.Stat(filepath.Join(r2.Backups.Dir, "alice", fileB))
	if fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("fetched file mode %v", fi.Mode())
	}
	// Names that are not backups never reach a destination.
	for _, f := range []string{"../x", "alice.tar", "alice-1.tar.zst", fileA + "/../x"} {
		if _, err := r.Upload(ctx, spec, "alice", f); err == nil {
			t.Errorf("upload of %q accepted", f)
		}
	}
	if _, err := r.Upload(ctx, spec, "../bob", fileA); err == nil {
		t.Error("upload for a bad account name accepted")
	}
}

func TestRemoteFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("folders are Unix paths")
	}
	r := remoteWith(t, map[string]map[string]string{"alice": {fileA: "first backup", fileB: "second backup"}})
	runCycle(t, r, RemoteSpec{Kind: RemoteFolder, Path: t.TempDir()})
	// A folder that is not there.
	if _, err := r.Test(context.Background(), RemoteSpec{Kind: RemoteFolder, Path: "/nonexistent/folder/xcp"}); err == nil {
		t.Error("a missing folder passed the test")
	}
}

// ---- an SFTP server in the test ----

type fakeSFTP struct {
	addr    string
	hostKey string
	root    string
}

func startSFTP(t *testing.T, user, password string) *fakeSFTP {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == user && string(pw) == password {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no TCP here:", err)
	}
	t.Cleanup(func() { l.Close() })
	root := t.TempDir()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						for rq := range creqs {
							ok := rq.Type == "subsystem" && strings.HasSuffix(string(rq.Payload), "sftp")
							_ = rq.Reply(ok, nil)
							if ok {
								srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(root))
								if err == nil {
									_ = srv.Serve()
								}
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return &fakeSFTP{addr: l.Addr().String(), hostKey: fingerprint(signer.PublicKey()), root: root}
}

func TestRemoteSFTP(t *testing.T) {
	srv := startSFTP(t, "xcp", "pw-123456")
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)
	r := remoteWith(t, map[string]map[string]string{"alice": {fileA: "first backup", fileB: "second backup"}})
	spec := RemoteSpec{Kind: RemoteSFTP, Host: host, Port: port, User: "xcp", Password: "pw-123456", Path: "backups"}

	// Without a host key the test only learns it.
	res, err := r.Test(context.Background(), spec)
	if err != nil || res.HostKey != srv.hostKey {
		t.Fatalf("learning the key: %+v %v (want %s)", res, err, srv.hostKey)
	}
	spec.HostKey = srv.hostKey
	runCycle(t, r, spec)
	if _, err := os.Stat(filepath.Join(srv.root, "backups", "alice", fileB)); err != nil {
		t.Errorf("the file is not under the server's folder: %v", err)
	}
	// A different key is refused; a wrong password too.
	wrong := spec
	wrong.HostKey = "SHA256:" + strings.Repeat("B", 43)
	if _, err := r.Test(context.Background(), wrong); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Errorf("a changed host key was accepted: %v", err)
	}
	badpw := spec
	badpw.Password = "nope"
	if _, err := r.Test(context.Background(), badpw); err == nil {
		t.Error("a wrong password was accepted")
	}
}

// ---- a small S3 ----

type fakeS3 struct {
	mu    sync.Mutex
	files map[string][]byte // bucket/key
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")
	if bucket != "bkt" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code></Error>`))
		return
	}
	switch {
	case key == "" && r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case key == "" && r.Method == http.MethodGet:
		prefix := r.URL.Query().Get("prefix")
		type obj struct {
			Key          string
			Size         int
			LastModified string
		}
		var objs []obj
		var keys []string
		for k := range f.files {
			if rest, ok := strings.CutPrefix(k, "bkt/"); ok && strings.HasPrefix(rest, prefix) {
				keys = append(keys, rest)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			objs = append(objs, obj{Key: k, Size: len(f.files["bkt/"+k]), LastModified: time.Now().UTC().Format("2006-01-02T15:04:05.000Z")})
		}
		out := struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			Name        string
			Prefix      string
			KeyCount    int
			IsTruncated bool
			Contents    []obj
		}{Name: "bkt", Prefix: prefix, KeyCount: len(objs), Contents: objs}
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			b = decodeAWSChunks(b)
		}
		f.files["bkt/"+key] = b
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		b, ok := f.files["bkt/"+key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", `"abc"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	case r.Method == http.MethodDelete:
		delete(f.files, "bkt/"+key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestRemoteS3(t *testing.T) {
	fake := &fakeS3{files: map[string][]byte{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	r := remoteWith(t, map[string]map[string]string{"alice": {fileA: "first backup", fileB: "second backup"}})
	spec := RemoteSpec{Kind: RemoteS3, Endpoint: strings.TrimPrefix(srv.URL, "http://"), Region: "us-east-1", Bucket: "bkt", AccessKey: "AKIATEST", SecretKey: "secret", Path: "xcp"}
	runCycle(t, r, spec)
	// The keys are prefix/account/file.
	if _, ok := fake.files["bkt/xcp/alice/"+fileB]; !ok {
		var ks []string
		for k := range fake.files {
			ks = append(ks, k)
		}
		t.Errorf("keys: %v", ks)
	}
	missing := spec
	missing.Bucket = "other"
	if _, err := r.Test(context.Background(), missing); err == nil {
		t.Error("a missing bucket passed the test")
	}
}

// decodeAWSChunks undoes the framing of aws-chunked uploads: each chunk is
// "<hex size>;chunk-signature=...", a line break, the data and a line break;
// the last chunk is empty.
func decodeAWSChunks(b []byte) []byte {
	var out []byte
	crlf := []byte("\r\n")
	for len(b) > 0 {
		line, rest, ok := bytes.Cut(b, crlf)
		if !ok {
			break
		}
		sizeHex, _, _ := strings.Cut(string(line), ";")
		n, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil || n == 0 || int(n) > len(rest) {
			break
		}
		out = append(out, rest[:n]...)
		b = rest[min(int(n)+2, len(rest)):]
	}
	return out
}
