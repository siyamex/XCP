"""Helpers for the end-to-end tests run as root on a server where XCP is installed."""
import http.client, http.cookiejar, json, os, ssl, subprocess, sys, time, urllib.request

API = "https://127.0.0.1:2443/api/v1"
_ctx = ssl.create_default_context(cafile="/etc/xcp/ssl/panel.crt")
_failures = 0


class Session:
    """One logged-in panel user, like one browser."""

    def __init__(self):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx), urllib.request.HTTPCookieProcessor(jar))
        self.csrf = ""

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(API + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if method != "GET" and self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def login(self, username, password):
        st, res = self.call("POST", "/auth/login", {"username": username, "password": password})
        self.csrf = (res or {}).get("csrf_token", "")
        return st

    def wait_job(self, job_id):
        for _ in range(120):
            st, j = self.call("GET", f"/jobs/{job_id}")
            if j and j["status"] in ("succeeded", "failed"):
                return j
            time.sleep(0.5)
        return {"status": "timeout"}


def admin():
    """The admin session (XCP_E2E_USER / XCP_E2E_PASSWORD)."""
    s = Session()
    s.login(os.environ.get("XCP_E2E_USER", "e2etest"), os.environ.get("XCP_E2E_PASSWORD", "e2e test password 42"))
    return s


def site(host, path="/"):
    req = urllib.request.Request("http://127.0.0.1" + path, headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def raw(host, path="/"):
    """One request without following redirects: status and Location."""
    c = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, r.getheader("Location", "")


def check(ok, what, detail=""):
    global _failures
    print(("OK   " if ok else "FAIL ") + what + (f"  [{detail}]" if detail and not ok else ""))
    _failures += 0 if ok else 1


def as_user(user, path, content):
    subprocess.run(["runuser", "-u", user, "--", "tee", path], input=content.encode(), stdout=subprocess.DEVNULL, check=True)


def finish():
    print(f"\n{_failures} failure(s)")
    sys.exit(1 if _failures else 0)
