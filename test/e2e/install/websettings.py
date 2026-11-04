#!/usr/bin/env python3
"""End-to-end test of the per-domain web settings (ADR-0020), run as root on
a server where XCP is installed: error pages, hotlink protection, the IP
blocker, compression and browser caching reach Apache and work."""
import http.client, os, subprocess, time

from xcpe2e import Session, admin, as_user, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "web settings password 1234"
HOST = "ws1.xcp.test"
HOME = "/home/ws1"


def get(path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
    c.request("GET", path, headers={"Host": HOST, **(headers or {})})
    r = c.getresponse()
    body = r.read()
    out = (r.status, {k.lower(): v for k, v in r.getheaders()}, body)
    c.close()
    return out


st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "ws1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "ws1"})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "ws1", "domain": HOST, "package_id": pkg, "password": PW})
wait_job(a["job_id"])
acct = a["id"]
user = Session()
user.login("ws1", PW)
st, dm = user.call("GET", f"/accounts/{acct}/domains")
dom = dm["items"][0]["id"]

root = f"{HOME}/public_html"
as_user("ws1", f"{root}/index.html", "<p>home</p>")
os.makedirs(f"{root}/errors", exist_ok=True)
as_user("ws1", f"{root}/errors/404.html", "<p>custom not found</p>")
as_user("ws1", f"{root}/pic.jpg", "not really a jpeg")
as_user("ws1", f"{root}/style.css", "body { color: red }\n" * 200)
subprocess.run(["chown", "-R", "ws1:ws1", f"{root}"], check=True)

# Defaults.
st, w = user.call("GET", f"/domains/{dom}/web")
check(st == 200 and not w["compress"] and w["blocked"] == [], "a domain starts without web settings", f"{st} {w}")
st, body = get("/missing")[0], get("/missing")[2]
check(st == 404 and b"custom not found" not in body, "the default 404 page", f"{st}")

# Bad input is refused.
for bad in (
    {"error_pages": {"404": "../../etc/passwd"}},
    {"error_pages": {"418": "/x.html"}},
    {"blocked": ["not-an-address"]},
    {"blocked": ["0.0.0.0/0"]},
    {"hotlink": {"enabled": True, "hosts": [], "extensions": [], "allow_empty": False}},
    {"cache_rules": [{"extensions": ["css"], "days": 0}]},
):
    base = {"error_pages": {}, "hotlink": {"enabled": False, "hosts": [], "extensions": [], "allow_empty": False}, "blocked": [], "compress": False, "cache_rules": []}
    st, r = user.call("PUT", f"/domains/{dom}/web", {**base, **bad})
    check(st == 400, "bad web settings are refused", f"{st} {r}")

# Apply everything.
cfg = {
    "error_pages": {"404": "/errors/404.html"},
    "hotlink": {"enabled": True, "hosts": ["partner.example"], "extensions": ["jpg", "png"], "allow_empty": True},
    "blocked": [],
    "compress": True,
    "cache_rules": [{"extensions": ["css"], "days": 7}],
}
st, r = user.call("PUT", f"/domains/{dom}/web", cfg)
check(st == 202, "the settings are saved", f"{st} {r}")
wait_job(r["job_id"])
st, w = user.call("GET", f"/domains/{dom}/web")
check(w["error_pages"] == {"404": "/errors/404.html"} and w["hotlink"]["hosts"] == ["partner.example"], "they read back", f"{w}")

st, hdr, body = get("/missing")
check(st == 404 and b"custom not found" in body, "the custom 404 page is served", f"{st} {body[:80]}")

st, hdr, body = get("/pic.jpg", {"Referer": "http://evil.example/page"})
check(st == 403, "another site cannot embed the picture", f"{st}")
st, hdr, body = get("/pic.jpg", {"Referer": f"http://{HOST}/page"})
check(st == 200, "the site itself can", f"{st}")
st, hdr, body = get("/pic.jpg", {"Referer": "https://cdn.partner.example/x"})
check(st == 200, "an allowed partner can", f"{st}")
st, hdr, body = get("/pic.jpg")
check(st == 200, "a visit without referrer passes when allowed", f"{st}")
st, hdr, body = get("/index.html", {"Referer": "http://evil.example/"})
check(st == 200, "other file types are not protected", f"{st}")

st, hdr, body = get("/style.css", {"Accept-Encoding": "gzip"})
check(hdr.get("content-encoding") == "gzip", "text is compressed", str(hdr))
check("expires" in hdr or "max-age=604800" in hdr.get("cache-control", ""), "css gets browser caching for 7 days", str(hdr))

# The IP blocker.
st, r = user.call("PUT", f"/domains/{dom}/web", {**cfg, "blocked": ["127.0.0.1"]})
wait_job(r["job_id"])
st, hdr, body = get("/index.html")
check(st == 403, "a blocked address gets 403", f"{st}")
st, r = user.call("PUT", f"/domains/{dom}/web", {**cfg, "blocked": ["203.0.113.0/24"]})
wait_job(r["job_id"])
st, hdr, body = get("/index.html")
check(st == 200, "other addresses are not blocked", f"{st}")

# Directory privacy (ADR-0025).
import base64, grp, stat
os.makedirs(f"{root}/private", exist_ok=True)
as_user("ws1", f"{root}/private/secret.html", "<p>secret</p>")
subprocess.run(["chown", "-R", "ws1:ws1", f"{root}/private"], check=True)
def basic(u, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{pw}".encode()).decode()}
st, r = user.call("PUT", f"/domains/{dom}/protected-dirs", {"dirs": [{"path": "/private", "realm": "Staff only", "users": [{"name": "amy", "password": "a long enough password"}]}]})
check(st == 202, "a protected folder is saved", f"{st} {r}")
wait_job(r["job_id"])
check("hash" not in str(r), "the API never shows hashes", str(r)[:200])
st, hdr, body = get("/private/secret.html")
check(st == 401 and "Staff only" in hdr.get("www-authenticate", ""), "the folder asks for a password", f"{st} {hdr.get('www-authenticate')}")
st, hdr, body = get("/private/secret.html", basic("amy", "a long enough password"))
check(st == 200 and b"secret" in body, "the right password opens it", f"{st}")
st, hdr, body = get("/private/secret.html", basic("amy", "wrong password at all"))
check(st == 401, "a wrong password does not", f"{st}")
st, hdr, body = get("/index.html")
check(st == 200, "the rest of the site is open", f"{st}")
pwdir = "/etc/xcp/webauth/ws1"
files = os.listdir(pwdir)
check(len(files) == 1, "one password file", str(files))
fst = os.stat(f"{pwdir}/{files[0]}")
check(stat.S_IMODE(fst.st_mode) == 0o640 and grp.getgrgid(fst.st_gid).gr_name == "www-data" and fst.st_uid == 0, "owned by root:www-data, 0640", oct(fst.st_mode))
check(subprocess.run(["runuser", "-u", "ws1", "--", "cat", f"{pwdir}/{files[0]}"], capture_output=True).returncode != 0, "the account's own user cannot read it")
# Changing other web settings keeps the folder; keeping a user keeps the password.
st, r = user.call("PUT", f"/domains/{dom}/web", {**cfg, "blocked": ["203.0.113.0/24"]})
wait_job(r["job_id"])
st, hdr, body = get("/private/secret.html", basic("amy", "a long enough password"))
check(st == 200, "the folder survives a change of other settings", f"{st}")
st, r = user.call("PUT", f"/domains/{dom}/protected-dirs", {"dirs": [{"path": "/private", "realm": "Staff only", "users": [{"name": "amy"}]}]})
wait_job(r["job_id"])
st, hdr, body = get("/private/secret.html", basic("amy", "a long enough password"))
check(st == 200, "a user without a new password keeps the old one", f"{st}")
st, r = user.call("PUT", f"/domains/{dom}/protected-dirs", {"dirs": [{"path": "/private", "realm": "x", "users": [{"name": "new"}]}]})
check(st == 400, "a new user needs a password", f"{st}")
st, r = user.call("PUT", f"/domains/{dom}/protected-dirs", {"dirs": [{"path": "/../etc", "realm": "x", "users": []}]})
check(st == 400, "a path outside the site is refused", f"{st}")
st, r = user.call("PUT", f"/domains/{dom}/protected-dirs", {"dirs": []})
wait_job(r["job_id"])
st, hdr, body = get("/private/secret.html")
check(st == 200, "removing the folder opens it again", f"{st}")
check(not os.path.exists(pwdir) or os.listdir(pwdir) == [], "and its password file is gone")

# One account cannot change another's domain.
st, pk = api("GET", "/packages")
st, b = api("POST", "/accounts", {"username": "ws2", "domain": "ws2.xcp.test", "package_id": pkg, "password": PW})
wait_job(b["job_id"])
other = Session()
other.login("ws2", PW)
st, r = other.call("PUT", f"/domains/{dom}/web", cfg)
check(st in (403, 404), "another account cannot change the settings", f"{st}")
st, r = other.call("GET", f"/domains/{dom}/web")
check(st in (403, 404), "or read them", f"{st}")

# Clean up.
st, existing = api("GET", "/accounts")
for x in existing["items"]:
    if x["username"] in ("ws1", "ws2"):
        st, t = api("POST", f"/accounts/{x['id']}/terminate", {"confirm": x["username"]})
        wait_job(t["job_id"])
finish()
