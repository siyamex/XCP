#!/usr/bin/env python3
"""End-to-end test of the file manager (P1 #10, ADR-0009), run as root on a
server where XCP is installed: every operation through the panel, done by
xcp-userd as the account's user in its slice, never leaving the home."""
import io, json, os, pwd, subprocess, time, urllib.error, urllib.parse, urllib.request, zipfile

from xcpe2e import API, Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "files test password 1234"
HOME = "/home/files1"


def raw(session, method, path, body=None, ctype="application/octet-stream"):
    """A request with a raw body; returns (status, bytes)."""
    req = urllib.request.Request(API + path, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", ctype)
    if method != "GET":
        req.add_header("X-CSRF-Token", session.csrf)
    try:
        with session.opener.open(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def q(**kw):
    return "?" + urllib.parse.urlencode(kw)


st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] in ("files1", "files2"):  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
ids = {}
for name in ("files1", "files2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": pkg, "password": PW})
    wait_job(a["job_id"])
    ids[name] = a["id"]
acct = ids["files1"]
F = f"/accounts/{acct}/files"
user = Session()
user.login("files1", PW)

st, ls = user.call("GET", F)
check(st == 200 and "public_html" in [e["name"] for e in ls["items"]], "the user lists the home folder", f"{st} {ls}")
st, body = raw(user, "PUT", F + "/upload" + q(path="public_html/hello.txt"), b"hello from the file manager\n")
check(st == 200, "upload a file", f"{st} {body[:200]}")
owner = pwd.getpwuid(os.stat(f"{HOME}/public_html/hello.txt").st_uid).pw_name
check(owner == "files1", "the file belongs to the account's user, not root", owner)
st, body = raw(user, "GET", F + "/download" + q(path="public_html/hello.txt"))
check(st == 200 and body == b"hello from the file manager\n", "download it", f"{st} {body[:100]}")
st, body = raw(user, "PUT", F + "/upload" + q(path="deep/new/folder/x.bin"), os.urandom(3 << 20))
check(st == 200 and os.path.getsize(f"{HOME}/deep/new/folder/x.bin") == 3 << 20, "a 3 MB upload into new folders", f"{st}")

st, r = user.call("PUT", F + "/text" + q(path="public_html/.htaccess"), {"content": "Options -Indexes\n# café\n", "encoding": "iso-8859-1"})
check(st == 200 and open(f"{HOME}/public_html/.htaccess", "rb").read() == b"Options -Indexes\n# caf\xe9\n", "save text in Latin-1", f"{st} {r}")
st, t = user.call("GET", F + "/text" + q(path="public_html/.htaccess"))
check(st == 200 and t["content"].endswith("café\n") and t["encoding"] == "windows-1252", "open it again, encoding guessed", str(t))

for opname, body, what in [
    ("mkdir", {"path": "projects/site"}, "make a folder"),
    ("copy", {"from": "public_html", "to": "projects/site/backup"}, "copy a folder"),
    ("rename", {"from": "projects/site/backup/hello.txt", "to": "projects/hello.txt"}, "move a file"),
    ("chmod", {"path": "projects/hello.txt", "mode": "600"}, "change permissions"),
    ("compress", {"paths": ["projects/site"], "to": "site.zip", "format": "zip"}, "compress to zip"),
    ("extract", {"path": "site.zip", "to": "unpacked"}, "extract it"),
]:
    st, r = user.call("POST", F + "/" + opname, body)
    check(st == 200, what, f"{st} {r}")
check(oct(os.stat(f"{HOME}/projects/hello.txt").st_mode & 0o777) == "0o600", "the permissions are set")
check(os.path.isfile(f"{HOME}/unpacked/site/backup/.htaccess"), "the archive round trip keeps the files")
st, r = user.call("POST", F + "/trash", {"paths": ["unpacked"]})
check(st == 200 and r["trash"].startswith(".trash/") and os.path.isdir(f"{HOME}/{r['trash']}/unpacked"), "delete moves to ~/.trash", str(r))
# The trash (ADR-0032): listed with where things were, put back, never over something, emptied.
st, tl = user.call("GET", F + "/trash")
batch = next((b for b in tl.get("batches", []) if any(i["name"] == "unpacked" for i in b["items"])), None)
check(st == 200 and batch is not None and batch["items"][0]["origin"] == "unpacked" and batch["items"][0]["type"] == "dir", "the trash lists what was deleted and where it was", str(tl)[:300])
st, r = user.call("POST", F + "/mkdir", {"path": "unpacked"})
st, r = user.call("POST", F + "/trash-restore", {"id": batch["id"]})
check(st == 200 and r["conflicts"] == ["unpacked"] and r["restored"] == [], "putting back never replaces what is there", str(r))
subprocess.run(["runuser", "-u", "files1", "--", "rmdir", f"{HOME}/unpacked"], check=True)
st, r = user.call("POST", F + "/trash-restore", {"id": batch["id"], "names": ["unpacked"]})
check(st == 200 and r["restored"] == ["unpacked"] and os.path.isfile(f"{HOME}/unpacked/site/backup/.htaccess"), "it goes back where it was", str(r))
st, tl = user.call("GET", F + "/trash")
check(not any(b["id"] == batch["id"] for b in tl["batches"]), "and leaves the trash")
for bad in ({"id": "../x"}, {"id": ""}, {"id": "20261101-120000"}):
    st, r = user.call("POST", F + "/trash-restore", bad)
    check(st == 400, f"a bad batch is refused {bad}", f"{st}")
st, r = user.call("POST", F + "/trash-empty", {"ids": ["../../etc"]})
check(st == 400, "so is emptying one", f"{st}")
st, r = user.call("POST", F + "/trash", {"paths": ["unpacked"]})
st, r = user.call("POST", F + "/trash-empty", {})
check(st == 200 and r["emptied"] >= 1 and not os.listdir(f"{HOME}/.trash"), "emptying removes everything for good", str(r))
check(os.path.isdir(f"{HOME}/projects") and os.path.isdir(f"{HOME}/public_html"), "and nothing outside the trash")
st, r = user.call("GET", F + "/search" + q(q="HELLO"))
check(st == 200 and [e["path"] for e in r["items"]] == ["projects/hello.txt", "public_html/hello.txt"] or
      sorted(e["path"] for e in r["items"]) == ["projects/hello.txt", "public_html/hello.txt"], "search finds by name", str(r)[:300])
st, u = user.call("GET", F + "/usage")
check(st == 200 and u["children"][0]["name"] == "deep" and u["largest"][0]["path"] == "deep/new/folder/x.bin", "disk usage shows the largest", str(u)[:300])

# Never leaving the home.
st, r = user.call("GET", F + q(path="../files2"))
check(st == 400, "a path leaving the home is refused", f"{st} {r}")
subprocess.run(["runuser", "-u", "files1", "--", "ln", "-s", "/etc/shadow", f"{HOME}/public_html/shadow"], check=True)
st, body = raw(user, "GET", F + "/download" + q(path="public_html/shadow"))
check(st == 400 and b"root:" not in body, "the user's own link to /etc/shadow is not followed", f"{st} {body[:120]}")
evil = io.BytesIO()
with zipfile.ZipFile(evil, "w") as z:
    z.writestr("../../../tmp/evil.txt", "x")
raw(user, "PUT", F + "/upload" + q(path="evil.zip"), evil.getvalue())
st, r = user.call("POST", F + "/extract", {"path": "evil.zip", "to": "evil"})
check(st == 400 and not os.path.exists("/tmp/evil.txt") and not os.path.exists(f"{HOME}/evil"), "an archive leaving its folder is refused", f"{st} {r}")

# Who does the work.
helper = subprocess.run(["systemctl", "show", "-p", "MainPID", "-p", "Slice", "-p", "User", "xcp-userd@files1.service"], capture_output=True, text=True).stdout
pid = dict(l.split("=", 1) for l in helper.split())["MainPID"]
check(pid != "0" and pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name == "files1" and "Slice=xcp-u-files1.slice" in helper,
      "xcp-userd runs as the account's user in its slice", helper)
st, r = Session().call("GET", F)
other = Session()
other.login("files2", PW)
st, r = other.call("GET", F)
check(st == 404, "another account cannot reach the files", f"{st} {r}")

subprocess.run(["systemctl", "restart", "xcp-agent"], check=True)
time.sleep(2)
st, r = user.call("GET", F)
check(st == 200, "the files stay reachable after xcp-agent restarts", f"{st} {r}")

st, a = api("POST", f"/accounts/{acct}/suspend", {"reason": "e2e"})
wait_job(a["job_id"])
st, r = api("GET", F)
active = subprocess.run(["systemctl", "is-active", "xcp-userd@files1.socket"], capture_output=True, text=True).stdout.strip()
check(st == 409 and active != "active", "suspension stops the helper and the file manager", f"{st} {active}")
st, a = api("POST", f"/accounts/{acct}/unsuspend")
wait_job(a["job_id"])
st, r = api("GET", F + q(path="projects"))
check(st == 200, "after unsuspending the helper starts again on demand", f"{st} {r}")

for name, id_ in ids.items():
    st, t = api("POST", f"/accounts/{id_}/terminate", {"confirm": name})
    wait_job(t["job_id"])
finish()
