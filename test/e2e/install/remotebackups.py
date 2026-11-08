#!/usr/bin/env python3
"""End-to-end test of the remote backup destinations (ADR-0031), run as root
on a server where XCP is installed. The destination is a folder (standing for
a mounted disk); SFTP and S3 are covered by tests against real protocol
servers. A backup is copied there and compared byte for byte, the local
backup and the account are removed, and the copy is brought back and restored."""
import hashlib, os, shutil, stat, subprocess

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "remote backup password 1234"
DEST = "/var/backups/xcp-remote-test"


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"] == "rbk1":
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "rbk1"})
            wait_job(t["job_id"])
    st, orph = api("GET", "/server/backups")
    for o in orph.get("items", []):
        if o["username"] == "rbk1":
            api("DELETE", f"/backups/{o['id']}")
    st, ds = api("GET", "/server/backup-destinations")
    for d in ds["items"]:
        if d["name"].startswith("E2E"):
            api("PUT", "/server/backups/schedule", {"enabled": False, "frequency": "daily", "hour": 2, "weekday": 0, "day": 1, "keep": 7, "destination_id": "", "remote_keep": 0})
            api("DELETE", f"/server/backup-destinations/{d['id']}")
    shutil.rmtree(DEST, ignore_errors=True)
    shutil.rmtree("/var/backups/xcp/rbk1", ignore_errors=True)


clean()
os.makedirs(DEST, mode=0o755)

# Only admins.
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "rbk1", "domain": "rbk1.xcp.test", "package_id": pkg, "password": PW})
wait_job(a["job_id"])
acct = a["id"]
user = Session()
user.login("rbk1", PW)
for method, path, body in (("GET", "/server/backup-destinations", None), ("POST", "/server/backup-destinations", {"name": "x", "kind": "folder", "path": DEST})):
    st, _ = user.call(method, path, body)
    check(st == 403, f"a user cannot {method} {path}", f"{st}")

# Add destinations: bad ones are refused, the good one is tested.
for bad in (
    {"name": "E2E bad", "kind": "folder", "path": "relative/path"},
    {"name": "E2E bad", "kind": "folder", "path": "/etc/xcp"},
    {"name": "E2E bad", "kind": "folder", "path": "/nonexistent/folder"},
    {"name": "E2E bad", "kind": "ftp"},
    {"name": "E2E bad", "kind": "s3", "bucket": "X", "access_key": "abc", "secret_key": "s"},
):
    st, r = api("POST", "/server/backup-destinations", bad)
    check(st == 400, f"a bad destination is refused {bad.get('path') or bad.get('kind')}", f"{st} {r}")
st, d = api("POST", "/server/backup-destinations", {"name": "E2E folder", "kind": "folder", "path": DEST})
check(st == 201 and d["kind"] == "folder", "a folder destination is added", f"{st} {d}")
st, again = api("POST", "/server/backup-destinations", {"name": "E2E folder", "kind": "folder", "path": DEST})
check(st == 409, "the same name twice is refused", f"{st}")
st, _ = api("POST", f"/server/backup-destinations/{d['id']}/test")
check(st == 204, "it can be tested again", f"{st}")

# A backup, copied.
st, b = user.call("POST", f"/accounts/{acct}/backups")
check(st == 202, "a backup is made", f"{st} {b}")
wait_job(b["job_id"])
st, o = user.call("GET", f"/accounts/{acct}/backups")
bk = o["backups"][0]
check(bk["status"] == "ok" and "remote" not in bk, "it is made, and the user sees no remote copies", str(bk))
st, _ = user.call("POST", f"/backups/{bk['id']}/upload", {"destination_id": d["id"]})
check(st == 403, "a user cannot copy it to a destination", f"{st}")
st, r = api("POST", f"/backups/{bk['id']}/upload", {"destination_id": d["id"]})
check(st == 202, "an admin copies it", f"{st} {r}")
wait_job(r["job_id"])
copy = f"{DEST}/rbk1/{bk['file']}"
local = f"/var/backups/xcp/rbk1/{bk['file']}"
check(os.path.exists(copy), "the copy is at the destination", copy)
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
check(os.path.exists(copy) and sha(copy) == sha(local), "byte for byte the same")
check(stat.S_IMODE(os.stat(copy).st_mode) == 0o600 and stat.S_IMODE(os.stat(f"{DEST}/rbk1").st_mode) == 0o700, "private to root at the destination")
check(not [f for f in os.listdir(f"{DEST}/rbk1") if f.endswith(".part")], "no half-written file is left")
st, ao = api("GET", f"/accounts/{acct}/backups")
rc = ao["backups"][0].get("remote", [])
check(len(rc) == 1 and rc[0]["status"] == "ok" and rc[0]["destination"] == "E2E folder" and rc[0]["size"] == bk["size"], "the admin sees where it is copied", str(rc))

# What the destination holds.
st, fl = api("GET", f"/server/backup-destinations/{d['id']}/files")
check(st == 200 and len(fl["items"]) == 1 and fl["items"][0]["on_server"] and fl["items"][0]["file"] == bk["file"], "the destination lists it", f"{st} {fl}")
st, _ = api("GET", f"/server/backup-destinations/{d['id']}/files?username=../x")
check(st == 400, "a bad account name is refused", f"{st}")

# The schedule names it; it cannot be forgotten then.
sched = {"enabled": False, "frequency": "daily", "hour": 2, "weekday": 0, "day": 1, "keep": 7, "destination_id": d["id"], "remote_keep": 2}
st, r = api("PUT", "/server/backups/schedule", sched)
check(st == 200 and r["destination_id"] == d["id"] and r["remote_keep"] == 2, "the schedule sends copies there", f"{st} {r}")
st, _ = api("DELETE", f"/server/backup-destinations/{d['id']}")
check(st == 409, "a destination in the schedule cannot be forgotten", f"{st}")
st, _ = api("PUT", "/server/backups/schedule", {**sched, "destination_id": "nope"})
check(st == 400, "an unknown destination in the schedule is refused", f"{st}")

# Disaster: the account and its local backups are gone; the copy brings it back.
st, t = api("POST", f"/accounts/{acct}/terminate", {"confirm": "rbk1"})
wait_job(t["job_id"])
st, orph = api("GET", "/server/backups")
mine = [x for x in orph.get("items", []) if x["username"] == "rbk1"]
check(len(mine) == 1 and mine[0]["remote"] and mine[0]["remote"][0]["status"] == "ok", "the backup of the removed account shows its copy", str(mine))
st, _ = api("DELETE", f"/backups/{mine[0]['id']}")
check(st == 204, "the local backup is deleted", f"{st}")
check(os.path.exists(copy) and not os.path.exists(local), "only the copy is left")
st, fl = api("GET", f"/server/backup-destinations/{d['id']}/files")
check(len(fl["items"]) == 1 and not fl["items"][0]["on_server"], "the destination says this server does not have it", str(fl))
for bad in ({"username": "rbk1", "file": "../../etc/passwd"}, {"username": "../x", "file": bk["file"]}, {"username": "rbk1", "file": "rbk1-1.tar.zst"}):
    st, _ = api("POST", f"/server/backup-destinations/{d['id']}/fetch", bad)
    check(st == 400, f"a bad fetch is refused {bad['file']}", f"{st}")
st, r = api("POST", f"/server/backup-destinations/{d['id']}/fetch", {"username": "rbk1", "file": bk["file"]})
check(st == 202, "the copy is fetched", f"{st} {r}")
wait_job(r["job_id"])
check(os.path.exists(local) and sha(local) == sha(copy), "it is back, byte for byte")
check(stat.S_IMODE(os.stat(local).st_mode) == 0o600, "private to root again")
st, r = api("POST", f"/server/backup-destinations/{d['id']}/fetch", {"username": "rbk1", "file": bk["file"]})
check(st == 409, "fetching what is here is refused", f"{st}")
st, orph = api("GET", "/server/backups")
mine = [x for x in orph.get("items", []) if x["username"] == "rbk1"]
check(len(mine) == 1, "it is listed with the backups of removed accounts", str(mine))
st, rs = api("POST", f"/server/backups/{mine[0]['id']}/restore", {})
check(st == 202, "and the account is restored from it", f"{st} {rs}")
if st == 202:
    j = wait_job(rs["job_id"])
    st, accts = api("GET", "/accounts")
    check(any(x["username"] == "rbk1" for x in accts["items"]), "the account exists again")

clean()
finish()
