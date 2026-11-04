#!/usr/bin/env python3
"""End-to-end test of backups (P1 #14, ADR-0013), run as root on a server
where XCP is installed: a backup made in the panel holds the account's
files, database and settings, can be downloaded by its owner only, is
root-only on disk, and goes with the account."""
import hashlib, io, json, os, smtplib, subprocess, tarfile, time, urllib.request
from email.message import EmailMessage

from xcpe2e import API, Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "backup test password 1234"
HOME = "/home/bak1"
DIR = "/var/backups/xcp/bak1"

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] in ("bak1", "bak2"):  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
ids = {}
for name in ("bak1", "bak2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": pkg, "password": PW})
    wait_job(a["job_id"])
    ids[name] = a["id"]
acct = ids["bak1"]
user = Session()
user.login("bak1", PW)

# Something to back up: files (one the user made unreadable), a link, a database with data.
uid, gid = os.stat(HOME).st_uid, os.stat(HOME).st_gid


def as_user(*cmd):
    subprocess.run(["runuser", "-u", "bak1", "--", *cmd], check=True)


as_user("sh", "-c", f"echo '<?php echo 42;' > {HOME}/public_html/app.php; mkdir -p {HOME}/docs; echo secret > {HOME}/docs/locked.txt; "
        f"chmod 000 {HOME}/docs/locked.txt; ln -s /etc/shadow {HOME}/docs/shadow-link; head -c 300000 /dev/urandom > {HOME}/docs/blob.bin")
blob = open(f"{HOME}/docs/blob.bin", "rb").read()
st, wz = user.call("POST", f"/accounts/{acct}/database-wizard", {"database": "shop", "user": "shopper", "password": PW})
wait_job(wz["job_id"])
subprocess.run(["mariadb", "-e", "CREATE TABLE bak1_shop.items (id INT PRIMARY KEY, name VARCHAR(40)); INSERT INTO bak1_shop.items VALUES (1, 'backup-marker-row')"], check=True)
st, mb = user.call("GET", f"/accounts/{acct}/mail")
st, box = user.call("POST", f"/accounts/{acct}/mailboxes", {"domain_id": mb["domains"][0]["id"], "local": "info", "password": PW})
wait_job(box["job_id"])
msg = EmailMessage()
msg["From"], msg["To"], msg["Subject"] = "someone@example.org", "info@bak1.xcp.test", "in the backup"
msg.set_content("mail marker")
with smtplib.SMTP("127.0.0.1", 25, timeout=30) as smtp:
    smtp.send_message(msg)
for _ in range(60):  # delivered into the mailbox in the home
    if subprocess.run(["sh", "-c", f"ls {HOME}/mail/bak1.xcp.test/info/Maildir/new/* >/dev/null 2>&1"]).returncode == 0:
        break
    time.sleep(1)

st, o = user.call("GET", f"/accounts/{acct}/backups")
check(st == 200 and o["backups"] == [] and o["max_manual"] == 3 and not o["schedule"]["enabled"], "the user sees an empty backup list", f"{st} {o}")
st, b = user.call("POST", f"/accounts/{acct}/backups")
check(st == 202 and b["status"] == "running", "start a backup", f"{st} {b}")
st, again = user.call("POST", f"/accounts/{acct}/backups")
check(st == 409, "a second one while it runs is refused", f"{st} {again}")
j = wait_job(b["job_id"])
check(j["status"] == "succeeded", "the job succeeds", str(j)[:400])
st, o = user.call("GET", f"/accounts/{acct}/backups")
bk = o["backups"][0]
check(bk["status"] == "ok" and bk["size"] > 300000 and bk["file"].startswith("bak1-") and "locked.txt" in bk["detail"],
      "it is ready, and says which file it could not read", str(bk))

path = f"{DIR}/{bk['file']}"
check(oct(os.stat(DIR).st_mode & 0o777) == "0o700" and oct(os.stat(path).st_mode & 0o777) == "0o600" and os.stat(path).st_uid == 0,
      "the archive is root-only on disk")
r = subprocess.run(["runuser", "-u", "bak1", "--", "cat", path], capture_output=True, text=True)
check(r.returncode != 0, "the account's user cannot read its backups", r.stderr[:100])
check(not os.path.exists(DIR + "/.staging") and not [f for f in os.listdir(DIR) if f.endswith(".part")], "no partial files are left")

# Download, and open the archive.
req = urllib.request.Request(API + f"/backups/{bk['id']}/download")
with user.opener.open(req) as resp:
    data = resp.read()
    cd = resp.headers.get("Content-Disposition", "")
check(len(data) == bk["size"] and "attachment" in cd and data == open(path, "rb").read(),
      "the download is the whole archive", f"{len(data)} vs {bk['size']}")
tarbytes = subprocess.run(["zstd", "-dc"], input=data, capture_output=True, check=True).stdout
tf = tarfile.open(fileobj=io.BytesIO(tarbytes))
names = tf.getnames()
manifest = json.load(tf.extractfile("manifest.json"))
check(manifest["format"] == 1 and manifest["username"] == "bak1", "the manifest names format and account", str(manifest)[:200])
bad = [n for n, want in manifest["sha256"].items() if hashlib.sha256(tf.extractfile(n).read()).hexdigest() != want]
check(not bad and len(manifest["sha256"]) >= 4, "every file matches its checksum in the manifest", str(bad))
check("homedir/public_html/app.php" in names and tf.extractfile("homedir/public_html/app.php").read() == b"<?php echo 42;\n", "the home folder's files are in it")
check(tf.extractfile("homedir/docs/blob.bin").read() == blob, "a big file is intact")
check("homedir/docs/locked.txt" not in names, "a file the user cannot read is left out")
link = tf.getmember("homedir/docs/shadow-link")
check(link.issym() and link.linkname == "/etc/shadow" and not any("root:" in str(tf.extractfile(n).read()) for n in names if tf.getmember(n).isfile() and n.startswith("homedir/docs/shadow")),
      "a symlink is kept as a link, never followed")
check(any(n.startswith("homedir/mail/bak1.xcp.test/info/Maildir/new/") for n in names), "delivered mail in the home is in it")
check(all(n in ("manifest.json", "account.json", "homedir") or n.startswith(("homedir/", "mysql/")) for n in names), "nothing is outside homedir/, mysql/ and the two json files", str(names[:5]))
dump = tf.extractfile("mysql/bak1_shop.sql").read().decode()
check("backup-marker-row" in dump and "CREATE TABLE" in dump, "the database dump has its data")
acc = json.load(tf.extractfile("account.json"))
tables = acc["export"]["tables"]
check(acc["package"] == "Default" and tables["accounts"][0]["username"] == "bak1" and any(d["name"] == "bak1.xcp.test" for d in tables["domains"])
      and len(tables["mailboxes"]) == 1 and len(tables["databases"]) == 1 and len(tables["db_users"]) == 1 and tables["mailboxes"][0]["password_hash"].startswith("{ARGON2ID}"),
      "account.json holds the account, domains, mailbox and database", str(tables.keys()))
check("bak2" not in json.dumps(acc), "and nothing of another account")

# Other accounts.
other = Session()
other.login("bak2", PW)
st, r = other.call("GET", f"/accounts/{acct}/backups")
check(st == 404, "another account cannot list the backups", str(st))
try:
    other.opener.open(urllib.request.Request(API + f"/backups/{bk['id']}/download"))
    status = 200
except urllib.error.HTTPError as e:
    status = e.code
check(status == 404, "another account cannot download one", str(status))

# Limits, delete, schedule.
for _ in range(2):
    st, x = user.call("POST", f"/accounts/{acct}/backups")
    wait_job(x["job_id"])
st, x = user.call("POST", f"/accounts/{acct}/backups")
check(st == 409, "a fourth backup of its own is refused", f"{st} {x}")
st, r = user.call("DELETE", f"/backups/{bk['id']}")
check(st == 204 and not os.path.exists(path), "delete removes the file", f"{st}")
sched = {"enabled": True, "frequency": "weekly", "hour": 3, "weekday": 0, "day": 1, "keep": 4}
st, r = user.call("PUT", "/server/backups/schedule", sched)
check(st == 403, "a user cannot set the schedule", str(st))
st, r = api("PUT", "/server/backups/schedule", sched)
st2, r2 = api("GET", "/server/backups/schedule")
check(st == 200 and r2 == sched, "the admin sets the schedule", f"{st} {r2}")
api("PUT", "/server/backups/schedule", {**sched, "enabled": False})

# Backups outlive the account (ADR-0015): they are listed as the backups of removed accounts.
for name, id_ in ids.items():
    st, t = api("POST", f"/accounts/{id_}/terminate", {"confirm": name})
    wait_job(t["job_id"])
check(os.path.isdir(DIR) and len(os.listdir(DIR)) > 0, "terminating the account keeps its backups")
st, orph = api("GET", "/server/backups")
check(st == 200 and any(o["username"] == "bak1" for o in orph.get("orphans", orph.get("items", []))), "they are listed as the backups of a removed account", f"{st} {str(orph)[:200]}")
st, r = user.call("GET", "/server/backups")
check(st in (401, 403), "a user cannot list them", f"{st}")
# Clean up what this test left.
subprocess.run(["rm", "-rf", DIR], check=True)
import sqlite3
_db = sqlite3.connect("/var/lib/xcp/xcp.db")
_db.execute("DELETE FROM backups WHERE account_id IS NULL AND username LIKE 'bak%'")
_db.commit()
finish()
