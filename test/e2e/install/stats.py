#!/usr/bin/env python3
"""End-to-end test of bandwidth and logs (P1 #13, ADR-0012), run as root on
a server where XCP is installed: web, FTP and mail traffic of an account's
domain is counted by xcp-logd once, and its logs are shown only to it.
Takes about three minutes."""
import ftplib, io, os, smtplib, subprocess, time, urllib.request
from email.message import EmailMessage

from xcpe2e import API, Session, admin, check, finish, site

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "stats test password 1234"
DOMAIN = "stat1.xcp.test"
HOME = "/home/stat1"
MARKER = "e2e-marker-" + str(int(time.time()))

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] in ("stat1", "stat2"):  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
        wait_job(t["job_id"])
# Mail an earlier run left deferred would be counted for this run's domain of the same name.
subprocess.run(["postsuper", "-d", "ALL", "deferred"], capture_output=True, check=False)
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
ids = {}
for name in ("stat1", "stat2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": pkg, "password": PW})
    wait_job(a["job_id"])
    ids[name] = a["id"]
acct = ids["stat1"]
user = Session()
user.login("stat1", PW)


def bandwidth():
    st, b = user.call("GET", f"/accounts/{acct}/stats/bandwidth")
    return b if st == 200 else {}


def domain_bytes():
    return next((d for d in bandwidth().get("domains", []) if d["domain"] == DOMAIN), {"web": 0, "mail": 0, "ftp": 0, "total": 0})


def wait_until(cond, seconds):
    for _ in range(seconds):
        if cond():
            return True
        time.sleep(1)
    return False


b = bandwidth()
check(b.get("month") and b["total"]["total"] == 0 and b["limit_mb"] == 100 * 1024, "the user sees an empty month with the package's limit", str(b)[:300])

# Web: a 100 kB file three times, a marked 404, and a denied request for the error log.
big = os.urandom(100_000)
with open(f"{HOME}/public_html/big.bin", "wb") as f:
    f.write(big)
os.chown(f"{HOME}/public_html/big.bin", os.stat(HOME).st_uid, os.stat(HOME).st_gid)
for _ in range(3):
    st, body = site(DOMAIN, "/big.bin")
check(st == 200, "the site serves the file", str(st))
site(DOMAIN, "/" + MARKER)
site(DOMAIN, "/.htaccess")

# FTP: a 50 kB upload.
st, l = user.call("POST", f"/accounts/{acct}/ftp", {"domain_id": user.call("GET", f"/accounts/{acct}/ftp")[1]["domains"][0]["id"],
                                                     "name": "up", "password": PW})
wait_job(l["job_id"])
f = ftplib.FTP("127.0.0.1", timeout=10)
f.login("up@" + DOMAIN, PW)
f.storbinary("STOR up.bin", io.BytesIO(os.urandom(50_000)))
f.quit()

# Mail: a 20 kB message to a mailbox.
st, mail = user.call("GET", f"/accounts/{acct}/mail")
st, box = user.call("POST", f"/accounts/{acct}/mailboxes", {"domain_id": mail["domains"][0]["id"], "local": "info", "password": PW})
wait_job(box["job_id"])
msg = EmailMessage()
msg["From"], msg["To"], msg["Subject"] = "someone@example.org", "info@" + DOMAIN, "bandwidth"
msg.set_content("x" * 20_000)
with smtplib.SMTP("127.0.0.1", 25, timeout=30) as s:
    s.send_message(msg)

ok = False
for i in range(150):
    d = domain_bytes()
    if d["web"] >= 300_000 and d["ftp"] >= 50_000 and d["mail"] >= 20_000:
        ok = True
        break
    if i % 15 == 14:  # a delivery deferred by a mail server restart is retried now, not in 5 minutes
        subprocess.run(["postqueue", "-f"], check=False)
    time.sleep(1)
d = domain_bytes()
logd = subprocess.run(["journalctl", "-u", "xcp-logd", "-n", "6", "--no-pager", "-o", "cat"], capture_output=True, text=True).stdout
check(ok, "web, FTP and mail bytes are counted for the domain within two minutes", f"{d} xcp-logd: {logd!r}")
check(d["web"] < 400_000 and d["ftp"] < 60_000 and d["mail"] < 40_000, "each byte once", str(d))
b = bandwidth()
check(b["total"]["total"] == sum(x["total"] for x in b["domains"]) and b["days"] and b["days"][-1]["total"] >= d["total"],
      "the month's total and today's bar add up", str(b["days"][-1:]))

# Logs.
st, r = user.call("GET", f"/accounts/{acct}/logs/access?lines=50")
check(st == 200 and any(MARKER in line and line.startswith(DOMAIN + ":") for line in r["lines"]), "the access log shows the request", str(r)[:300])
st, r = user.call("GET", f"/accounts/{acct}/logs/access?lines=1000&q={MARKER}")
check(st == 200 and len(r["lines"]) == 1, "the search keeps only matching lines", str(r)[:300])
st, r = user.call("GET", f"/accounts/{acct}/logs/error?lines=50")
check(st == 200 and any("denied" in line for line in r["lines"]), "the error log shows the denied request", str(r)[:300])
req = urllib.request.Request(API + f"/accounts/{acct}/logs/access/download")
with user.opener.open(req) as resp:
    raw = resp.read().decode()
check(MARKER in raw and "attachment" in resp.headers.get("Content-Disposition", ""), "the whole log downloads", raw[-200:])
other = Session()
other.login("stat2", PW)
st, r = other.call("GET", f"/accounts/{acct}/logs/access")
check(st == 404, "another account cannot read the logs", f"{st}")
st, r = other.call("GET", f"/accounts/{acct}/stats/bandwidth")
check(st == 404, "another account cannot see the bandwidth", f"{st}")
fi = os.stat("/var/log/apache2/xcp")
check(oct(fi.st_mode & 0o777) == "0o750" and fi.st_gid == int(subprocess.run(["getent", "group", "adm"], capture_output=True, text=True).stdout.split(":")[2]),
      "the log folder is root:adm 0750", oct(fi.st_mode))
r = subprocess.run(["runuser", "-u", "stat2", "--", "cat", "/var/log/apache2/xcp/stat1.access.log"], capture_output=True, text=True)
check(r.returncode != 0 and MARKER not in r.stdout, "an account's user cannot read another's log from a shell", r.stdout[:100])
pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "xcp-logd"], capture_output=True, text=True).stdout.strip()
status = open(f"/proc/{pid}/status").read()
check(pid != "0" and "Uid:\t" in status and status.split("Uid:\t")[1].split()[0] != "0", "xcp-logd runs without root", status[:100])

# A restart neither repeats nor loses bytes.
before = domain_bytes()
subprocess.run(["systemctl", "restart", "xcp-logd"], check=True)
time.sleep(70)
check(domain_bytes() == before, "a restarted xcp-logd does not count again", f"{before} -> {domain_bytes()}")

for name, id_ in ids.items():
    st, t = api("POST", f"/accounts/{id_}/terminate", {"confirm": name})
    wait_job(t["job_id"])
finish()
