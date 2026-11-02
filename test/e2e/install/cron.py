#!/usr/bin/env python3
"""End-to-end test of cron jobs (P1 #12, ADR-0011), run as root on a server
where XCP is installed: jobs made in the panel run every minute as the
account's user in its slice, report their last run, mail their output, do
not overlap and stop with the account. Takes about three minutes."""
import glob, os, pwd, subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "cron test password 1234"
HOME = "/home/cron1"
MAILDIR = f"{HOME}/mail/cron1.xcp.test/ops/Maildir"

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "cron1":  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "cron1"})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "cron1", "domain": "cron1.xcp.test", "package_id": pkg, "password": PW})
wait_job(a["job_id"])
acct = a["id"]
user = Session()
user.login("cron1", PW)
st, mail = user.call("GET", f"/accounts/{acct}/mail")
st, box = user.call("POST", f"/accounts/{acct}/mailboxes", {"domain_id": mail["domains"][0]["id"], "local": "ops", "password": PW})
wait_job(box["job_id"])


def create(command, email="", schedule="* * * * *"):
    st, j = user.call("POST", f"/accounts/{acct}/cron", {"schedule": schedule, "command": command, "email": email})
    check(st == 202 and wait_job(j["job_id"])["status"] == "succeeded", f"add the job {command[:40]}", f"{st} {j}")
    return j


def jobs():
    st, o = user.call("GET", f"/accounts/{acct}/cron")
    return {j["id"]: j for j in o["jobs"]}


def wait_until(cond, seconds):
    for _ in range(seconds):
        if cond():
            return True
        time.sleep(1)
    return False


st, o = user.call("GET", f"/accounts/{acct}/cron")
check(st == 200 and o["jobs"] == [] and o["time_zone"] != "", "the user sees the cron page", f"{st} {o}")
good = create('echo "user=$(id -un) cg=$(cat /proc/self/cgroup) home=$PWD" >> ~/cron.txt; echo hello-from-cron', email="ops@cron1.xcp.test")
bad = create("echo failing >&2; exit 3")
slow = create("sleep 100")
later = create("echo never", schedule="0 0 1 1 *")
check(len(jobs()[later["id"]]["next_runs"]) == 3, "the next runs are shown")

# The first minute.
check(wait_until(lambda: os.path.exists(f"{HOME}/cron.txt"), 75), "a job runs within a minute")
line = open(f"{HOME}/cron.txt").read()
check(pwd.getpwuid(os.stat(f"{HOME}/cron.txt").st_uid).pw_name == "cron1" and "user=cron1" in line, "it runs as the account's user", line)
check("xcp-u-cron1.slice" in line and f"home={HOME}" in line, "in the account's slice, from its home", line)
unit = f"xcp-cron-cron1-{slow['id'].lower()}.service"
active = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True).stdout.strip()
check(active == "active", "a run is a unit of its own", f"{unit}: {active}")
def finished(job_id, code):
    r = jobs()[job_id]["last_run"] or {}
    return not r.get("skipped") and r.get("exit_code") == code


check(wait_until(lambda: finished(good["id"], 0), 20), "the last run is reported", str(jobs()[good["id"]]["last_run"]))
j = jobs()
check("hello-from-cron" in j[good["id"]]["last_run"]["output"], "with its output", str(j[good["id"]]["last_run"]))
check(wait_until(lambda: finished(bad["id"], 3), 20) and "failing" in jobs()[bad["id"]]["last_run"]["output"],
      "a failing job reports its exit code and error output", str(jobs()[bad["id"]]["last_run"]))
check(jobs()[later["id"]]["last_run"] is None, "a job not due has not run")
check(wait_until(lambda: any("hello-from-cron" in open(f).read() for f in glob.glob(f"{MAILDIR}/new/*")), 30),
      "the output is mailed to the job's address")
mails = [open(f).read() for f in glob.glob(f"{MAILDIR}/new/*")]
check(any("From: Cron <cron1@" in m and "Subject: Cron <cron1> echo" in m for m in mails), "from the account's user",
      "".join(l for l in (mails[0] if mails else "no mail").splitlines(True) if l.startswith(("From:", "Subject:", "To:"))))
check(not any("failing" in m for m in mails), "a job without an address mails nothing")

# The second minute: the slow job is still going, so it is not started again.
check(wait_until(lambda: "still going" in (jobs()[slow["id"]]["last_run"] or {}).get("skipped", ""), 75),
      "a run still going is not started twice", str(jobs()[slow["id"]]["last_run"]))

# Suspension stops the running job and the schedule.
st, r = api("POST", f"/accounts/{acct}/suspend", {"reason": "e2e"})
wait_job(r["job_id"])
active = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True).stdout.strip()
check(active != "active", "suspension stops a running job", active)
lines = open(f"{HOME}/cron.txt").read().count("\n")
time.sleep(65)
check(open(f"{HOME}/cron.txt").read().count("\n") == lines, "a suspended account's jobs do not run")
st, r = api("POST", f"/accounts/{acct}/unsuspend")
wait_job(r["job_id"])
user.login("cron1", PW)  # suspension ended the user's panel session

st, r = user.call("DELETE", f"/cron/{good['id']}")
check(st == 202 and wait_job(r["job_id"])["status"] == "succeeded" and good["id"] not in jobs(), "delete a job", f"{st} {r}")

st, t = api("POST", f"/accounts/{acct}/terminate", {"confirm": "cron1"})
wait_job(t["job_id"])
check(not os.path.exists("/etc/xcp/cron/accounts/cron1.json") and not os.path.exists("/var/lib/xcp-cron/cron1.json"),
      "terminating the account removes its jobs and their runs")
finish()
