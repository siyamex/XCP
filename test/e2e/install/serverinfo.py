#!/usr/bin/env python3
"""End-to-end test of the admin's server pages (P1 #15, ADR-0014), run as
root on a server where XCP is installed: dashboard figures from the real
host, the service manager, the job monitor, all sessions and the sign-in
history."""
import os, subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "server test password 1234"
HOME = "/home/srv1"

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "srv1":  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "srv1"})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "srv1", "domain": "srv1.xcp.test", "package_id": pkg, "password": PW})
wait_job(a["job_id"])
user = Session()
user.login("srv1", PW)

# Only admins.
for path in ("/server/status", "/server/services", "/server/jobs", "/server/sessions", "/server/logins", "/server/services/web/log"):
    st, r = user.call("GET", path)
    check(st == 403, f"a user cannot read {path}", f"{st}")
st, r = user.call("POST", "/server/services/web/restart")
check(st == 403, "a user cannot restart a service", f"{st}")

# The accounts' disk use is measured when the agent first reports: give the account something to measure, then restart it.
with open(f"{HOME}/big.bin", "wb") as f:
    f.write(os.urandom(2 << 20))
os.chown(f"{HOME}/big.bin", os.stat(HOME).st_uid, os.stat(HOME).st_gid)
subprocess.run(["systemctl", "restart", "xcp-agent"], check=True)
time.sleep(2)

st, s = api("GET", "/server/status")
check(st == 200 and s["hostname"] and s["cores"] >= 1 and s["mem_total"] > 0 and 0 < s["mem_available"] <= s["mem_total"] and s["uptime_seconds"] > 0 and len(s["load"]) == 3,
      "the dashboard has the host's figures", str(s)[:300])
check(s["os"] and s["kernel"] and s["arch"] and s["xcp_version"], "and its operating system, kernel and version", str({k: s[k] for k in ("os", "kernel", "arch", "xcp_version")}))
check(any(d["mount"] == "/" and d["total"] > d["used"] > 0 and d["files"] > d["files_used"] > 0 for d in s["disks"]), "the root disk shows space and inodes", str(s["disks"])[:300])
check(any(n["name"] != "lo" for n in s["net"]), "network interfaces are listed", str(s["net"])[:200])
check(s["procs"] and all(p["pid"] > 0 and p["name"] and p["rss"] >= 0 for p in s["procs"]) and len(s["procs"]) <= 12, "the busiest processes are listed", str(s["procs"])[:300])
check({"apache2", "mariadb-server", "postfix", "dovecot-core", "pure-ftpd"} <= {v["package"] for v in s["versions"]}, "installed services show their versions", str([v["package"] for v in s["versions"]]))
check("queued" in s["jobs"] or "succeeded" in s["jobs"], "job counts are there", str(s["jobs"]))
mine = None
for _ in range(90):  # measured in the background
    st, s = api("GET", "/server/status")
    mine = next((x for x in s["accounts"] if x["username"] == "srv1"), None)
    if mine:
        break
    time.sleep(1)
check(mine and mine["bytes"] >= 2 << 20 and s["accounts_at"], "the account's disk use is measured", f"{mine} {s['accounts_at']} computing={s['accounts_computing']}")

# Services.
st, sv = api("GET", "/server/services")
items = {x["id"]: x for x in sv["items"]}
check(st == 200 and len(items) >= 12 and items["web"]["installed"] and items["web"]["state"] == "active" and items["web"]["unit"] == "apache2.service", "the service list shows Apache running", str(items.get("web")))
check(items["panel-api"]["protected"] and items["ssh"]["protected"] and not items["web"]["protected"], "the panel and SSH are protected")
for sid, action in (("panel-api", "stop"), ("panel-api", "restart"), ("ssh", "disable")):
    st, r = api("POST", f"/server/services/{sid}/{action}")
    check(st == 409 and r.get("code") == "protected", f"{action} of {sid} is refused", f"{st} {r}")
st, r = api("POST", "/server/services/web/explode")
check(st == 400, "an unknown action is refused", f"{st}")
st, r = api("POST", "/server/services/nope/restart")
check(st == 404, "an unknown service is a 404", f"{st}")


def unit(name, what):
    return subprocess.run(["systemctl", what, name], capture_output=True, text=True).stdout.strip()


st, r = api("POST", "/server/services/logd/stop")
check(st == 200 and r["state"] != "active" and unit("xcp-logd", "is-active") != "active", "stop a service", f"{st} {r}")
st, r = api("POST", "/server/services/logd/start")
check(st == 200 and r["state"] == "active", "start it again", f"{st} {r}")
st, r = api("POST", "/server/services/logd/restart")
check(st == 200 and r["state"] == "active", "restart it", f"{st} {r}")
st, r = api("POST", "/server/services/logd/disable")
check(st == 200 and not r["enabled"] and unit("xcp-logd", "is-enabled") == "disabled" and r["state"] == "active", "disable at boot without stopping", f"{st} {r}")
st, r = api("POST", "/server/services/logd/enable")
check(st == 200 and r["enabled"] and unit("xcp-logd", "is-enabled") == "enabled", "enable at boot", f"{st} {r}")
st, r = api("GET", "/server/services/logd/log?lines=20")
check(st == 200 and "xcp-logd" in r["text"], "the service log shows its journal", str(r)[:200])
st, r = api("GET", "/server/services/logd/log?lines=501")
check(st == 400, "too many log lines are refused", f"{st}")

# Jobs.
st, jb = api("GET", "/server/jobs?status=succeeded&kind=account.apply&limit=5")
check(st == 200 and jb["items"] and all(j["status"] == "succeeded" and j["kind"] == "account.apply" for j in jb["items"]) and len(jb["items"]) <= 5, "the job list filters by state and kind", str(jb)[:300])
st, r = api("GET", "/server/jobs?status=bogus")
check(st == 400, "a bad filter is refused", f"{st}")
st, r = api("POST", f"/server/jobs/{jb['items'][0]['id']}/cancel")
check(st == 409 and r.get("code") == "bad_state", "a finished job cannot be canceled", f"{st} {r}")
st, r = api("POST", "/server/jobs/nope/retry")
check(st == 404, "an unknown job is a 404", f"{st}")

# Sessions and sign-ins.
bad = Session()
bad.login("mallory-" + str(int(time.time())), "wrong password entirely")
st, ss = api("GET", "/server/sessions")
mine_s = [x for x in ss["items"] if x["username"] == "srv1"]
check(st == 200 and any(x["current"] and x["username"] == os.environ.get("XCP_E2E_USER", "e2etest") for x in ss["items"]) and mine_s, "all sessions are listed, mine marked", str(ss)[:300])
st, lg = api("GET", "/server/logins")
check(st == 200 and any(l["result"] == "denied" and l["reason"] == "bad_credentials" and l["username"].startswith("mallory-") for l in lg["items"])
      and any(l["username"] == "srv1" and l["result"] == "ok" for l in lg["items"]), "the sign-in history shows failures and successes", str(lg["items"][:3]))
st, r = api("DELETE", f"/server/sessions/{mine_s[0]['id']}")
check(st == 204, "an admin ends someone's session", f"{st}")
st, r = user.call("GET", "/me")
check(st == 401, "that person is signed out at once", f"{st}")
st, r = api("DELETE", f"/server/sessions/{mine_s[0]['id']}")
check(st == 404, "it is gone", f"{st}")

st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "srv1"})
wait_job(t["job_id"])
finish()
