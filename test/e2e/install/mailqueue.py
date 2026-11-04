#!/usr/bin/env python3
"""End-to-end test of the admin's mail queue (ADR-0022), run as root on a
server where XCP and Postfix are installed: queued mail is listed with its
reason, can be tried again and deleted; only admins may."""
import subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "mail queue password 1234"


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "mq1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "mq1"})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "mq1", "domain": "mq1.xcp.test", "package_id": pkg, "password": PW})
wait_job(a["job_id"])
user = Session()
user.login("mq1", PW)
st, r = user.call("GET", "/server/mail/queue")
check(st == 403, "a user cannot read the queue", f"{st}")
st, r = user.call("POST", "/server/mail/queue", {"action": "delete_all"})
check(st == 403, "a user cannot empty it", f"{st}")

# Make every outgoing delivery wait, so mail stays queued.
sh("postconf", "-e", "defer_transports = smtp")
sh("postfix", "reload")
try:
    for i in range(2):
        r = sh("sendmail", "-f", "root@mq1.xcp.test", f"nobody{i}@remote.invalid", input=f"Subject: queue test {i}\n\nhello\n")
        check(r.returncode == 0, "mail is handed to Postfix", r.stderr)
    end = time.time() + 30
    items = []
    while time.time() < end:
        st, q = api("GET", "/server/mail/queue")
        items = [m for m in q["items"] if m["queue"] == "deferred" and any("remote.invalid" in r["address"] for r in m["recipients"])]
        if len(items) >= 2:
            break
        time.sleep(1)
    check(st == 200 and len(items) == 2, "both messages are in the queue", f"{st} {items}")
    if len(items) == 2:
        m = items[0]
        check(m["sender"] == "root@mq1.xcp.test" and m["size"] > 0 and m["queue"] == "deferred", "with sender, size and queue", str(m))

        st, r = api("POST", "/server/mail/queue", {"action": "delete", "ids": []})
        check(st == 400, "deleting nothing is refused", f"{st}")
        st, r = api("POST", "/server/mail/queue", {"action": "delete", "ids": ["-d ALL"]})
        check(st == 400, "an id that is not an id is refused", f"{st}")
        st, r = api("POST", "/server/mail/queue", {"action": "explode"})
        check(st == 400, "an unknown action is refused", f"{st}")

        st, r = api("POST", "/server/mail/queue", {"action": "flush", "ids": [items[0]["id"]]})
        check(st == 204, "a message can be tried again", f"{st} {r}")
        st, r = api("POST", "/server/mail/queue", {"action": "delete", "ids": [items[0]["id"]]})
        check(st == 204, "a message can be deleted", f"{st} {r}")
        st, q = api("GET", "/server/mail/queue")
        left = [x["id"] for x in q["items"]]
        check(items[0]["id"] not in left and items[1]["id"] in left, "only that one is gone", str(left))
        st, r = api("POST", "/server/mail/queue", {"action": "delete_all"})
        check(st == 204, "everything deferred can be deleted", f"{st} {r}")
        st, q = api("GET", "/server/mail/queue")
        check(not any("remote.invalid" in r["address"] for m in q["items"] for r in m["recipients"]), "the queue is empty of it")
finally:
    sh("postconf", "-X", "defer_transports")
    sh("postfix", "reload")
    sh("postsuper", "-d", "ALL", "deferred")

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "mq1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "mq1"})
        wait_job(t["job_id"])
finish()
