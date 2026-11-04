#!/usr/bin/env python3
"""End-to-end test of the messages to customers (ADR-0027), run as root on a
server where XCP and Postfix are installed. Outgoing delivery is held back
(defer_transports), so the mail stays in Postfix's queue, where the admin's
queue view shows what the panel sent: the welcome message of a new account
and a message to all customers."""
import subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "messages test password 1234"


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def queued(pred, secs=30):
    end = time.time() + secs
    items = []
    while time.time() < end:
        st, q = api("GET", "/server/mail/queue")
        items = [m for m in q["items"] if m["queue"] == "deferred" and pred(m)] if st == 200 else []
        if items:
            return items
        time.sleep(1)
    return items


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"].startswith("msg"):
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
            wait_job(t["job_id"])
    sh("postsuper", "-d", "ALL", "deferred")


clean()
# The ten-minute gap between messages to all customers starts over for this test.
import sqlite3
_db = sqlite3.connect("/var/lib/xcp/xcp.db")
_db.execute("DELETE FROM settings WHERE key LIKE 'messages.last_broadcast.%'")
_db.commit()
_db.close()
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]

# Only admins and resellers.
st, a0 = api("POST", "/accounts", {"username": "msg0", "domain": "msg0.xcp.test", "package_id": pkg, "password": PW})
wait_job(a0["job_id"])
user = Session()
user.login("msg0", PW)
for method, path, body in (("GET", "/messages/welcome", None), ("PUT", "/messages/welcome", {"subject": "x", "body": "y"}), ("POST", "/messages/broadcast", {"subject": "x", "body": "y"})):
    st, _ = user.call(method, path, body)
    check(st == 403, f"a customer cannot use {method} {path}", f"{st}")

# The welcome message: default, then the admin's own text.
st, t = api("GET", "/messages/welcome")
check(st == 200 and not t["custom"] and "{{domain}}" in t["subject"], "the default welcome message", str(t))
st, r = api("PUT", "/messages/welcome", {"subject": "Welcome {{username}} to the host", "body": "Sign in at {{panel_url}} as {{username}} ({{domain}})."})
check(st == 200 and r["custom"], "the admin saves its own text", f"{st} {r}")
for bad in ({"subject": "x", "body": "{{password}}"}, {"subject": "a\nBcc: evil@example.test", "body": "y"}, {"subject": "", "body": "y"}):
    st, _ = api("PUT", "/messages/welcome", bad)
    check(st == 400, "a bad message is refused", f"{st} {bad}")

# Hold outgoing mail in the queue.
sh("postconf", "-e", "defer_transports = smtp")
sh("postfix", "reload")
try:
    st, a1 = api("POST", "/accounts", {"username": "msg1", "domain": "msg1.xcp.test", "package_id": pkg, "password": PW, "email": "owner1@remote.invalid"})
    check(st in (200, 201, 202), "an account with an email address is made", f"{st} {a1}")
    wait_job(a1["job_id"])
    got = queued(lambda m: any(r["address"] == "owner1@remote.invalid" for r in m["recipients"]))
    check(len(got) == 1, "its welcome message is queued for delivery", str(got))
    st, a2 = api("POST", "/accounts", {"username": "msg2", "domain": "msg2.xcp.test", "package_id": pkg, "password": PW})
    wait_job(a2["job_id"])
    time.sleep(3)
    st, q = api("GET", "/server/mail/queue")
    check(not any("msg2" in str(m) for m in q["items"]), "an account without an address gets none", "")

    sh("postsuper", "-d", "ALL", "deferred")
    st, a3 = api("POST", "/accounts", {"username": "msg3", "domain": "msg3.xcp.test", "package_id": pkg, "password": PW, "email": "owner3@remote.invalid"})
    wait_job(a3["job_id"])
    queued(lambda m: any(r["address"] == "owner3@remote.invalid" for r in m["recipients"]))
    sh("postsuper", "-d", "ALL", "deferred")

    # A message to all customers.
    st, r = api("POST", "/messages/broadcast", {"subject": "Maintenance on {{domain}}", "body": "Hello {{username}}, we will restart the servers."})
    check(st == 202, "a message to all customers is queued", f"{st} {r}")
    if st == 202:
        wait_job(r["job_id"])
        got = queued(lambda m: any(x["address"] in ("owner1@remote.invalid", "owner3@remote.invalid") for x in m["recipients"]))
        addrs = {x["address"] for m in got for x in m["recipients"]}
        check({"owner1@remote.invalid", "owner3@remote.invalid"} <= addrs, "every customer with an address gets it", str(addrs))
    st, r = api("POST", "/messages/broadcast", {"subject": "Again", "body": "x"})
    check(st == 409, "a second message right away is refused", f"{st}")
finally:
    sh("postconf", "-X", "defer_transports")
    sh("postfix", "reload")
    sh("postsuper", "-d", "ALL", "deferred")
    api("PUT", "/messages/welcome", {"subject": "", "body": ""})
    clean()
finish()
