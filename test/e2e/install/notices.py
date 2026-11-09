#!/usr/bin/env python3
"""End-to-end test of the customer notices (ADR-0033), run as root on a server
where XCP and Postfix are installed. Outgoing delivery is held back
(defer_transports), so the mail stays in Postfix's queue: suspending and
reactivating an account with an email address queue a notice each, an editable
text is used, and the master switch in the server settings turns them off."""
import base64, email, subprocess, time
from email.header import decode_header, make_header

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "notices test password 1234"
ADDR = "owner@remote.invalid"


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def queued(secs=30, count=1):
    end = time.time() + secs
    items = []
    while time.time() < end:
        st, q = api("GET", "/server/mail/queue")
        items = [m for m in q["items"] if m["queue"] == "deferred" and any(r["address"] == ADDR for r in m["recipients"])] if st == 200 else []
        if len(items) >= count:
            return items
        time.sleep(1)
    return items


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"].startswith("ntc"):
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
            wait_job(t["job_id"])
    sh("postsuper", "-d", "ALL", "deferred")


clean()
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]

st, a0 = api("POST", "/accounts", {"username": "ntc0", "domain": "ntc0.xcp.test", "package_id": pkg, "password": PW})
wait_job(a0["job_id"])
user = Session()
user.login("ntc0", PW)
for method, path, body in (("GET", "/messages/notices", None), ("PUT", "/messages/notices/suspended", {"subject": "x", "body": "y"})):
    st, _ = user.call(method, path, body)
    check(st == 403, f"a customer cannot use {method} {path}", f"{st}")

# The texts: defaults first, then an own one, with validation.
st, r = api("GET", "/messages/notices")
kinds = [n["kind"] for n in r["items"]] if st == 200 else []
check(kinds == ["suspended", "unsuspended", "disk_warning", "disk_full", "traffic_warning", "traffic_full"] and not any(n["custom"] for n in r["items"]), "the six notices with their default texts", f"{st} {kinds}")
st, _ = api("PUT", "/messages/notices/nope", {"subject": "x", "body": "y"})
check(st == 404, "an unknown notice is refused", f"{st}")
st, _ = api("PUT", "/messages/notices/suspended", {"subject": "x", "body": "{{password}}"})
check(st == 400, "an unknown variable is refused", f"{st}")
st, r = api("PUT", "/messages/notices/suspended", {"subject": "Suspended: {{domain}}", "body": "Because: {{reason}}"})
check(st == 200 and r["custom"], "the admin saves its own text", f"{st} {r}")

sh("postconf", "-e", "defer_transports = smtp")
sh("postfix", "reload")
try:
    st, a1 = api("POST", "/accounts", {"username": "ntc1", "domain": "ntc1.xcp.test", "package_id": pkg, "password": PW, "email": ADDR})
    check(st in (200, 201, 202), "an account with an email address is made", f"{st} {a1}")
    wait_job(a1["job_id"])
    queued()  # the welcome message
    sh("postsuper", "-d", "ALL", "deferred")

    st, r = api("POST", f"/accounts/{a1['id']}/suspend", {"reason": "payment overdue"})
    wait_job(r["job_id"])
    got = queued()
    check(len(got) == 1, "suspending queues a notice", str(got))
    raw = sh("postcat", "-q", got[0]["id"]).stdout if got else ""
    msg = email.message_from_string(raw[raw.find("Received:") if "Received:" in raw else 0:])
    text = str(make_header(decode_header(msg.get("Subject", "")))) + "\n" + (msg.get_payload(decode=True) or b"").decode("utf-8", "replace")
    check("Suspended: ntc1.xcp.test" in text and "payment overdue" in text, "it uses the text and the reason", text[-300:])
    sh("postsuper", "-d", "ALL", "deferred")

    st, r = api("POST", f"/accounts/{a1['id']}/unsuspend")
    wait_job(r["job_id"])
    got = queued()
    check(len(got) == 1, "reactivating queues a notice", str(got))
    sh("postsuper", "-d", "ALL", "deferred")

    # The master switch.
    st, r = api("PUT", "/server/settings", {"values": {"notices.enabled": False}})
    check(st == 200, "the notices can be switched off", f"{st} {r}")
    st, r = api("POST", f"/accounts/{a1['id']}/suspend", {"reason": "again"})
    wait_job(r["job_id"])
    time.sleep(4)
    check(not queued(secs=1), "nothing is sent while they are off")
    api("PUT", "/server/settings", {"values": {"notices.enabled": True}})
    api("POST", f"/accounts/{a1['id']}/unsuspend")
finally:
    sh("postconf", "-X", "defer_transports")
    sh("postfix", "reload")
    sh("postsuper", "-d", "ALL", "deferred")
    api("PUT", "/messages/notices/suspended", {"subject": "", "body": ""})
    api("PUT", "/server/settings", {"values": {"notices.enabled": True}})
    clean()
finish()
