#!/usr/bin/env python3
"""End-to-end test of the mail sending limits (ADR-0028), run as root on a
server where XCP and Postfix are installed: an account whose package allows
4 recipients per hour can send up to that through submission, the next message
is deferred with a 450 reply, and another account is not affected. Outgoing
delivery is held back so nothing leaves the machine."""
import smtplib, ssl, subprocess
from email.message import EmailMessage

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "send limits password 1234"
insecure = ssl.create_default_context()
insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def send(login, to):
    """Sends one message through submission; returns None or the SMTP error."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = login, to if isinstance(to, str) else ", ".join(to), "limit test"
    msg.set_content("hello\n")
    try:
        with smtplib.SMTP("127.0.0.1", 587, timeout=30) as s:
            s.starttls(context=insecure)
            s.login(login, PW)
            s.send_message(msg)
        return None
    except smtplib.SMTPException as e:
        return e


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"] in ("lim1", "lim2"):
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
            wait_job(t["job_id"])
    st, pk = api("GET", "/packages")
    for p in pk["items"]:
        if p["name"] == "Mail limited":
            api("DELETE", f"/packages/{p['id']}")


clean()
st, pk = api("GET", "/packages")
base = next(p for p in pk["items"] if p["name"] == "Default")
limits = dict(base["limits"])
limits["mail_per_hour"] = 4
st, pkg = api("POST", "/packages", {"name": "Mail limited", "feature_list_id": base["feature_list_id"], "limits": limits})
check(st in (200, 201), "a package with 4 recipients per hour is made", f"{st} {pkg}")

users = {}
for name in ("lim1", "lim2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": f"{name}.xcp.test", "package_id": pkg["id"], "password": PW})
    wait_job(a["job_id"])
    s = Session()
    s.login(name, PW)
    st, o = s.call("GET", f"/accounts/{a['id']}/mail")
    st, r = s.call("POST", f"/accounts/{a['id']}/mailboxes", {"domain_id": o["domains"][0]["id"], "local": "info", "password": PW})
    check(st == 202, f"{name} has a mailbox", f"{st} {r}")
    s.wait_job(r["job_id"])
    users[name] = f"info@{name}.xcp.test"

sh("postconf", "-e", "defer_transports = smtp")
sh("postfix", "reload")
try:
    check(sh("systemctl", "is-active", "xcp-mailpolicy").stdout.strip() == "active", "xcp-mailpolicy is running")
    check(send(users["lim1"], "a@remote.invalid") is None, "1 recipient (1 of 4)")
    check(send(users["lim1"], ["b@remote.invalid", "c@remote.invalid"]) is None, "2 more (3 of 4)")
    e = send(users["lim1"], ["d@remote.invalid", "e@remote.invalid"])
    check(isinstance(e, smtplib.SMTPResponseException) and e.smtp_code == 450 and "hourly sending limit" in str(e.smtp_error),
          "2 more would pass 4: refused with a 450 reply", str(e))
    check(send(users["lim1"], "f@remote.invalid") is None, "a refused message was not counted: 1 more still fits (4 of 4)")
    e = send(users["lim1"], "g@remote.invalid")
    check(isinstance(e, smtplib.SMTPResponseException) and e.smtp_code == 450, "the fifth recipient is refused", str(e))
    check(send(users["lim2"], "a@remote.invalid") is None, "another account is not affected")
    # Mail to our own mailboxes through submission counts too (it is sending).
    e = send(users["lim1"], users["lim2"])
    check(isinstance(e, smtplib.SMTPResponseException) and e.smtp_code == 450, "the limit holds for local recipients as well", str(e))
    # Inbound mail from outside is never limited.
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "someone@example.org", users["lim1"], "inbound"
    msg.set_content("hi\n")
    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=30) as s:
            s.send_message(msg)
        check(True, "inbound mail is not limited")
    except smtplib.SMTPException as ex:
        check(False, "inbound mail is not limited", str(ex))
finally:
    sh("postconf", "-X", "defer_transports")
    sh("postfix", "reload")
    sh("postsuper", "-d", "ALL", "deferred")
    clean()
finish()
