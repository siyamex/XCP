#!/usr/bin/env python3
"""End-to-end test of the mailbox spam filters (ADR-0029), run as root on a
server where XCP, Postfix, Dovecot and Rspamd are installed. Messages are
handed to Dovecot over LMTP with the X-Spam-Level header Rspamd would have
added, so the mailbox's Sieve script is what is tested: threshold, Junk or
delete, allow and block lists, switched off. A second part checks that Rspamd
adds the header itself and replaces one a sender made up."""
import imaplib, os, smtplib, ssl, sys, time
from email.message import EmailMessage

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "spam test password 1234"
DOMAIN = "spm1.xcp.test"
ADDR = "info@" + DOMAIN
LMTP = "/var/spool/postfix/private/dovecot-lmtp"
insecure = ssl.create_default_context()
insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE


def deliver(subject, sender="someone@example.org", stars=0):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, ADDR, subject
    if stars:
        msg["X-Spam-Level"] = "*" * stars
    msg.set_content("hello\n")
    with smtplib.LMTP(LMTP) as s:
        s.sendmail(sender, [ADDR], msg.as_bytes())


def folder(name):
    """The subjects in a folder, or None when it does not exist (one retry after a dropped connection)."""
    try:
        return _folder(name)
    except (imaplib.IMAP4.abort, OSError):
        time.sleep(1)
        return _folder(name)


def _folder(name):
    with imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=insecure, timeout=30) as m:
        m.login(ADDR, PW)
        st, _ = m.select(f'"{name}"', readonly=True)
        if st != "OK":
            return None
        _, ids = m.search(None, "ALL")
        out = []
        for i in ids[0].split():
            _, data = m.fetch(i, "(BODY.PEEK[HEADER.FIELDS (SUBJECT X-SPAM-LEVEL)])")
            out.append(data[0][1].decode(errors="replace"))
        return out


def has(f, subject):
    return any(subject in x for x in (folder(f) or []))


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"] == "spm1":
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "spm1"})
            wait_job(t["job_id"])


clean()
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "spm1", "domain": DOMAIN, "package_id": pkg, "password": PW})
wait_job(a["job_id"])
user = Session()
user.login("spm1", PW)
st, o = user.call("GET", f"/accounts/{a['id']}/mail")
st, r = user.call("POST", f"/accounts/{a['id']}/mailboxes", {"domain_id": o["domains"][0]["id"], "local": "info", "password": PW})
user.wait_job(r["job_id"])
mbx = r["id"]

# Defaults: on, 6, Junk.
st, sp = user.call("GET", f"/mailboxes/{mbx}/spam")
check(st == 200 and sp["enabled"] and sp["threshold"] == 6 and sp["action"] == "junk", "the default filter", f"{st} {sp}")
deliver("plain mail")
deliver("clearly spam", stars=12)
deliver("borderline", stars=5)
time.sleep(2)
check(has("INBOX", "plain mail"), "mail without a score goes to the inbox")
check(has("INBOX", "borderline"), "5 points is below the default 6: inbox")
check(has("Junk", "clearly spam") and not has("INBOX", "clearly spam"), "12 points goes to Junk, not the inbox", str(folder("Junk")))


def put(**kw):
    body = {"enabled": True, "threshold": 6, "action": "junk", "allow": [], "block": []}
    body.update(kw)
    st, r = user.call("PUT", f"/mailboxes/{mbx}/spam", body)
    check(st == 202, f"spam filter saved {kw}", f"{st} {r}")
    if st == 202:
        user.wait_job(r["job_id"])
    return st


# A stricter and a looser threshold.
put(threshold=3)
deliver("three stars", stars=3)
time.sleep(1)
check(has("Junk", "three stars"), "threshold 3: three points is spam")
put(threshold=9)
deliver("eight stars", stars=8)
time.sleep(1)
check(has("INBOX", "eight stars"), "threshold 9: eight points is not")

# Lists.
put(threshold=6, allow=["friend@good.example", "*@partner.example"], block=["bad@spam.example", "*@evil.example"])
deliver("from a friend", sender="friend@good.example", stars=30)
deliver("from the partner", sender="Anyone@Partner.example", stars=30)
deliver("from the blocked", sender="bad@spam.example")
deliver("from the evil domain", sender="anyone@evil.example")
deliver("from a stranger", sender="stranger@else.example", stars=30)
time.sleep(2)
check(has("INBOX", "from a friend") and has("INBOX", "from the partner"), "allowed senders are delivered whatever the score")
check(has("Junk", "from the blocked") and has("Junk", "from the evil domain"), "blocked senders go to Junk")
check(has("Junk", "from a stranger"), "others are still scored")

# Delete.
put(action="delete")
deliver("to be deleted", stars=30)
deliver("blocked and deleted", sender="bad@spam.example")
time.sleep(1)
check(not has("INBOX", "to be deleted") and not has("Junk", "to be deleted"), "delete: gone from both folders")
check(not has("Junk", "blocked and deleted"), "delete applies to the block list too")

# Off.
put(enabled=False)
deliver("filter is off", stars=30)
time.sleep(1)
check(has("INBOX", "filter is off"), "switched off: everything is delivered")

# Validation and isolation.
for bad in ({"threshold": 0}, {"threshold": 99}, {"action": "bounce"}, {"allow": ["x\" ; discard"]}, {"block": ["*"]}, {"allow": ["a@b.example"], "block": ["a@b.example"]}):
    body = {"enabled": True, "threshold": 6, "action": "junk", "allow": [], "block": []}
    body.update(bad)
    st, _ = user.call("PUT", f"/mailboxes/{mbx}/spam", body)
    check(st == 400, f"a bad filter is refused {bad}", f"{st}")
st, b = api("POST", "/accounts", {"username": "spm2", "domain": "spm2.xcp.test", "package_id": pkg, "password": PW})
wait_job(b["job_id"])
other = Session()
other.login("spm2", PW)
st, _ = other.call("GET", f"/mailboxes/{mbx}/spam")
check(st in (403, 404), "another account cannot read the filter", f"{st}")
st, _ = other.call("PUT", f"/mailboxes/{mbx}/spam", {"enabled": False, "threshold": 6, "action": "junk", "allow": [], "block": []})
check(st in (403, 404), "or change it", f"{st}")

# Rspamd adds the header itself and replaces one a sender made up.
put(enabled=True, threshold=50, action="junk")
msg = EmailMessage()
msg["From"], msg["To"], msg["Subject"] = "someone@example.org", ADDR, "forged header"
msg["X-Spam-Level"] = "*" * 49
msg.set_content("hello from the test\n")
with smtplib.SMTP("127.0.0.1", 25, timeout=30) as s:
    s.send_message(msg)
got = None
for _ in range(30):
    got = next((x for x in (folder("INBOX") or []) + (folder("Junk") or []) if "forged header" in x), None)
    if got:
        break
    time.sleep(1)
check(got is not None, "a message through Rspamd arrives", "")
if got:
    levels = [l for l in got.splitlines() if l.lower().startswith("x-spam-level")]
    check(len(levels) <= 1 and (not levels or levels[0].count("*") < 49), "the made-up X-Spam-Level is replaced by Rspamd's", str(levels))

# Server-wide settings (ADR-0030): the block list and the score from which Rspamd refuses mail.
def server_mail(**kw):
    st, cur = api("GET", "/server/mail")
    body = {k: v for k, v in cur.items() if k != "has_relay_password"}
    body["relay_password"] = ""
    body.update(kw)
    st, r = api("PUT", "/server/mail", body)
    if st == 202:
        wait_job(r["job_id"])
        return 200, r["settings"], cur
    return st, r, cur


def smtp_in(sender, subject):
    """Hands a message to port 25; returns None when accepted, else the SMTP error."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, ADDR, subject
    msg.set_content("hello from the test\n")
    try:
        with smtplib.SMTP("127.0.0.1", 25, timeout=30) as c:
            c.send_message(msg)
        return None
    except smtplib.SMTPException as e:
        return e


put(enabled=True, threshold=6, action="junk", allow=[], block=[])
st, r, orig = server_mail()
check(st == 200 and r["spam_reject"] == 15, "the server starts with Rspamd's own refusal score", f"{st} {r.get('spam_reject')}")
for bad in ({"spam_reject": 3}, {"spam_reject": 500}, {"spam_allow": ["a@b.example"]}, {"spam_block": ["x y"]}):
    st, _, _ = server_mail(**bad)
    check(st == 400, f"bad server spam settings are refused {bad}", f"{st}")
try:
    st, r, _ = server_mail(spam_block=["Bad@Blocked.example", "evil.example"], spam_allow=["partner.example"])
    check(st == 200 and r["spam_block"] == ["bad@blocked.example", "evil.example"] and r["spam_allow"] == ["partner.example"], "the lists are saved in lower case", f"{st} {r}")
    time.sleep(3)  # Rspamd reloads its configuration
    e = smtp_in("bad@blocked.example", "from a blocked sender")
    check(isinstance(e, smtplib.SMTPException), "a blocked sender is refused at the score of 15", str(e))
    e = smtp_in("nobody@evil.example", "from a blocked domain")
    check(isinstance(e, smtplib.SMTPException), "so is a blocked domain", str(e))
    st, r, _ = server_mail(spam_reject=100)
    time.sleep(3)
    e = smtp_in("bad@blocked.example", "blocked but not refused")
    check(e is None, "with the refusal score at 100 the blocked sender is accepted", str(e))
    for _ in range(30):
        if has("Junk", "blocked but not refused"):
            break
        time.sleep(1)
    check(has("Junk", "blocked but not refused"), "and its mail goes to the mailbox's Junk folder")
    check(not has("INBOX", "blocked but not refused"), "not to the inbox")
finally:
    server_mail(spam_reject=15, spam_block=[], spam_allow=[])

if os.environ.get("KEEP"):  # leave the accounts for a look at the server
    finish()
    sys.exit(0)
st, existing = api("GET", "/accounts")
for x in existing["items"]:
    if x["username"] in ("spm1", "spm2"):
        st, t = api("POST", f"/accounts/{x['id']}/terminate", {"confirm": x["username"]})
        wait_job(t["job_id"])
finish()
