#!/usr/bin/env python3
"""End-to-end mail test (P1 #8, ADR-0007), run as root on a server where XCP
is installed: delivery over SMTP, forwarders, the default address,
rejections, IMAP logins, submission with DKIM signing, the switches,
suspension and the settings. Used by run.sh."""
import http.cookiejar, imaplib, urllib.error, os, pwd, smtplib, ssl, subprocess, time, urllib.request
from email.message import EmailMessage

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "mail test password 1234"
DOMAIN = "mail1.xcp.test"
insecure = ssl.create_default_context()
insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE


def send(to, subject, sender="someone@example.org", port=25, login=None):
    """Sends a message; returns None or the SMTP error."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg.set_content("Hello from the XCP mail test.\n")
    try:
        with smtplib.SMTP("127.0.0.1", port, timeout=30) as s:
            if login:
                s.starttls(context=insecure)
                s.login(*login)
            s.send_message(msg)
        return None
    except smtplib.SMTPException as e:
        return e


def inbox(user, password):
    """The raw messages in a mailbox's INBOX, or the login error."""
    try:
        with imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=insecure, timeout=30) as m:
            m.login(user, password)
            m.select("INBOX")
            _, ids = m.search(None, "ALL")
            out = []
            for i in ids[0].split():
                _, data = m.fetch(i, "(RFC822)")
                out.append(data[0][1].decode(errors="replace"))
            return out
    except (imaplib.IMAP4.error, OSError) as e:
        return e


def wait_for(user, password, subject, seconds=30):
    for _ in range(seconds * 2):
        msgs = inbox(user, password)
        if isinstance(msgs, list):
            found = [m for m in msgs if subject in m]
            if found:
                return found[0]
        time.sleep(0.5)
    return None


st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "mail1":  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "mail1"})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "mail1", "domain": DOMAIN, "package_id": pkg, "password": PW})
wait_job(a["job_id"])
acct = a["id"]
user = Session()
user.login("mail1", PW)

st, o = user.call("GET", f"/accounts/{acct}/mail")
check(st == 200 and o["domains"][0]["routing"] == "local", "the account's domain gets its mail here", str(o))
dom = o["domains"][0]["id"]


def create(path, body):
    st, r = user.call("POST", path, body)
    check(st == 202, f"create {body.get('local')}@{DOMAIN}", f"{st} {r}")
    user.wait_job(r.get("job_id", ""))
    return r


info = create(f"/accounts/{acct}/mailboxes", {"domain_id": dom, "local": "info", "password": PW})
quiet = create(f"/accounts/{acct}/mailboxes", {"domain_id": dom, "local": "quiet", "password": PW, "quota_mb": 1})
create(f"/accounts/{acct}/forwarders", {"domain_id": dom, "local": "sales", "to": [f"info@{DOMAIN}"]})
create(f"/accounts/{acct}/forwarders", {"domain_id": dom, "local": "old", "fail": "This address is no longer used"})
INFO = (f"info@{DOMAIN}", PW)

check(send(f"info@{DOMAIN}", "direct delivery") is None and wait_for(*INFO, "direct delivery"), "mail to a mailbox arrives over SMTP and IMAP")
check(send(f"sales@{DOMAIN}", "via forwarder") is None and wait_for(*INFO, "via forwarder"), "a forwarder passes mail on")
err = send(f"nobody@{DOMAIN}", "unknown")
check(isinstance(err, smtplib.SMTPRecipientsRefused), "unknown addresses are refused while there is no default address", str(err))
st, r = user.call("PUT", f"/domains/{dom}/mail/catch-all", {"to": [f"info@{DOMAIN}"]})
user.wait_job(r["job_id"])
check(send(f"nobody@{DOMAIN}", "to the default address") is None and wait_for(*INFO, "to the default address"),
      "the default address takes mail for unknown addresses")
err = send(f"old@{DOMAIN}", "rejected")
check(isinstance(err, smtplib.SMTPRecipientsRefused) and "no longer used" in str(err), "a failing forwarder rejects with its message", str(err))

# Switches: quiet neither logs in nor receives.
st, r = user.call("PUT", f"/mailboxes/{quiet['id']}", {"quota_mb": 1, "login": False, "receive": False, "send": False})
user.wait_job(r["job_id"])
check(isinstance(inbox(f"quiet@{DOMAIN}", PW), Exception), "a mailbox with login off cannot log in")
err = send(f"quiet@{DOMAIN}", "not received")
check(isinstance(err, smtplib.SMTPRecipientsRefused), "a mailbox with receiving off refuses mail", str(err))

# Dovecot caches logins: a new password must count at once all the same.
check(isinstance(inbox(*INFO), list), "info logs in (and Dovecot caches the login)")
st, r = user.call("PUT", f"/mailboxes/{info['id']}/password", {"password": "a changed password 99"})
user.wait_job(r["job_id"])
check(isinstance(inbox(*INFO), Exception) and isinstance(inbox(f"info@{DOMAIN}", "a changed password 99"), list),
      "a new password replaces the old one at once")
st, r = user.call("PUT", f"/mailboxes/{info['id']}/password", {"password": PW})
user.wait_job(r["job_id"])

# Submission: log in, sign with DKIM, send only as yourself.
check(send(f"info@{DOMAIN}", "signed", sender=f"info@{DOMAIN}", port=587, login=INFO) is None, "a mailbox sends over submission (587)")
signed = wait_for(*INFO, "signed")
check(signed is not None and f"d={DOMAIN}" in signed and "s=xcp" in signed, "outgoing mail is DKIM-signed for the domain", (signed or "")[:600])
err = send(f"info@{DOMAIN}", "forged", sender=f"boss@{DOMAIN}", port=587, login=INFO)
check(isinstance(err, smtplib.SMTPException), "it cannot send as another address", str(err))
err = send(f"info@{DOMAIN}", "unauthenticated", port=587)
check(isinstance(err, smtplib.SMTPException), "submission needs a login", str(err))
st, r = user.call("PUT", f"/mailboxes/{info['id']}", {"quota_mb": 0, "login": True, "receive": True, "send": False})
user.wait_job(r["job_id"])
err = send(f"info@{DOMAIN}", "send off", sender=f"info@{DOMAIN}", port=587, login=INFO)
check(isinstance(err, smtplib.SMTPException) and "switched off" in str(err), "sending off refuses the mailbox's mail", str(err))
st, r = user.call("PUT", f"/mailboxes/{info['id']}", {"quota_mb": 0, "login": True, "receive": True, "send": True})
user.wait_job(r["job_id"])

# DNS: the DKIM key is in the zone; the check runs; repair has nothing to add.
key = subprocess.run(["dig", "@127.0.0.1", "+short", "TXT", f"xcp._domainkey.{DOMAIN}"], capture_output=True, text=True).stdout
check("v=DKIM1" in key, "the DKIM key is published in the domain's zone", key[:120])
st, d = user.call("GET", f"/domains/{dom}/mail/deliverability")
check(st == 200 and [c["name"] for c in d["checks"]] == ["mx", "spf", "dkim", "dmarc", "ptr"] and d["repairable"], "the deliverability check runs", str(d)[:300])
st, r = user.call("POST", f"/domains/{dom}/mail/repair")
check(st == 200 and r["changed"] is False, "repair finds the zone complete", f"{st} {r}")

# Suspension: no login, mail still arrives.
st, r = api("POST", f"/accounts/{acct}/suspend", {"reason": "e2e"})
wait_job(r["job_id"])
check(isinstance(inbox(*INFO), Exception), "a suspended account's mailboxes cannot log in")
check(send(f"info@{DOMAIN}", "while suspended") is None, "but still receive mail")
st, r = api("POST", f"/accounts/{acct}/unsuspend")
wait_job(r["job_id"])
check(wait_for(*INFO, "while suspended") is not None, "which is there after unsuspending")

# Settings.
st, before = api("GET", "/server/mail")
body = {k: before[k] for k in ("hostname", "max_message_mb", "relay_host", "relay_user", "rbls", "helo_checks", "greylisting")}
st, r = api("PUT", "/server/mail", dict(body, max_message_mb=1))
wait_job(r["job_id"])
limit = subprocess.run(["postconf", "-h", "message_size_limit"], capture_output=True, text=True).stdout.strip()
check(limit == "1048576", "the largest message size reaches Postfix", limit)
st, r = api("PUT", "/server/mail", body)
wait_job(r["job_id"])

# Mail part 2 (ADR-0008): autoresponder, pipe, webmail sign-on.
user.login("mail1", PW)  # suspending ended the user's sessions
sender = create(f"/accounts/{acct}/mailboxes", {"domain_id": dom, "local": "sender", "password": PW})
SENDER = (f"sender@{DOMAIN}", PW)
st, r = user.call("PUT", f"/mailboxes/{info['id']}/autoresponder", {"subject": "Out of office", "body": "I am away until Monday.", "days": 1})
check(st == 202, "set an autoresponder", f"{st} {r}")
user.wait_job(r["job_id"])
check(send(f"info@{DOMAIN}", "are you there", sender=f"sender@{DOMAIN}", port=587, login=SENDER) is None, "mail to a mailbox with an autoresponder")
reply = wait_for(*SENDER, "Out of office")
check(reply is not None and "I am away until Monday." in reply, "the autoresponder answers the sender", (reply or "")[:300])
st, r = user.call("PUT", f"/mailboxes/{info['id']}/autoresponder", {"subject": "Later", "body": "x", "start": "2099-01-01", "days": 1})
user.wait_job(r["job_id"])
check(send(f"info@{DOMAIN}", "not yet", sender=f"sender@{DOMAIN}", port=587, login=SENDER) is None and wait_for(*INFO, "not yet"), "mail before the start date")
time.sleep(3)
check(wait_for(*SENDER, "Later", seconds=2) is None, "gets no reply before the autoresponder starts")
st, r = user.call("DELETE", f"/mailboxes/{info['id']}/autoresponder")
user.wait_job(r["job_id"])

subprocess.run(["runuser", "-u", "mail1", "--", "mkdir", "-p", "/home/mail1/bin"], check=True)
script = "#!/bin/sh\n# $1 = sender, $2 = recipient\ncat > /home/mail1/piped.eml\nid -un > /home/mail1/piped.user\n"
subprocess.run(["runuser", "-u", "mail1", "--", "tee", "/home/mail1/bin/pipe.sh"], input=script.encode(), stdout=subprocess.DEVNULL, check=True)
subprocess.run(["runuser", "-u", "mail1", "--", "chmod", "700", "/home/mail1/bin/pipe.sh"], check=True)
create(f"/accounts/{acct}/forwarders", {"domain_id": dom, "local": "orders", "pipe": "bin/pipe.sh"})
check(send(f"orders@{DOMAIN}", "new order 42") is None, "mail to a pipe address is accepted")
piped = ""
for _ in range(60):
    if os.path.exists("/home/mail1/piped.user"):
        piped = open("/home/mail1/piped.eml").read()
        break
    time.sleep(0.5)
check("new order 42" in piped and open("/home/mail1/piped.user").read().strip() == "mail1", "the script gets the mail and runs as the account's user", piped[:200])

st, s = user.call("POST", f"/mailboxes/{info['id']}/webmail")
url = (s or {}).get("url", "")
check(st == 200 and url.startswith("https://127.0.0.1/webmail/?_xcp_ticket="), "webmail sign-on gives a URL", f"{st} {s}")
jar = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=insecure), urllib.request.HTTPCookieProcessor(jar))
with browser.open(url.replace("https://127.0.0.1", "https://127.0.0.1"), timeout=30) as resp:
    page = resp.read().decode(errors="replace")
check('"task":"mail"' in page and f"info@{DOMAIN}" in page, "the ticket signs in to Roundcube's inbox", page[:300])
try:
    with urllib.request.build_opener(urllib.request.HTTPSHandler(context=insecure)).open(url, timeout=30) as resp:
        again = resp.read().decode(errors="replace")
except urllib.error.HTTPError as e:  # Roundcube answers a failed login with 401
    again = e.read().decode(errors="replace")
check('"task":"login"' in again, "a ticket works once", again[:200])
tokens = open("/etc/dovecot/xcp/tokens").read()
check(f"info@{DOMAIN}:" in tokens, "the temporary password is in Dovecot's second passdb")
st, r = user.call("PUT", f"/mailboxes/{info['id']}", {"quota_mb": 0, "login": False, "receive": True, "send": True})
user.wait_job(r["job_id"])
check(f"info@{DOMAIN}:" not in open("/etc/dovecot/xcp/tokens").read(), "switching login off drops it")
st, r = user.call("POST", f"/mailboxes/{info['id']}/webmail")
check(st == 409, "and webmail sign-on is refused", f"{st} {r}")
st, r = user.call("PUT", f"/mailboxes/{info['id']}", {"quota_mb": 0, "login": True, "receive": True, "send": True})
user.wait_job(r["job_id"])

maildir = os.stat(f"/home/mail1/mail/{DOMAIN}/info/Maildir")
check(pwd.getpwuid(maildir.st_uid).pw_name == "mail1" and maildir.st_mode & 0o077 == 0,
      "mail is kept in the account's home, owned by the account and private")

st, t = api("POST", f"/accounts/{acct}/terminate", {"confirm": "mail1"})
wait_job(t["job_id"])
passwd = open("/etc/dovecot/xcp/passwd").read()
check(DOMAIN not in passwd and DOMAIN not in open("/etc/postfix/xcp/domains").read(), "terminating removes the account's mail")
finish()
