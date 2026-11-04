#!/usr/bin/env python3
"""The P1 acceptance test (docs/plan/09-roadmap.md), run as root on a server
where XCP is installed: create an account, add a domain, DNS resolves from
the server, AutoSSL issues (Pebble), upload a site by FTP, create a
database, the site loads over HTTPS, create a mailbox, send and receive
mail with DKIM, back up, terminate, restore, and the site works again.

Pebble (Let's Encrypt's test CA) runs on localhost like in acme.py; the
server's resolver points to PowerDNS for the test. Everything is restored
at the end."""
import glob, hashlib, imaplib, json, os, smtplib, socket, sqlite3, ssl, subprocess, tempfile, time, urllib.request
from email.message import EmailMessage
from ftplib import FTP_TLS

from xcpe2e import Session, admin, check, finish

PEBBLE = os.environ.get("PEBBLE", "/opt/xcp/pebble")
PW = "acceptance password 1234"
USER, DOMAIN = "acc1", "acc1.xcp.test"
HOME = "/home/" + USER
admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
tmp = tempfile.mkdtemp()
insecure = ssl.create_default_context()
insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE


def tls_get(name, cafile):
    """GET / of the site name over HTTPS, the certificate checked against cafile; (ok, body or error)."""
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=name) as s:
                s.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while chunk := s.recv(65536):
                    data += chunk
                return True, data.decode(errors="replace")
    except (ssl.SSLError, OSError) as e:
        return False, str(e)


def wait_site(name, cafile, needle, seconds=60):
    body = ""
    for _ in range(seconds * 2):
        ok, body = tls_get(name, cafile)
        if ok and needle in body:
            return True, body
        time.sleep(0.5)
    return False, body


def dig(name):
    return subprocess.run(["dig", "@127.0.0.1", "+short", name], capture_output=True, text=True).stdout.strip()


def wait_dns(name, ip, seconds=60):
    for _ in range(seconds * 2):
        if ip in dig(name):
            return True
        time.sleep(0.5)
    return False


class Resolver:
    """Points this server's resolver at PowerDNS, and back."""

    path = "/etc/resolv.conf"

    def __enter__(self):
        self.link = os.readlink(self.path) if os.path.islink(self.path) else None
        self.content = None if self.link else open(self.path).read()
        if self.link:
            os.remove(self.path)
        with open(self.path, "w") as f:
            f.write("nameserver 127.0.0.1\n")
        time.sleep(6)
        return self

    def __exit__(self, *exc):
        if self.link:
            os.remove(self.path)
            os.symlink(self.link, self.path)
        else:
            with open(self.path, "w") as f:
                f.write(self.content)


def start_pebble():
    cert, key = os.path.join(tmp, "pebble.crt"), os.path.join(tmp, "pebble.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "2", "-subj", "/CN=pebble", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"], check=True, capture_output=True)
    config = os.path.join(tmp, "pebble.json")
    with open(config, "w") as f:
        json.dump({"pebble": {
            "listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000", "certificate": cert, "privateKey": key,
            "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": False,
            "retryAfter": {"authz": 1, "order": 1}, "profiles": {"default": {"description": "default", "validityPeriod": 7776000}},
        }}, f)
    proc = subprocess.Popen([PEBBLE, "-config", config, "-dnsserver", "127.0.0.1:53"], env=dict(os.environ, PEBBLE_VA_NOSLEEP="1", PEBBLE_WFE_NONCEREJECT="0"),
                            stdout=open(os.path.join(tmp, "pebble.log"), "w"), stderr=subprocess.STDOUT)
    pctx = ssl.create_default_context(cafile=cert)
    for _ in range(50):
        try:
            urllib.request.urlopen("https://127.0.0.1:14000/dir", context=pctx, timeout=2).read()
            break
        except OSError:
            time.sleep(0.2)
    root = os.path.join(tmp, "pebble-root.pem")
    with open(root, "wb") as f:
        f.write(urllib.request.urlopen("https://127.0.0.1:15000/roots/0", context=pctx).read())
    return proc, cert, root


def mariadb(sql):
    return subprocess.run(["mariadb", "-N", "-e", sql], capture_output=True, text=True)


def ftp_upload(login, files):
    """Uploads {path: bytes} through FTP over TLS; folders are made."""
    f = FTP_TLS(context=insecure, timeout=15)
    f.connect("127.0.0.1", 21)
    f.login(login, PW)
    f.prot_p()
    for path, data in files.items():
        folder, _, name = path.rpartition("/")
        f.cwd("/")
        for part in filter(None, folder.split("/")):
            try:
                f.mkd(part)
            except Exception:
                pass
            f.cwd(part)
        import io
        f.storbinary("STOR " + name, io.BytesIO(data))
    f.quit()


def inbox(address, password):
    with imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=insecure, timeout=30) as m:
        m.login(address, password)
        m.select("INBOX")
        _, ids = m.search(None, "ALL")
        return [m.fetch(i, "(RFC822)")[1][0][1].decode(errors="replace") for i in ids[0].split()]


# Leftovers of an earlier run.
st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == USER:
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": USER})
        wait_job(t["job_id"])
st, orphans = api("GET", "/server/backups")
for o in orphans["items"]:
    if o["username"] == USER:
        api("DELETE", f"/backups/{o['id']}")

pebble, cert, root = start_pebble()
st, ssl_before = api("GET", "/server/ssl")
st, dns = api("GET", "/server/dns")
ip = dns["ipv4"]
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
try:
    with Resolver():
        st, r = api("PUT", "/server/ssl", {"enabled": True, "provider": "custom", "directory_url": "https://127.0.0.1:14000/dir",
                                           "ca_bundle": open(cert).read(), "email": "e2e@xcp.test", "hostname": "panel.acc1.xcp.test"})
        check(st == 200, "AutoSSL is set up for Pebble", str(r))

        # 1. Account and domain.
        st, a = api("POST", "/accounts", {"username": USER, "domain": DOMAIN, "package_id": pkg, "password": PW})
        j = wait_job(a["job_id"])
        acct = a["id"]
        check(j["status"] == "succeeded", "create the account", str(j)[:300])
        user = Session()
        user.login(USER, PW)
        st, doms = user.call("GET", f"/accounts/{acct}/domains")
        primary = next(d for d in doms["items"] if d["name"] == DOMAIN)
        st, sub = user.call("POST", f"/accounts/{acct}/domains", {"kind": "sub", "name": "blog", "parent_id": primary["id"]})
        check(st in (200, 201, 202), "add a domain (blog.acc1.xcp.test)", f"{st} {sub}")
        if st in (200, 201, 202) and sub.get("job_id"):
            wait_job(sub["job_id"])

        # 2. DNS resolves from the server.
        st, zs = api("GET", f"/dns/zones?account_id={acct}")
        st, r = api("POST", f"/dns/zones/{zs['items'][0]['id']}/records", {"name": "panel", "type": "A", "content": ip})
        wait_job(r["job_id"])
        check(wait_dns(DOMAIN, ip) and wait_dns("blog." + DOMAIN, ip), "both names resolve to the server through PowerDNS", f"{dig(DOMAIN)!r} {dig('blog.' + DOMAIN)!r}")

        # 3. AutoSSL issues.
        st, run = api("POST", "/server/ssl/run")
        j = wait_job(run["job_id"])
        check(j["status"] == "succeeded" and (j.get("result") or {}).get("issued", 0) >= 1, "AutoSSL issues the certificates", json.dumps(j)[:400])

        # 4. A database, and a site uploaded by FTP that uses it.
        st, wz = user.call("POST", f"/accounts/{acct}/database-wizard", {"database": "shop", "user": "shopper", "password": PW})
        wait_job(wz["job_id"])
        r = mariadb("CREATE TABLE acc1_shop.items (id INT PRIMARY KEY, name VARCHAR(40)); INSERT INTO acc1_shop.items VALUES (1, 'acceptance-row')")
        check(r.returncode == 0, "create a database with data", r.stderr)
        index = (b'<?php $m = new mysqli("localhost", "acc1_shopper", "' + PW.encode() + b'", "acc1_shop"); '
                 b'echo "42 " . $m->query("SELECT name FROM items")->fetch_row()[0]; ?>\n')
        blob = os.urandom(200_000)
        st, dm = user.call("GET", f"/accounts/{acct}/ftp")
        st, fl = user.call("POST", f"/accounts/{acct}/ftp", {"domain_id": dm["domains"][0]["id"], "name": "deploy", "password": PW, "folder": "public_html"})
        wait_job(fl["job_id"])
        ftp_upload("deploy@" + DOMAIN, {"index.php": index, "wp-content/uploads/data.bin": blob})
        check(open(f"{HOME}/public_html/wp-content/uploads/data.bin", "rb").read() == blob, "upload a site by FTP")

        # 5. The site loads over HTTPS, with the ACME certificate (chain checked).
        ok, body = wait_site(DOMAIN, root, "42 acceptance-row")
        check(ok, "the site loads over HTTPS and shows the database's data", body[-300:])

        # 6. A mailbox; mail sent and received, signed with DKIM.
        st, mail = user.call("GET", f"/accounts/{acct}/mail")
        st, box = user.call("POST", f"/accounts/{acct}/mailboxes", {"domain_id": mail["domains"][0]["id"], "local": "info", "password": PW})
        wait_job(box["job_id"])
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = "info@" + DOMAIN, "info@" + DOMAIN, "acceptance mail"
        msg.set_content("hello from the acceptance test\n")
        with smtplib.SMTP("127.0.0.1", 587, timeout=30) as s:
            s.starttls(context=insecure)
            s.login("info@" + DOMAIN, PW)
            s.send_message(msg)
        maildir = f"{HOME}/mail/{DOMAIN}/info/Maildir/new/*"
        for _ in range(60):
            if glob.glob(maildir):
                break
            time.sleep(1)
        mails = [open(f).read() for f in glob.glob(maildir)]
        check(any("acceptance mail" in m and "DKIM-Signature:" in m for m in mails), "send and receive mail; it carries a DKIM signature", str(mails)[:300])

        # 7. Back up.
        st, b = user.call("POST", f"/accounts/{acct}/backups")
        j = wait_job(b["job_id"])
        st, ov = user.call("GET", f"/accounts/{acct}/backups")
        check(j["status"] == "succeeded" and ov["backups"][0]["status"] == "ok", "make a backup", str(j)[:300])

        # 8. Terminate: everything of the account is gone, the backup stays.
        st, t = api("POST", f"/accounts/{acct}/terminate", {"confirm": USER})
        j = wait_job(t["job_id"])
        gone = subprocess.run(["id", USER], capture_output=True).returncode != 0 and not os.path.exists(HOME)
        check(j["status"] == "succeeded" and gone, "terminate the account: its user and home are gone", str(j)[:300])
        check(USER not in mariadb("SHOW DATABASES").stdout and "acc1_shop" not in mariadb("SHOW DATABASES").stdout, "and its database")
        st, orphans = api("GET", "/server/backups")
        mine = [o for o in orphans["items"] if o["username"] == USER]
        check(len(mine) == 1, "the backup stays, for the admin", str(orphans)[:300])

        # 9. Restore it.
        st, rs = api("POST", f"/server/backups/{mine[0]['id']}/restore", {})
        check(st == 202, "start the restore", f"{st} {rs}")
        j = wait_job(rs["job_id"])
        check(j["status"] == "succeeded", "the restore finishes", json.dumps(j)[:600])

        # 10. The site works again, and so does everything else.
        st, acc = api("GET", "/accounts")
        again = next((x for x in acc["items"] if x["username"] == USER), None)
        check(again and again["status"] == "active" and again["id"] == acct, "the account is back and active", str(again))
        check(wait_dns(DOMAIN, ip), "its DNS zone is served again")
        ok, body = wait_site(DOMAIN, root, "42 acceptance-row", seconds=90)
        check(ok, "the site loads over HTTPS again, with its certificate and database", body[-300:])
        check(open(f"{HOME}/public_html/wp-content/uploads/data.bin", "rb").read() == blob and open(f"{HOME}/public_html/index.php", "rb").read() == index,
              "the uploaded files are back, intact")
        check(os.stat(f"{HOME}/public_html/index.php").st_uid == os.stat(HOME).st_uid, "owned by the account's user")
        check("acceptance-row" in mariadb("SELECT name FROM acc1_shop.items").stdout, "the database has its data")
        try:
            got = inbox("info@" + DOMAIN, PW)
        except Exception as e:  # noqa: BLE001
            got = [str(e)]
        check(any("acceptance mail" in m and "DKIM-Signature:" in m for m in got), "the mailbox logs in and has its mail", str(got)[:300])
        back = Session()
        check(back.login(USER, PW) == 200, "the account's panel login works with its old password")
        try:
            ftp_upload("deploy@" + DOMAIN, {"again.txt": b"ok"})
            ftp_ok = os.path.exists(f"{HOME}/public_html/again.txt")
        except Exception:  # noqa: BLE001
            ftp_ok = False
        check(ftp_ok, "the FTP login works again")
        st, ov = back.call("GET", f"/accounts/{acct}/backups")
        check(st == 200 and len(ov["backups"]) >= 1, "the account has its backup again", f"{st}")

        # Clean up.
        st, t = api("POST", f"/accounts/{acct}/terminate", {"confirm": USER})
        wait_job(t["job_id"])
        st, orphans = api("GET", "/server/backups")
        for o in orphans["items"]:
            if o["username"] == USER:
                api("DELETE", f"/backups/{o['id']}")
finally:
    body = {k: ssl_before[k] for k in ("enabled", "provider", "directory_url", "ca_bundle", "eab_key_id", "email", "hostname")}
    api("PUT", "/server/ssl", body)
    db = sqlite3.connect("/var/lib/xcp/xcp.db")
    db.execute("DELETE FROM certificates WHERE domain_id IS NULL")
    db.commit()
    db.close()
    for f in ("/etc/xcp/ssl/hostname.crt", "/etc/xcp/ssl/hostname.key"):
        if os.path.exists(f):
            os.remove(f)
    pebble.terminate()
    pebble.wait()
finish()
