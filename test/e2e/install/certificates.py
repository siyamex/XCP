#!/usr/bin/env python3
"""End-to-end SSL test, run as root on a server where XCP is installed.

It uploads a certificate (made with openssl) through the API and checks
what Apache serves: HTTPS, forced HTTPS that still lets ACME challenges
through, the default HTTPS host for unknown names, and AutoSSL's reasons
for names that do not point here. Issuing through a real ACME CA is not
part of it. Used by run.sh.
"""
import os, socket, ssl, subprocess, tempfile

from xcpe2e import admin, check, finish, raw

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
tmp = tempfile.mkdtemp()


def make_cert(*names):
    """A self-signed certificate for names and its key, as PEM text."""
    cert, key = os.path.join(tmp, names[0] + ".crt"), os.path.join(tmp, names[0] + ".key")
    san = ",".join("DNS:" + n for n in names)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "90", "-subj", "/CN=" + names[0], "-addext", "subjectAltName=" + san],
                   check=True, capture_output=True)
    return open(cert).read(), open(key).read(), cert


def https(name, path="/", cafile=None):
    """GET over HTTPS to this server with SNI name: (status line, body). cafile=None: no verification."""
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as s:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := s.recv(65536):
                data += chunk
    head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
    return head.split("\r\n")[0], body


st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "ssl1", "domain": "ssl1.xcp.test", "package_id": pkg, "password": "ssl password 1234"})
wait_job(a["job_id"])
st, doms = api("GET", f"/accounts/{a['id']}/ssl")
dom = doms["items"][0]
check(dom["domain"] == "ssl1.xcp.test" and dom.get("certificate") is None, "a new domain has no certificate", str(dom))

cert, key, certfile = make_cert("ssl1.xcp.test", "www.ssl1.xcp.test")
_, wrong_key, _ = make_cert("other.xcp.test")
st, res = api("PUT", f"/domains/{dom['domain_id']}/certificate", {"certificate": cert, "key": wrong_key})
check(st == 400, "a key that does not belong to the certificate is refused", f"{st} {res}")
st, up = api("PUT", f"/domains/{dom['domain_id']}/certificate", {"certificate": cert, "key": key})
check(st == 202 and up["certificate"]["source"] == "upload", "uploaded certificate accepted", f"{st} {up}")
wait_job(up["job_id"])

status, body = https("ssl1.xcp.test", cafile=certfile)
check(status.endswith("200 OK") and "ssl1.xcp.test</b> is hosted" in body, "the site is served over HTTPS with the uploaded certificate", status)
status, body = https("www.ssl1.xcp.test", cafile=certfile)
check(status.endswith("200 OK"), "www is served over HTTPS too", status)
status, _ = https("unknown.example")
check(" 403 " in status, "HTTPS for an unknown name gets the default host's error, not a site", status)
mode = oct(os.stat("/etc/xcp/ssl/sites/ssl1/ssl1.xcp.test.key").st_mode & 0o777)
check(mode == "0o600", "the private key file is root-only", mode)

st, d = api("PUT", f"/domains/{dom['domain_id']}/ssl", {"autossl": True, "force_https": True})
wait_job(d["job_id"])
check(raw("ssl1.xcp.test", "/page?x=1") == (301, "https://ssl1.xcp.test/page?x=1"), "force HTTPS redirects HTTP", str(raw("ssl1.xcp.test", "/page?x=1")))
token = "e2eTokenForTheChallengeCheck0123"
with open(f"/var/www/xcp-acme/{token}", "w") as f:
    f.write("challenge-answer")
os.chmod(f"/var/www/xcp-acme/{token}", 0o644)
st, _ = raw("ssl1.xcp.test", f"/.well-known/acme-challenge/{token}")
check(st == 200, "ACME challenges still work over HTTP with HTTPS forced", str(st))
os.remove(f"/var/www/xcp-acme/{token}")

# AutoSSL: this test name does not resolve in public DNS, so it is skipped with a reason.
st, before = api("GET", "/server/ssl")
st, res = api("PUT", "/server/ssl", {"enabled": True, "provider": "letsencrypt-staging", "hostname": before["hostname"]})
st, other = api("POST", f"/accounts/{a['id']}/domains", {"kind": "addon", "name": "nossl.xcp.test"})
wait_job(other["job_id"])
st, run = api("POST", f"/accounts/{a['id']}/ssl/run")
j = wait_job(run["job_id"])
st, doms = api("GET", f"/accounts/{a['id']}/ssl")
nossl = next(d for d in doms["items"] if d["domain"] == "nossl.xcp.test")
check(j["status"] == "succeeded" and nossl["status"] == "skipped" and "nossl.xcp.test" in nossl["detail"],
      "AutoSSL skips a name that does not point here and says why", f"{j.get('result')} {nossl}")
mine = next(d for d in doms["items"] if d["domain"] == "ssl1.xcp.test")
check(mine["status"] == "ok" and mine["detail"].startswith("uploaded certificate"), "AutoSSL keeps a valid uploaded certificate", str(mine))
api("PUT", "/server/ssl", {k: before[k] for k in ("enabled", "provider", "hostname", "email")} | {"directory_url": before["directory_url"]})

st, ref = api("DELETE", f"/domains/{dom['domain_id']}/certificate")
wait_job(ref["job_id"])
status, _ = https("ssl1.xcp.test")
check(" 403 " in status and raw("ssl1.xcp.test")[0] == 200, "without its certificate the site is HTTP only again (force HTTPS off)", status)

st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "ssl1"})
wait_job(t["job_id"])
check(not os.path.exists("/etc/xcp/ssl/sites/ssl1"), "termination removes the account's certificate files")
finish()
