#!/usr/bin/env python3
"""End-to-end ACME test against Pebble (Let's Encrypt's test CA), run as root
on a server where XCP is installed. Used by run.sh.

Pebble runs on localhost; it looks names up in our PowerDNS and checks
HTTP-01 answers through Apache, like Let's Encrypt would on the internet.
The server's resolver points to PowerDNS for the test, so xcp-api's "does
it point here" check sees the same. Everything is restored at the end.
"""
import json, os, socket, sqlite3, ssl, subprocess, tempfile, time, urllib.request

from xcpe2e import admin, check, finish

PEBBLE = os.environ.get("PEBBLE", "/opt/xcp/pebble")
admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
tmp = tempfile.mkdtemp()


def openssl_cert(name):
    """A self-signed certificate for Pebble's own HTTPS listener."""
    cert, key = os.path.join(tmp, "pebble.crt"), os.path.join(tmp, "pebble.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=" + name,
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"], check=True, capture_output=True)
    return cert, key


def tls_name(port, name, cafile):
    """Connects to this server with SNI name and checks the certificate against cafile."""
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=name) as s:
                if port == 443:
                    s.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                    data = b""
                    while chunk := s.recv(65536):
                        data += chunk
                    return True, data.decode(errors="replace")
                return True, ""
    except (ssl.SSLError, OSError) as e:
        return False, str(e)


class Resolver:
    """Points this server's resolver at PowerDNS, and back."""

    path = "/etc/resolv.conf"

    def __enter__(self):
        self.link = os.readlink(self.path) if os.path.islink(self.path) else None
        self.content = None if self.link else open(self.path).read()
        if self.link:
            os.remove(self.path)  # a shared file (WSL): replace the link, do not write through it
        with open(self.path, "w") as f:  # in Docker a bind mount: rewrite it in place
            f.write("nameserver 127.0.0.1\n")
        time.sleep(6)  # Go re-reads resolv.conf at most every 5 seconds
        return self

    def __exit__(self, *exc):
        if self.link:
            os.remove(self.path)
            os.symlink(self.link, self.path)
        else:
            with open(self.path, "w") as f:
                f.write(self.content)


cert, key = openssl_cert("pebble")
config = os.path.join(tmp, "pebble.json")
with open(config, "w") as f:
    json.dump({"pebble": {
        "listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
        "certificate": cert, "privateKey": key, "httpPort": 80, "tlsPort": 443,
        "ocspResponderURL": "", "externalAccountBindingRequired": False,
        "retryAfter": {"authz": 1, "order": 1},
        "profiles": {"default": {"description": "default", "validityPeriod": 7776000}},
    }}, f)
env = dict(os.environ, PEBBLE_VA_NOSLEEP="1", PEBBLE_WFE_NONCEREJECT="0")
pebble = subprocess.Popen([PEBBLE, "-config", config, "-dnsserver", "127.0.0.1:53"], env=env,
                          stdout=open(os.path.join(tmp, "pebble.log"), "w"), stderr=subprocess.STDOUT)
pebble_ctx = ssl.create_default_context(cafile=cert)
for _ in range(50):
    try:
        urllib.request.urlopen("https://127.0.0.1:14000/dir", context=pebble_ctx, timeout=2).read()
        break
    except OSError:
        time.sleep(0.2)
root = os.path.join(tmp, "pebble-root.pem")
with open(root, "wb") as f:
    f.write(urllib.request.urlopen("https://127.0.0.1:15000/roots/0", context=pebble_ctx).read())

st, ssl_before = api("GET", "/server/ssl")
st, dns = api("GET", "/server/dns")
ip = dns["ipv4"]
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
try:
    with Resolver():
        st, res = api("PUT", "/server/ssl", {
            "enabled": True, "provider": "custom", "directory_url": "https://127.0.0.1:14000/dir",
            "ca_bundle": open(cert).read(), "email": "e2e@xcp.test", "hostname": "panel.acme1.xcp.test",
        })
        check(st == 200, "AutoSSL set up for Pebble", str(res))
        st, a = api("POST", "/accounts", {"username": "acme1", "domain": "acme1.xcp.test", "package_id": pkg, "password": "acme password 1234"})
        wait_job(a["job_id"])
        st, zones = api("GET", f"/dns/zones?account_id={a['id']}")
        st, r = api("POST", f"/dns/zones/{zones['items'][0]['id']}/records", {"name": "panel", "type": "A", "content": ip})
        wait_job(r["job_id"])
        for _ in range(60):  # until PowerDNS serves the new zone
            if ip in subprocess.run(["dig", "@127.0.0.1", "+short", "panel.acme1.xcp.test"], capture_output=True, text=True).stdout:
                break
            time.sleep(0.5)

        st, run = api("POST", "/server/ssl/run")
        j = wait_job(run["job_id"])
        result = j.get("result") or {}
        check(j["status"] == "succeeded" and result.get("issued", 0) >= 1, "AutoSSL issued a certificate through ACME", json.dumps(j))
        check(str(result.get("hostname", "")).startswith("ok"), "the server's host name got its certificate", str(result.get("hostname")))
        st, doms = api("GET", f"/accounts/{a['id']}/ssl")
        d = doms["items"][0]
        check(d["status"] == "ok" and d["certificate"]["source"] == "acme" and set(d["certificate"]["names"]) == {"acme1.xcp.test", "www.acme1.xcp.test"},
              "the domain's certificate covers it and www", json.dumps(d))

        # The site job applies the certificate; then Apache serves it with Pebble's chain.
        for _ in range(60):
            served, body = tls_name(443, "acme1.xcp.test", root)
            if served:
                break
            time.sleep(0.5)
        check(served and "acme1.xcp.test</b> is hosted" in body, "Apache serves the site with the ACME certificate (chain checked)", body[:200])
        check(tls_name(443, "www.acme1.xcp.test", root)[0], "and for www")
        for _ in range(90):  # xcp-api looks for a new host name certificate every 30 seconds
            panel_ok, err = tls_name(2443, "panel.acme1.xcp.test", root)
            if panel_ok:
                break
            time.sleep(0.5)
        check(panel_ok, "the panel serves the host name certificate to clients asking for that name", err)
        check(tls_name(2443, "127.0.0.1", "/etc/xcp/ssl/panel.crt")[0], "and its own certificate to local tools by IP")
        st, again = api("POST", f"/accounts/{a['id']}/ssl/run")
        result = wait_job(again["job_id"]).get("result") or {}
        check(result.get("issued") == 0 and result.get("ok", 0) >= 1, "a second run keeps the valid certificate", str(result))

        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "acme1"})
        wait_job(t["job_id"])
finally:
    body = {k: ssl_before[k] for k in ("enabled", "provider", "directory_url", "ca_bundle", "eab_key_id", "email", "hostname")}
    api("PUT", "/server/ssl", body)
    # The test's host name certificate must not stay around.
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
