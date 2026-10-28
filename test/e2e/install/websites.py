#!/usr/bin/env python3
"""End-to-end website test, run as root on a server where XCP is installed.

It drives the XCP API (admin login from XCP_E2E_USER / XCP_E2E_PASSWORD) and
checks the result in Apache, PHP-FPM and the file system. Used by run.sh in CI.
"""
import grp, http.client, http.cookiejar, json, os, pwd, ssl, stat, subprocess, sys, time, urllib.request

API = "https://127.0.0.1:2443/api/v1"
ctx = ssl.create_default_context(cafile="/etc/xcp/ssl/panel.crt")
failures = 0


class Session:
    """One logged-in panel user, like one browser."""

    def __init__(self):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
        self.csrf = ""

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(API + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if method != "GET" and self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def login(self, username, password):
        st, res = self.call("POST", "/auth/login", {"username": username, "password": password})
        self.csrf = (res or {}).get("csrf_token", "")
        return st


def site(host, path="/"):
    req = urllib.request.Request("http://127.0.0.1" + path, headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def raw(host, path="/"):
    """One request without following redirects: status and Location."""
    c = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, r.getheader("Location", "")


def check(ok, what, detail=""):
    global failures
    print(("OK   " if ok else "FAIL ") + what + (f"  [{detail}]" if detail and not ok else ""))
    failures += 0 if ok else 1


def wait_job(job_id):
    for _ in range(120):
        st, j = api("GET", f"/jobs/{job_id}")
        if j and j["status"] in ("succeeded", "failed"):
            return j
        time.sleep(0.5)
    return {"status": "timeout"}


def as_user(user, path, content):
    subprocess.run(["runuser", "-u", user, "--", "tee", path], input=content.encode(), stdout=subprocess.DEVNULL, check=True)


admin = Session()
api = admin.call
admin.login(os.environ.get("XCP_E2E_USER", "e2etest"), os.environ.get("XCP_E2E_PASSWORD", "e2e test password 42"))
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, ver = api("GET", "/server/php-versions")
check(ver["items"] == ["8.3"], "server reports PHP versions " + str(ver["items"]))

accts = {}
for user in ("site1", "site2"):
    st, a = api("POST", "/accounts", {"username": user, "domain": f"{user}.xcp.test", "package_id": pkg, "password": "site password 1234"})
    j = wait_job(a["job_id"])
    accts[user] = a["id"]
    check(j["status"] == "succeeded" and j["result"].get("website") == "configured",
          f"{user}: account + website created (PHP {j.get('result', {}).get('php_version')})", json.dumps(j))

st, body = site("site1.xcp.test")
check(st == 200 and "site1.xcp.test</b> is hosted with XCP" in body, "site1 default page served by Apache", f"{st} {body[:80]}")
st, body = site("www.site2.xcp.test")
check(st == 200 and "site2.xcp.test" in body, "www alias of site2 works", f"{st} {body[:80]}")
st, body = site("unknown.example")
check("hosted with XCP" not in body, "an unknown host name does not get a customer's site", body[:80])

as_user("site1", "/home/site1/public_html/whoami.php",
        "<?php echo posix_getpwuid(posix_geteuid())['name'], '|', @file_get_contents('/etc/passwd') === false ? 'passwd-blocked' : 'PASSWD-READABLE', '|', ini_get('open_basedir');")
st, body = site("site1.xcp.test", "/whoami.php")
parts = body.split("|")
check(st == 200 and parts[0] == "site1", "PHP runs as the account's own user (site1)", body)
check(len(parts) > 1 and parts[1] == "passwd-blocked", "open_basedir blocks /etc/passwd", body)

as_user("site2", "/home/site2/public_html/peek.php",
        "<?php echo @file_get_contents('/home/site1/public_html/whoami.php') === false ? 'blocked' : 'LEAKED';")
st, body = site("site2.xcp.test", "/peek.php")
check(body == "blocked", "site2's PHP cannot read site1's files", body)

st, a = api("POST", f"/accounts/{accts['site1']}/suspend", {"reason": "web e2e"})
wait_job(a["job_id"])
st, body = site("site1.xcp.test", "/whoami.php")
check("currently suspended" in body and "site1|" not in body, "suspended site shows the notice and runs no PHP", body[:120])
check(not os.path.exists("/etc/php/8.3/fpm/pool.d/xcp-site1.conf"), "suspended site has no PHP-FPM pool")

st, a = api("POST", f"/accounts/{accts['site1']}/unsuspend")
wait_job(a["job_id"])
st, body = site("site1.xcp.test", "/whoami.php")
check(body.startswith("site1|"), "unsuspended site runs PHP again", body[:80])

# Domains: addon, subdomain, wildcard subdomain, alias, www choice, redirects.
s1 = accts["site1"]
st, doms = api("GET", f"/accounts/{s1}/domains")
primary = doms["items"][0]["id"]


def add_domain(body, account=s1):
    st, d = api("POST", f"/accounts/{account}/domains", body)
    if st != 202:
        return st, d
    return (200 if wait_job(d["job_id"])["status"] == "succeeded" else 500), d


results = [add_domain({"kind": "addon", "name": "shop1.xcp.test"})]
shop = results[0][1]
results += [add_domain({"kind": "sub", "name": "blog", "parent_id": primary}),
            add_domain({"kind": "sub", "name": "*", "parent_id": shop["id"]}),
            add_domain({"kind": "alias", "name": "alias1.xcp.test", "parent_id": shop["id"]})]
check(all(st == 200 for st, _ in results), "addon, subdomain, wildcard subdomain and alias added", str(results))
alias = results[3][1]

st, body = site("shop1.xcp.test")
check("<b>shop1.xcp.test</b> is hosted" in body, "addon domain serves its own new folder", body[:80])
fi = os.stat("/home/site1/domains/shop1.xcp.test")
check(pwd.getpwuid(fi.st_uid).pw_name == "site1" and grp.getgrgid(fi.st_gid).gr_name == "www-data" and stat.S_IMODE(fi.st_mode) == 0o750,
      "addon folder belongs to site1, group www-data, mode 0750", f"{fi.st_uid}:{fi.st_gid} {oct(fi.st_mode)}")
as_user("site1", "/home/site1/domains/shop1.xcp.test/who.php", "<?php echo posix_getpwuid(posix_geteuid())['name'];")
st, body = site("shop1.xcp.test", "/who.php")
check(body == "site1", "PHP of the addon domain runs as site1", body[:80])
st, body = site("blog.site1.xcp.test")
check("<b>blog.site1.xcp.test</b> is hosted" in body, "subdomain serves its own folder", body[:80])
as_user("site1", "/home/site1/domains/_wildcard.shop1.xcp.test/index.html", "WILDCARD")
st, body = site("anything.shop1.xcp.test")
check(body == "WILDCARD", "wildcard subdomain catches other names", body[:80])
st, body = site("www.shop1.xcp.test")
check(body != "WILDCARD" and "shop1.xcp.test" in body, "wildcard does not catch names another vhost serves", body[:80])
st, body = site("alias1.xcp.test", "/who.php")
check(body == "site1", "alias shows the addon domain's site", body[:80])

st, d = api("PUT", f"/domains/{shop['id']}", {"docroot": shop["docroot"], "canonical": "www"})
wait_job(d["job_id"])
check(raw("shop1.xcp.test", "/x?y=1") == (301, "http://www.shop1.xcp.test/x?y=1") and raw("www.shop1.xcp.test")[0] == 200,
      "www chosen: example.com redirects to www.example.com", str(raw("shop1.xcp.test", "/x?y=1")))

for body in ({"path": "/old", "target": "https://example.org/new", "code": 301, "keep_path": True},
             {"path": "/go", "target": "https://example.org/landing?src=xcp", "code": 302}):
    st, r = api("POST", f"/domains/{primary}/redirects", body)
    wait_job(r["job_id"])
check(raw("site1.xcp.test", "/old/page") == (301, "https://example.org/new/page"), "redirect keeping the path", str(raw("site1.xcp.test", "/old/page")))
check(raw("site1.xcp.test", "/go/deeper") == (302, "https://example.org/landing?src=xcp"), "redirect to a fixed URL", str(raw("site1.xcp.test", "/go/deeper")))
check(raw("site1.xcp.test", "/older")[0] not in (301, 302), "redirect matches whole path segments only", str(raw("site1.xcp.test", "/older")))

user2 = Session()
user2.login("site2", "site password 1234")
st, res = user2.call("POST", f"/accounts/{accts['site2']}/domains", {"kind": "addon", "name": "evil.site1.xcp.test"})
check(st == 409 and res.get("code") == "verification_required", "another account cannot take a name under site1's domain", f"{st} {res}")

st, d = api("DELETE", f"/domains/{alias['id']}")
wait_job(d["job_id"])
st, body = site("alias1.xcp.test", "/who.php")
check(body != "site1", "removed alias is no longer served", body[:80])

# Symlinks: Apache reads every public_html (group www-data), so it must only
# follow a link whose target has the link's owner, the document root included.
def ln_as(user, target, link):
    subprocess.run(["runuser", "-u", user, "--", "ln", "-sfn", target, link], check=True)


as_user("site2", "/home/site2/public_html/secret.txt", "SITE2-SECRET")
ln_as("site1", "/home/site2/public_html/secret.txt", "/home/site1/public_html/s2.txt")
st, body = site("site1.xcp.test", "/s2.txt")
check("SITE2-SECRET" not in body, "a symlink to another account's file is not followed", f"{st} {body[:40]}")
ln_as("site1", "/home/site1/public_html/whoami.php", "/home/site1/public_html/mine.txt")
st, body = site("site1.xcp.test", "/mine.txt")
check(st == 200 and "posix_getpwuid" in body, "a symlink to the account's own file works", f"{st} {body[:40]}")
subprocess.run(["runuser", "-u", "site1", "--", "mv", "/home/site1/domains/shop1.xcp.test", "/home/site1/domains/shop1.saved"], check=True)
ln_as("site1", "/home/site2/public_html", "/home/site1/domains/shop1.xcp.test")
st, body = site("www.shop1.xcp.test", "/secret.txt")
check("SITE2-SECRET" not in body, "a document root swapped for a link to another account is not served", f"{st} {body[:40]}")

for user, aid in accts.items():
    st, a = api("POST", f"/accounts/{aid}/terminate", {"confirm": user})
    j = wait_job(a["job_id"])
    left = [p for p in (f"/etc/apache2/xcp/vhosts/{user}.conf", f"/etc/apache2/xcp/wildcards/{user}.conf",
                        f"/etc/php/8.3/fpm/pool.d/xcp-{user}.conf", f"/home/{user}") if os.path.exists(p)]
    check(j["status"] == "succeeded" and not left, f"{user}: terminated; vhosts, pool and home removed", json.dumps(j) + str(left))

st, body = site("site1.xcp.test")
check("hosted with XCP" not in body, "site1 no longer served after termination")
st, body = site("anything.shop1.xcp.test")
check(body != "WILDCARD", "wildcard no longer served after termination")
print(f"\n{failures} failure(s)")
sys.exit(1 if failures else 0)
