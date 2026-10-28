#!/usr/bin/env python3
"""End-to-end website test, run as root on a server where XCP is installed.

It drives the XCP API (admin login from XCP_E2E_USER / XCP_E2E_PASSWORD) and
checks the result in Apache, PHP-FPM and the file system. Used by run.sh in CI.
"""
import http.cookiejar, json, os, ssl, subprocess, sys, time, urllib.request

API = "https://127.0.0.1:2443/api/v1"
ctx = ssl.create_default_context(cafile="/etc/xcp/ssl/panel.crt")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
csrf = ""
failures = 0


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if method != "GET" and csrf:
        req.add_header("X-CSRF-Token", csrf)
    try:
        with opener.open(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def site(host, path="/"):
    req = urllib.request.Request("http://127.0.0.1" + path, headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


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


st, res = api("POST", "/auth/login", {"username": os.environ.get("XCP_E2E_USER", "e2etest"),
                                     "password": os.environ.get("XCP_E2E_PASSWORD", "e2e test password 42")})
csrf = res["csrf_token"]
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

for user, aid in accts.items():
    st, a = api("POST", f"/accounts/{aid}/terminate", {"confirm": user})
    j = wait_job(a["job_id"])
    gone = not any(os.path.exists(p) for p in (f"/etc/apache2/xcp/vhosts/{user}.conf", f"/etc/php/8.3/fpm/pool.d/xcp-{user}.conf", f"/home/{user}"))
    check(j["status"] == "succeeded" and gone, f"{user}: terminated; vhost, pool and home removed", json.dumps(j))

st, body = site("site1.xcp.test")
check("hosted with XCP" not in body, "site1 no longer served after termination")
print(f"\n{failures} failure(s)")
sys.exit(1 if failures else 0)
