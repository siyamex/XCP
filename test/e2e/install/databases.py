#!/usr/bin/env python3
"""End-to-end test of MariaDB databases and phpMyAdmin sign-on (P1 #7,
ADR-0006), run as root on a server where XCP is installed. Used by run.sh."""
import http.cookiejar, os, re, subprocess, time, urllib.error, urllib.request

from xcpe2e import Session, _ctx, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "db test password 1234"


def sql(user, password, query, db=None):
    """Runs a query as a MariaDB user; returns (ok, output)."""
    args = ["mariadb", "-N", "-B", "-u", user, "-e", query] + ([db] if db else [])
    r = subprocess.run(args, capture_output=True, text=True, env=dict(os.environ, MYSQL_PWD=password))
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def root_sql(query):
    r = subprocess.run(["mariadb", "-N", "-B", "-r", "-e", query], capture_output=True, text=True, check=True)
    return r.stdout.strip()


def https(path, opener=None, host="127.0.0.1"):
    """GET on Apache's HTTPS port; returns (status, body, final URL)."""
    opener = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx))
    req = urllib.request.Request("https://127.0.0.1" + path, headers={"Host": host})
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read().decode(errors="replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), path


st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] in ("db1", "db2"):  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
        wait_job(t["job_id"])
accts = {}
for name in ("db1", "db2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": pkg, "password": PW})
    check(st == 202, f"account {name} created", str(a))
    wait_job(a["job_id"])
    accts[name] = a["id"]

user = Session()
user.login("db1", PW)
st, w = user.call("POST", f"/accounts/{accts['db1']}/database-wizard", {"database": "shop", "user": "app", "password": PW})
check(st == 202 and w["database"]["name"] == "db1_shop" and w["user"]["name"] == "db1_app" and w["host"] == "localhost",
      "the wizard creates db1_shop and db1_app with all privileges", str(w))
check(user.wait_job(w["job_id"])["status"] == "succeeded", "and the job applies it")
ok, out = sql("db1_app", PW, "CREATE TABLE items (id INT PRIMARY KEY, name VARCHAR(20)); INSERT INTO items VALUES (1, 'apple')", "db1_shop")
check(ok, "the new user creates a table and writes to it", out)
check(root_sql("SELECT Db FROM mysql.db WHERE User = 'db1_app'") == r"db1\_shop",
      "the grant names the database with _ escaped, so it matches no other name", root_sql("SELECT Db FROM mysql.db WHERE User = 'db1_app'"))

st, o = user.call("GET", f"/accounts/{accts['db1']}/databases")
check(st == 200 and o["server"] == "ok" and o["databases"][0]["size_bytes"] > 0 and o["databases"][0]["users"][0]["name"] == "db1_app",
      "the overview shows the database's size and who may use it", str(o))

# Another account sees nothing of it.
user2 = Session()
user2.login("db2", PW)
st, u2 = user2.call("POST", f"/accounts/{accts['db2']}/database-users", {"name": "other", "password": PW})
user2.wait_job(u2["job_id"])
ok, out = sql("db2_other", PW, "SELECT * FROM items", "db1_shop")
check(not ok and "denied" in out, "another account's user cannot read the database", out)
st, res = user2.call("GET", f"/accounts/{accts['db1']}/databases")
check(st == 404, "nor see it in the panel", str(st))
st, res = user2.call("PUT", f"/database-users/{u2['id']}/grants/{w['database']['id']}", {"privileges": ["ALL"]})
check(st == 404, "nor grant itself access", f"{st} {res}")

# Custom privileges, a new password.
st, r = user.call("PUT", f"/database-users/{w['user']['id']}/grants/{w['database']['id']}", {"privileges": ["SELECT"]})
user.wait_job(r["job_id"])
check(sql("db1_app", PW, "SELECT name FROM items", "db1_shop") == (True, "apple") and
      not sql("db1_app", PW, "INSERT INTO items VALUES (2, 'pear')", "db1_shop")[0], "SELECT only: reads work, writes are refused")
new_pw = "another db password 5678"
st, r = user.call("PUT", f"/database-users/{w['user']['id']}/password", {"password": new_pw})
user.wait_job(r["job_id"])
check(not sql("db1_app", PW, "SELECT 1")[0] and sql("db1_app", new_pw, "SELECT 1")[0], "a new password replaces the old one")

# Rename keeps the data and moves the privileges; a view blocks it.
st, d = user.call("PUT", f"/databases/{w['database']['id']}", {"name": "store"})
check(st == 202 and d["name"] == "db1_store", "rename to db1_store", f"{st} {d}")
user.wait_job(d["job_id"])
check(sql("db1_app", new_pw, "SELECT name FROM items", "db1_store") == (True, "apple"), "the data and the user's access moved with it",
      str(sql("db1_app", new_pw, "SELECT name FROM items", "db1_store")))
check("db1_shop" not in root_sql("SHOW DATABASES"), "the old name is gone")
root_sql("CREATE VIEW db1_store.v AS SELECT name FROM db1_store.items")
st, res = user.call("PUT", f"/databases/{w['database']['id']}", {"name": "other"})
check(st == 409 and res.get("code") == "rename_refused", "a database with a view is not renamed", f"{st} {res}")
root_sql("DROP VIEW db1_store.v")

# phpMyAdmin: a one-time sign-on with access to the account's databases only.
st, s = user.call("POST", f"/accounts/{accts['db1']}/phpmyadmin")
url = (s or {}).get("url", "")
check(st == 200 and url.startswith("https://127.0.0.1/phpmyadmin/xcp-signon.php?ticket="), "phpMyAdmin sign-on gives a URL", f"{st} {s}")
jar = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx), urllib.request.HTTPCookieProcessor(jar))
path = url.removeprefix("https://127.0.0.1")
code, body, final = https(path, browser)
check(code == 200 and final.endswith("/phpmyadmin/index.php"), "the ticket signs in and lands in phpMyAdmin", f"{code} {final} {body[:300]}")
code, body, _ = https("/phpmyadmin/index.php?route=/server/databases", browser)
check(code == 200 and "db1_store" in body and "db2_" not in body and "mysql" not in re.findall(r'data-filter-row="([^"]+)"', body),
      "phpMyAdmin lists the account's database and nothing else", body[:300])
sso = root_sql("SELECT User FROM mysql.global_priv WHERE User LIKE 'xcp\\_sso\\_db1\\_%'")
check(len(sso.splitlines()) == 1 and root_sql(f"SELECT Db FROM mysql.db WHERE User = '{sso}'") == r"db1\_store",
      "as a temporary user with access to db1_store only", sso)
code, body, _ = https(path)
check(code == 403, "the ticket works once", f"{code} {body[:200]}")
code, body, _ = https("/phpmyadmin/libraries/classes/Config.php")
check(code == 403, "phpMyAdmin's code folders are not served", str(code))
code, body, _ = https("/phpmyadmin/setup/")
check(code == 404, "its setup wizard is not installed", str(code))
code, body, _ = https("/phpmyadmin/", host="db1.xcp.test")
check(code == 403, "a customer's domain does not serve phpMyAdmin", f"{code} {body[:200]}")

# Suspension locks the users; the root password is a second way in.
st, a = api("POST", f"/accounts/{accts['db1']}/suspend", {"reason": "e2e"})
wait_job(a["job_id"])
ok, out = sql("db1_app", new_pw, "SELECT 1")
check(not ok and "locked" in out.lower(), "a suspended account's database users are locked", out)
check(root_sql("SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'xcp\\_sso\\_db1\\_%'") == "0", "and its phpMyAdmin users dropped")
st, a = api("POST", f"/accounts/{accts['db1']}/unsuspend")
wait_job(a["job_id"])
check(sql("db1_app", new_pw, "SELECT 1")[0], "unsuspending unlocks them")
user.login("db1", PW)  # suspending ended the user's sessions
root_pw = "mariadb root password 99"
st, res = api("PUT", "/server/mysql/root-password", {"password": root_pw})
r = subprocess.run(["runuser", "-u", "nobody", "--", "mariadb", "-u", "root", "-N", "-e", "SELECT CURRENT_USER()"],
                   capture_output=True, text=True, env=dict(os.environ, MYSQL_PWD=root_pw))
check(st == 204 and r.returncode == 0, "the admin sets a root password that works", f"{st} {r.stderr}")
check(root_sql("SELECT 1") == "1", "and root on the server still gets in through the socket")
st, s = api("GET", "/server/mysql")
check(st == 200 and s["installed"] and s["version"].startswith("10.") and s["phpmyadmin"] == "5.2.3", "the server status shows both versions", str(s))

# Removing.
st, r = user.call("DELETE", f"/databases/{w['database']['id']}")
check(st == 202, "delete the database", f"{st} {r}")
user.wait_job((r or {}).get("job_id", ""))
check("db1_store" not in root_sql("SHOW DATABASES") and root_sql("SELECT COUNT(*) FROM mysql.db WHERE User = 'db1_app'") == "0",
      "deleting a database drops it and the privileges on it")
for name, id_ in accts.items():
    st, t = api("POST", f"/accounts/{id_}/terminate", {"confirm": name})
    wait_job(t["job_id"])
left = root_sql("SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'db1\\_%' OR User LIKE 'db2\\_%'")
check(left == "0" and not re.search(r"^db[12]_", root_sql("SHOW DATABASES"), re.M), "terminating removes all databases and users", left)
finish()
