#!/usr/bin/env python3
"""End-to-end test of resellers (ADR-0023), run as root on a server where
XCP is installed: an admin makes resellers with limits; a reseller makes
packages and customer accounts inside them and sees only its own; the
customer's account really exists on the server."""
import os, pwd

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "reseller test password 1234"


def clean():
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"].startswith("rsc"):
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
            wait_job(t["job_id"])


clean()
st, rs = api("GET", "/resellers")
have = {r["username"] for r in rs["items"]}

def make(name, limits):
    if name in have:
        return next(r for r in rs["items"] if r["username"] == name)
    st, r = api("POST", "/resellers", {"username": name, "password": PW, "email": name + "@example.test", "limits": limits})
    check(st == 201, f"admin creates reseller {name}", f"{st} {r}")
    return r

r1 = make("rsl1", {"max_accounts": 2, "disk_mb": 300, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False})
r2 = make("rsl2", {"max_accounts": None, "disk_mb": None, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False})
st, r = api("PUT", f"/resellers/{r1['id']}/limits", {"max_accounts": 2, "disk_mb": 300, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False})
check(st == 200 and r["limits"]["max_accounts"] == 2, "admin sets limits", f"{st}")

a1, a2 = Session(), Session()
a1.login("rsl1", PW)
a2.login("rsl2", PW)

# Only admins manage resellers; resellers have their own pages.
for s, who in ((a1, "a reseller"),):
    st, _ = s.call("GET", "/resellers")
    check(st == 403, f"{who} cannot list resellers", f"{st}")
    st, _ = s.call("POST", "/resellers", {"username": "evil", "password": PW})
    check(st == 403, f"{who} cannot make resellers", f"{st}")
    st, _ = s.call("PUT", f"/resellers/{r1['id']}/limits", {"max_accounts": None, "disk_mb": None, "bandwidth_mb": None, "oversell_disk": True, "oversell_bandwidth": True})
    check(st == 403, f"{who} cannot raise its own limits", f"{st}")
    st, _ = s.call("GET", "/server/status")
    check(st == 403, f"{who} cannot read the server's status", f"{st}")
    st, _ = s.call("GET", "/server/firewall")
    check(st == 403, f"{who} cannot read the firewall", f"{st}")
st, ov = a1.call("GET", "/reseller/overview")
check(st == 200 and ov["limits"]["disk_mb"] == 300 and ov["usage"]["accounts"] == 0, "a reseller sees its overview", f"{st} {ov}")
st, _ = admin_session.call("GET", "/reseller/overview")
check(st == 403, "an admin has no reseller overview", f"{st}")

# Packages: its own, from the admin's feature lists.
st, fl = a1.call("GET", "/feature-lists")
check(st == 200 and len(fl["items"]) > 0, "a reseller sees the admin's feature lists", f"{st}")
fl_id = fl["items"][0]["id"]
st, _ = a1.call("POST", "/feature-lists", {"name": "mine", "features": []})
check(st == 403, "but cannot make one", f"{st}")
st, p1 = a1.call("GET", "/packages")
for p in p1["items"]:
    a1.call("DELETE", f"/packages/{p['id']}")
def pkg(s, name, disk):
    limits = {k: None for k in ("disk_mb", "inodes", "bandwidth_mb", "addon_domains", "subdomains", "aliases", "mailboxes", "mailbox_mb", "forwarders", "mail_per_hour", "databases", "db_users", "ftp_accounts", "cron_jobs", "cpu_percent", "memory_mb", "processes", "io_mbps")}
    limits.update({"disk_mb": disk, "shell": "none", "php_versions": [], "dedicated_ip": False})
    return s.call("POST", "/packages", {"name": name, "feature_list_id": fl_id, "limits": limits})
st, small = pkg(a1, "Small", 100)
check(st in (200, 201), "a reseller makes a package", f"{st} {small}")
st, big = pkg(a1, "Big", 250)
st, any_ = pkg(a1, "Nolimit", None)
st, mine = a1.call("GET", "/packages")
check({p["name"] for p in mine["items"]} == {"Small", "Big", "Nolimit"}, "and lists only its own", str(mine))
st, theirs = a2.call("GET", "/packages")
check(theirs["items"] == [], "the other reseller sees none of them", str(theirs))
st, _ = a2.call("GET", f"/packages/{small['id']}")
check(st == 404, "nor reads one", f"{st}")

# Accounts inside the limits.
def acct(s, name, package):
    return s.call("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": package["id"], "password": PW})
st, c1 = acct(a1, "rsc1", small)
check(st == 202 or st == 201, "a reseller creates a customer account", f"{st} {c1}")
wait_job(c1["job_id"])
check(c1["owner_id"] == r1["id"], "owned by the reseller", str(c1))
try:
    pwd.getpwnam("rsc1")
    check(True, "its Linux user exists")
except KeyError:
    check(False, "its Linux user exists")
st, c = acct(a1, "rsc2", any_)
check(st == 409, "a package without a disk limit under a disk cap is refused", f"{st} {c}")
st, c = acct(a1, "rsc2", big)
check(st == 409, "100 + 250 MB over the 300 MB cap is refused", f"{st} {c}")
st, c2 = acct(a1, "rsc2", small)
check(st in (200, 201, 202), "100 + 100 MB fits", f"{st} {c2}")
if st in (200, 201, 202):
    wait_job(c2["job_id"])
st, c = acct(a1, "rsc3", small)
check(st == 409, "a third account over the limit of 2 is refused", f"{st} {c}")

# Overview now.
st, ov = a1.call("GET", "/reseller/overview")
check(ov["usage"]["accounts"] == 2 and ov["usage"]["disk_mb"] == 200, "the overview counts what was given out", str(ov["usage"]))

# Isolation.
st, l2 = a2.call("GET", "/accounts")
check(l2["items"] == [], "the other reseller sees no accounts", str(l2))
st, _ = a2.call("GET", f"/accounts/{c1['id']}")
check(st == 404, "nor reads one", f"{st}")
st, _ = a2.call("POST", f"/accounts/{c1['id']}/suspend", {"reason": "x"})
check(st == 404, "nor suspends one", f"{st}")
st, _ = a2.call("POST", f"/accounts/{c1['id']}/impersonate")
check(st == 404, "nor signs in as its customer", f"{st}")
st, la = admin_session.call("GET", "/accounts")
check({"rsc1", "rsc2"} <= {a["username"] for a in la["items"]}, "the admin sees all accounts", "")

# The reseller manages its customer; the customer signs in.
st, _ = a1.call("POST", f"/accounts/{c1['id']}/suspend", {"reason": "overdue"})
check(st in (200, 202), "a reseller suspends its customer", f"{st}")
st, _ = a1.call("POST", f"/accounts/{c1['id']}/unsuspend")
check(st in (200, 202), "and reactivates it", f"{st}")
cust = Session()
cust.login("rsc1", PW)
st, me = cust.call("GET", "/me")
check(st == 200 and me["role"] == "user", "the customer signs in", f"{st}")
st, _ = cust.call("GET", "/resellers")
check(st == 403, "the customer cannot use reseller pages", f"{st}")

# Signing in as the customer (RSL-ACC-05).
imp = Session()
imp.login("rsl1", PW)
st, _ = imp.call("POST", "/me/reauth", {"password": PW})
st, r = imp.call("POST", f"/accounts/{c1['id']}/impersonate")
check(st == 200, "a reseller signs in as its customer", f"{st} {r}")
if st == 200:
    imp.csrf = r["csrf_token"]
    st, me = imp.call("GET", "/me")
    check(me["username"] == "rsc1" and me.get("impersonator_id") == r1["id"], "as the customer, marked as impersonated", str(me))
    st, _ = imp.call("POST", "/me/password", {"current_password": PW, "new_password": "something else entirely 12"})
    check(st == 403, "and cannot change the customer's password", f"{st}")
    st, _ = imp.call("GET", "/reseller/overview")
    check(st == 403, "and is not a reseller any more", f"{st}")

# Privileges: without them the action is refused.
privs = ["create", "modify", "suspend", "password", "impersonate"]
st, r = api("PUT", f"/resellers/{r1['id']}/limits", {"max_accounts": 2, "disk_mb": 300, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False, "privileges": privs})
check(st == 200 and "terminate" not in r["limits"]["privileges"], "an admin takes a privilege away", f"{st} {r}")
st, _ = a1.call("POST", f"/accounts/{c2['id']}/terminate", {"confirm": "rsc2"})
check(st == 403, "the reseller can no longer terminate", f"{st}")
st, _ = api("PUT", f"/resellers/{r1['id']}/limits", {"max_accounts": 2, "disk_mb": 300, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False, "privileges": ["fly"]})
check(st == 400, "an unknown privilege is refused", f"{st}")
api("PUT", f"/resellers/{r1['id']}/limits", {"max_accounts": 2, "disk_mb": 300, "bandwidth_mb": None, "oversell_disk": False, "oversell_bandwidth": False})

# Suspended reseller cannot sign in.
st, _ = api("POST", f"/resellers/{r2['id']}/suspend")
check(st == 200, "an admin suspends a reseller", f"{st}")
s = Session()
check(s.login("rsl2", PW) != 200, "a suspended reseller cannot sign in")
api("POST", f"/resellers/{r2['id']}/unsuspend")

clean()
finish()
