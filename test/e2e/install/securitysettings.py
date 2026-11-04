#!/usr/bin/env python3
"""End-to-end test of the security settings (ADR-0018, 0019 and the password
rules), run as root on a server where XCP is installed: password rules apply
to every service, SSH settings are refused when they would lock everyone out,
and the policy values are validated."""
from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "security test password 1234"

st, items = api("GET", "/server/settings")
keys = {i["key"]: i for i in items["items"]}
for k in ("security.password_min_length", "security.password_classes", "auth.require_2fa", "ssh.password_auth", "ssh.root_login"):
    check(k in keys, f"setting {k} exists", "")
check(keys["auth.require_2fa"]["value"] == "none" and keys["ssh.password_auth"]["value"] is True, "defaults are off / on", "")

# Validation.
for bad in ({"auth.require_2fa": "everyone"}, {"ssh.root_login": "maybe"}, {"security.password_min_length": 3}, {"security.password_classes": 9}):
    st, r = api("PUT", "/server/settings", {"values": bad})
    check(st == 400, f"{bad} is refused", f"{st}")

# SSH: passwords cannot be switched off while no login has a key.
import glob, os
has_key = any(os.path.getsize(f) > 0 for f in glob.glob("/home/*/.ssh/authorized_keys") + ["/root/.ssh/authorized_keys"] if os.path.exists(f))
if not has_key:
    st, r = api("PUT", "/server/settings", {"values": {"ssh.password_auth": False}})
    check(st == 400, "switching SSH passwords off with no key anywhere is refused", f"{st} {r}")
    st, items = api("GET", "/server/settings")
    check({i["key"]: i for i in items["items"]}["ssh.password_auth"]["value"] is True, "and the setting stays as it was", "")

# Password rules reach every service.
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "sec1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "sec1"})
        wait_job(t["job_id"])
try:
    st, r = api("PUT", "/server/settings", {"values": {"security.password_min_length": 14, "security.password_classes": 3}})
    check(st == 200, "the password rules are set", f"{st} {r}")
    st, r = api("POST", "/accounts", {"username": "sec1", "domain": "sec1.xcp.test", "package_id": pkg, "password": "twelvechars1"})
    check(st == 400, "a 12-character password is too short now", f"{st}")
    st, r = api("POST", "/accounts", {"username": "sec1", "domain": "sec1.xcp.test", "package_id": pkg, "password": "alllowercaseletters"})
    check(st == 400, "a password of one kind of character is refused", f"{st}")
    st, a = api("POST", "/accounts", {"username": "sec1", "domain": "sec1.xcp.test", "package_id": pkg, "password": "Mixed-Case-Pass-1"})
    check(st in (200, 201, 202), "a password that follows the rules is accepted", f"{st} {a}")
    if st in (200, 201, 202):
        wait_job(a["job_id"])
        user = Session()
        user.login("sec1", "Mixed-Case-Pass-1")
        st, r = user.call("POST", "/me/password", {"current_password": "Mixed-Case-Pass-1", "new_password": "short"})
        check(st == 400, "changing to a weak password is refused", f"{st}")
        st, mb = user.call("POST", f"/accounts/{a['id']}/ftp", {"name": "weak", "password": "weakpassword1", "folder": ""})
        check(st == 400, "so is an FTP password", f"{st}")
finally:
    api("PUT", "/server/settings", {"values": {"security.password_min_length": 10, "security.password_classes": 1}})
    st, existing = api("GET", "/accounts")
    for a in existing["items"]:
        if a["username"] == "sec1":
            st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "sec1"})
            wait_job(t["job_id"])
finish()
