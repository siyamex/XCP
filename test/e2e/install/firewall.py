#!/usr/bin/env python3
"""End-to-end test of the firewall (ADR-0017), run as root on a server where
XCP is installed: rules reach the kernel, bans and lifting them, restricting
a service, a closed policy that keeps the panel open, and switching it off."""
import json, subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "firewall test password 1234"


def nft():
    r = subprocess.run(["nft", "list", "table", "inet", "xcp"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def until(cond, what, secs=40):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.5)
    check(False, what, "timed out")
    return False


def save(cfg):
    st, r = api("PUT", "/server/firewall", cfg)
    check(st == 200, "saving the firewall works", f"{st} {r}")
    if st == 200:
        wait_job(r["job_id"])
    return r


# Only admins.
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "fw1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "fw1"})
        wait_job(t["job_id"])
st, a = api("POST", "/accounts", {"username": "fw1", "domain": "fw1.xcp.test", "package_id": pkg, "password": PW})
wait_job(a["job_id"])
user = Session()
user.login("fw1", PW)
st, r = user.call("GET", "/server/firewall")
check(st == 403, "a user cannot read the firewall", f"{st}")
st, r = user.call("PUT", "/server/firewall", {})
check(st == 403, "a user cannot change the firewall", f"{st}")
st, r = user.call("POST", "/server/firewall/bans", {"ip": "203.0.113.1"})
check(st == 403, "a user cannot ban", f"{st}")

# The default is off and open.
st, o = api("GET", "/server/firewall")
check(st == 200 and o["panel_port"] > 0, "the firewall can be read", f"{st}")
cfg = o["config"]
check(cfg["policy"] == "open" and not cfg["enabled"], "it starts off and open", f"{cfg['policy']} {cfg['enabled']}")
check(any(p["port"] == "22" for p in cfg["ports"]) and any(p["port"] == str(o["panel_port"]) for p in cfg["ports"]),
      "the default ports hold SSH and the panel")

# Bad input is refused.
for bad in (
    {**cfg, "allow": [{"cidr": "not-an-address", "comment": ""}]},
    {**cfg, "policy": "maybe"},
    {**cfg, "ports": [{"port": "80; flush ruleset", "proto": "tcp", "comment": ""}]},
    {**cfg, "restrict": {"mysql": ["192.0.2.1"]}},
    {**cfg, "brute": {**cfg["brute"], "threshold": 1}},
):
    st, r = api("PUT", "/server/firewall", bad)
    check(st == 400, "bad firewall input is refused", f"{st}")
check(nft() is None, "nothing was loaded by the refused changes")

# Turn it on with a deny entry and a network allowed to reach SSH only.
cfg = {**cfg, "enabled": True,
       "deny": [{"cidr": "203.0.113.77", "comment": "test"}],
       "allow": [{"cidr": "198.51.100.0/24", "comment": "office"}],
       "restrict": {"ssh": ["198.51.100.0/24", "2001:db8::/32"]}}
r = save(cfg)
rules = nft() or ""
check("203.0.113.77" in rules, "the deny entry is in the kernel", rules[:300])
check("198.51.100.0/24" in rules, "the allow entry is in the kernel")
check("2001:db8::/32" in rules, "the IPv6 network of the SSH restriction is in the kernel")
check(subprocess.run(["test", "-s", "/etc/xcp/firewall.nft"]).returncode == 0, "the rules are kept for the next boot")
check(subprocess.run(["systemctl", "is-enabled", "xcp-firewall"], capture_output=True).returncode == 0, "xcp-firewall.service is enabled")
r = subprocess.run(["nft", "-c", "-f", "/etc/xcp/firewall.nft"], capture_output=True, text=True)
check(r.returncode == 0, "the saved file is a valid script", r.stderr[:200])
# Our own address is never shut out: the panel still answers.
st, o = api("GET", "/server/firewall")
check(st == 200, "the panel still answers with the firewall on", f"{st}")

# Bans.
st, b = api("POST", "/server/firewall/bans", {"ip": "203.0.113.88", "minutes": 5, "reason": "e2e"})
check(st == 201 and b["active"], "a ban can be made", f"{st} {b}")
if st == 201:
    until(lambda: "203.0.113.88" in (nft() or ""), "the ban reaches the kernel")
    st, o = api("GET", "/server/firewall")
    check(any(x["ip"] == "203.0.113.88" and x["active"] for x in o["bans"]), "the ban is listed")
    st, r = api("POST", "/server/firewall/bans", {"ip": "203.0.113.89", "minutes": 0})
    check(st == 201 and b["expires_at"] is not None and r["expires_at"] is None, "a ban for good has no end", f"{r}")
    st, r = api("POST", "/server/firewall/bans", {"ip": "not-an-ip"})
    check(st == 400, "a ban of garbage is refused", f"{st}")
    st, r = api("POST", "/server/firewall/bans", {"ip": "198.51.100.5"})
    check(st in (400, 409), "an allowed address cannot be banned", f"{st}")
    st, _ = api("DELETE", f"/server/firewall/bans/{b['id']}")
    check(st == 204, "a ban can be lifted", f"{st}")
    until(lambda: "203.0.113.88" not in (nft() or ""), "the lifted ban leaves the kernel")
    st, _ = api("DELETE", f"/server/firewall/bans/{b['id']}")
    check(st == 404 or st == 409, "lifting twice is refused", f"{st}")

# Closed policy must keep the panel and SSH open.
st, o = api("GET", "/server/firewall")
cfg = o["config"]
st, r = api("PUT", "/server/firewall", {**cfg, "policy": "closed", "ports": [{"port": "80", "proto": "tcp", "comment": ""}]})
check(st == 400, "a closed firewall without the panel's port is refused", f"{st}")
r = save({**cfg, "policy": "closed"})
rules = nft() or ""
check("drop" in rules, "the closed policy drops the rest")
st, o = api("GET", "/server/firewall")
check(st == 200, "the panel answers under the closed policy", f"{st}")

# Audit trail.
st, lg = api("GET", "/server/logins")
check(st == 200, "the sign-in history still reads", f"{st}")

# Off again: the table goes.
save({**cfg, "enabled": False, "policy": "open"})
check(nft() is None, "turning it off removes the table")

st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] == "fw1":
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "fw1"})
        wait_job(t["job_id"])
finish()
