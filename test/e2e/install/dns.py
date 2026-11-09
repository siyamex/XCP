#!/usr/bin/env python3
"""End-to-end DNS test, run as root on a server where XCP is installed.

It sets the DNS settings, creates an account, records and domains through
the API and asks PowerDNS (dig @127.0.0.1) what it serves. Used by run.sh.
The settings found at the start are restored at the end.
"""
import subprocess, time

from xcpe2e import admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job


def dig(name, typ="A"):
    """PowerDNS's answer: the status and the sorted record data."""
    out = subprocess.run(["dig", "@127.0.0.1", "+norecurse", "+noall", "+comments", "+answer", name, typ],
                         capture_output=True, text=True, timeout=10).stdout
    status = next((l.split("status: ")[1].split(",")[0] for l in out.splitlines() if "status: " in l), "NO ANSWER")
    answers = [f[4] for f in (l.split(None, 4) for l in out.splitlines() if l and not l.startswith(";")) if len(f) == 5 and f[3] == typ]
    return status, sorted(answers)


def until(name, typ, cond, what, timeout=30):
    """Waits until PowerDNS's answer satisfies cond (jobs run in the background), then checks it."""
    deadline = time.time() + timeout
    while True:
        status, answers = dig(name, typ)
        if cond(status, answers) or time.time() > deadline:
            check(cond(status, answers), what, f"{status} {answers}")
            return answers
        time.sleep(0.5)


st, before = api("GET", "/server/dns")
settings = {"nameservers": ["ns1.xcp.test", "ns2.xcp.test"], "ipv4": "192.0.2.10", "ipv6": "", "ttl": 300, "template": before["template"]}
st, res = api("PUT", "/server/dns", settings)
check(st == 200, "DNS settings saved", str(res))

st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
st, a = api("POST", "/accounts", {"username": "dns1", "domain": "dns1.xcp.test", "package_id": pkg, "password": "dns password 1234"})
wait_job(a["job_id"])

until("dns1.xcp.test", "A", lambda s, ans: ans == ["192.0.2.10"], "the new account's zone is served (A from the template)")
soa = until("dns1.xcp.test", "SOA", lambda s, ans: len(ans) == 1 and ans[0].startswith("ns1.xcp.test. hostmaster.dns1.xcp.test. "),
            "SOA names the first name server and hostmaster")
serial = int(soa[0].split()[2]) if soa else 0
until("dns1.xcp.test", "NS", lambda s, ans: ans == ["ns1.xcp.test.", "ns2.xcp.test."], "NS records come from the settings")
until("dns1.xcp.test", "MX", lambda s, ans: ans == ["10 mail.dns1.xcp.test."], "MX from the template")
until("www.dns1.xcp.test", "CNAME", lambda s, ans: ans == ["dns1.xcp.test."], "www CNAME from the template")
until("dns1.xcp.test", "TXT", lambda s, ans: ans == ['"v=spf1 a mx ~all"'], "SPF TXT from the template")
until("dns1.xcp.test", "AAAA", lambda s, ans: s == "NOERROR" and ans == [], "no AAAA without an IPv6 address in the settings")

st, zones = api("GET", f"/dns/zones?account_id={a['id']}")
zid = zones["items"][0]["id"]
st, r = api("POST", f"/dns/zones/{zid}/records", {"name": "api", "type": "A", "content": "192.0.2.50"})
api_rec = r["id"]
wait_job(r["job_id"])
until("api.dns1.xcp.test", "A", lambda s, ans: ans == ["192.0.2.50"], "an added A record is served")
until("dns1.xcp.test", "SOA", lambda s, ans: len(ans) == 1 and int(ans[0].split()[2]) > serial, "the SOA serial went up with the change")
text = 'say "hi"; ' + "x" * 300
st, r = api("POST", f"/dns/zones/{zid}/records", {"name": "_note", "type": "TXT", "content": text})
wait_job(r["job_id"])
until("_note.dns1.xcp.test", "TXT", lambda s, ans: len(ans) == 1 and ans[0].startswith('"say \\"hi\\"; xxx') and ans[0].count('" "') == 1,
      "a long TXT is split into strings, quotes kept")
st, res = api("POST", f"/dns/zones/{zid}/records", {"name": "api", "type": "CNAME", "content": "other.example"})
check(st == 409 and res.get("code") == "record_conflict", "a CNAME next to an A record is refused", f"{st} {res}")

st, doms = api("GET", f"/accounts/{a['id']}/domains")
primary = doms["items"][0]["id"]
st, d = api("POST", f"/accounts/{a['id']}/domains", {"kind": "sub", "name": "blog", "parent_id": primary})
wait_job(d["job_id"])
until("blog.dns1.xcp.test", "A", lambda s, ans: ans == ["192.0.2.10"], "a subdomain gets an A record in its domain's zone")
st, d = api("POST", f"/accounts/{a['id']}/domains", {"kind": "addon", "name": "dnsother.test"})
wait_job(d["job_id"])
until("dnsother.test", "SOA", lambda s, ans: len(ans) == 1, "an addon domain gets its own zone")
st, ref = api("DELETE", f"/domains/{d['id']}")
wait_job(ref["job_id"])
until("dnsother.test", "SOA", lambda s, ans: s == "REFUSED", "a removed addon domain's zone is gone")
st, ref = api("DELETE", f"/dns/records/{api_rec}")
wait_job(ref["job_id"])
until("api.dns1.xcp.test", "A", lambda s, ans: s == "NXDOMAIN", "a removed record is gone")

# Zone file: export, then import into the same zone.
import urllib.request
from xcpe2e import API
with admin_session.opener.open(urllib.request.Request(API + f"/dns/zones/{zid}/export")) as r:
    exported = r.read().decode()
    check(r.status == 200 and "$ORIGIN dns1.xcp.test." in exported and "	SOA	" not in exported and "192.0.2.10" in exported, "the zone is exported as a zone file", exported[:200])
st, res = api("POST", f"/dns/zones/{zid}/import", {"text": exported})
check(st == 200 and res["added"] == 0 and res["existing"] > 0, "importing the export adds nothing", f"{st} {res}")
st, res = api("POST", f"/dns/zones/{zid}/import", {"text": "$TTL 600\nimp IN A 192.0.2.88\nimptxt IN TXT \"v=spf1 -all\"\n@ IN SOA a.b. c.d. 1 2 3 4 5\n"})
check(st == 200 and res["added"] == 2 and res["job_id"], "a zone file adds its records", f"{st} {res}")
wait_job(res["job_id"])
until("imp.dns1.xcp.test", "A", lambda s, ans: ans == ["192.0.2.88"], "an imported record is served")
st, res = api("POST", f"/dns/zones/{zid}/import", {"text": "good IN A 192.0.2.99\nbad IN A 999.0.0.1\n"})
check(st == 409 and res.get("code") == "bad_zone_file", "a file with an invalid record is refused whole", f"{st} {res}")
until("good.dns1.xcp.test", "A", lambda s, ans: s == "NXDOMAIN", "nothing of a refused file is served")

# Bulk: one TTL for every record.
st, res = api("POST", "/server/dns/bulk-ttl", {"ttl": 10})
check(st == 400, "a TTL below 60 is refused", f"{st} {res}")
st, res = api("POST", "/server/dns/bulk-ttl", {"ttl": 777})
check(st == 200 and res["records"] > 0 and res["zones"] >= 1, "every record gets the TTL", f"{st} {res}")
st, z = api("GET", f"/dns/zones/{zid}")
check(all(r["ttl"] == 777 for r in z["records"]), "the zone's records have it", str([r["ttl"] for r in z["records"]]))
st, res = api("POST", "/server/dns/bulk-ttl", {"ttl": 3600})

# Orphan zones: made in the DNS server by hand, not owned by an account.
import subprocess
subprocess.run(["pdnsutil", "create-zone", "stray.dns1.test"], capture_output=True)
st, res = api("GET", "/server/dns/orphans")
check(st == 200 and "stray.dns1.test" in res["items"] and "dns1.xcp.test" not in res["items"], "a zone no account owns is listed, an account's is not", f"{st} {res}")
st, res = api("DELETE", "/server/dns/orphans/dns1.xcp.test")
check(st == 409 and res.get("code") == "zone_in_use", "an account's zone cannot be removed this way", f"{st} {res}")
st, res = api("DELETE", "/server/dns/orphans/stray.dns1.test")
check(st == 204, "an orphan zone is removed", f"{st} {res}")
until("stray.dns1.test", "SOA", lambda s, ans: s == "REFUSED", "it is no longer served")

st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": "dns1"})
wait_job(t["job_id"])
until("dns1.xcp.test", "SOA", lambda s, ans: s == "REFUSED", "a terminated account's zone is gone")

st, res = api("PUT", "/server/dns", {k: before[k] for k in ("nameservers", "ipv4", "ipv6", "ttl", "template")})
check(st == 200, "DNS settings restored", str(res))
finish()
