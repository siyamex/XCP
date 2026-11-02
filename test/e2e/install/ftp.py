#!/usr/bin/env python3
"""End-to-end test of FTP (P1 #11, ADR-0010), run as root on a server where
XCP is installed: logins made in the panel, checked by xcp-ftpauth, locked
into their folder by Pure-FTPd, files owned by the account's user."""
import ftplib, io, os, pwd, re, ssl, subprocess, time

from xcpe2e import Session, admin, check, finish

admin_session = admin()
api, wait_job = admin_session.call, admin_session.wait_job
PW = "ftp test password 1234"
FPW = "ftp login password 5678"
HOME = "/home/ftp1"


def ftp(login, password, tls=False):
    """A logged-in FTP connection, or the error text."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # the panel's self-signed pair here
            f = ftplib.FTP_TLS(context=ctx, timeout=10)
        else:
            f = ftplib.FTP(timeout=10)
        f.connect("127.0.0.1", 21)
        f.login(login, password)
        if tls:
            f.prot_p()
        return f
    except ftplib.all_errors as e:
        return str(e)


def store(f, name, data):
    try:
        f.storbinary("STOR " + name, io.BytesIO(data))
        return "ok"
    except ftplib.all_errors as e:
        return str(e)


st, existing = api("GET", "/accounts")
for a in existing["items"]:
    if a["username"] in ("ftp1", "ftp2"):  # left by an earlier run that stopped
        st, t = api("POST", f"/accounts/{a['id']}/terminate", {"confirm": a["username"]})
        wait_job(t["job_id"])
st, pk = api("GET", "/packages")
pkg = next(p for p in pk["items"] if p["name"] == "Default")["id"]
ids = {}
for name in ("ftp1", "ftp2"):
    st, a = api("POST", "/accounts", {"username": name, "domain": name + ".xcp.test", "package_id": pkg, "password": PW})
    wait_job(a["job_id"])
    ids[name] = a["id"]
acct = ids["ftp1"]
user = Session()
user.login("ftp1", PW)
st, o = user.call("GET", f"/accounts/{acct}/ftp")
check(st == 200 and len(o["domains"]) == 1 and o["logins"] == [] and o["port"] == 21, "the user sees the FTP page", f"{st} {o}")
dom = o["domains"][0]["id"]


def create(name, folder="", quota=0, session=user, account=acct, domain=dom):
    st, l = session.call("POST", f"/accounts/{account}/ftp", {"domain_id": domain, "name": name, "password": FPW, "folder": folder, "quota_mb": quota})
    if st == 202:
        j = wait_job(l["job_id"])
        check(j["status"] == "succeeded", f"the job for {name} succeeds", str(j)[:300])
    return st, l


st, web = create("web", "public_html/shop", 1)
check(st == 202 and web["login"] == "web@ftp1.xcp.test", "create a login for a new folder", f"{st} {web}")
check(os.path.isdir(f"{HOME}/public_html/shop") and pwd.getpwuid(os.stat(f"{HOME}/public_html/shop").st_uid).pw_name == "ftp1",
      "its folder is made, owned by the account's user")

f = ftp("web@ftp1.xcp.test", FPW)
check(not isinstance(f, str), "log in over FTP", str(f))
if not isinstance(f, str):
    check(f.pwd() == "/" and store(f, "hello.txt", b"hello over FTP\n") == "ok", "upload a file (passive mode)")
    owner = pwd.getpwuid(os.stat(f"{HOME}/public_html/shop/hello.txt").st_uid).pw_name
    check(owner == "ftp1", "the file belongs to the account's user", owner)
    f.cwd("..")
    names = [n for n in f.nlst() if not n.startswith(".")]
    check(f.pwd() == "/" and names == ["hello.txt"], "the login cannot leave its folder", str(names))
    try:
        listing = f.nlst("/etc")
    except ftplib.all_errors as e:
        listing = str(e)
    check("passwd" not in str(listing), "the system's files are out of reach", str(listing)[:200])
    r = store(f, "big.bin", os.urandom(2 << 20))
    check(r != "ok" and not os.path.exists(f"{HOME}/public_html/shop/big.bin"), "the 1 MB quota stops a 2 MB upload", r)
    f.close()  # Pure-FTPd may still owe a second 552 reply; QUIT would read it as an error

f = ftp("web@ftp1.xcp.test", FPW, tls=True)
check(not isinstance(f, str) and store(f, "secure.txt", b"over TLS\n") == "ok" and "secure.txt" in f.nlst(), "FTPS (explicit TLS) works", str(f))
for login, pw_, what in [("web@ftp1.xcp.test", "wrong password", "a wrong password"), ("nobody@ftp1.xcp.test", FPW, "an unknown login"),
                         ("ftp1", PW, "the account's system user"), ("root", "x", "root"), ("anonymous", "a@b.c", "anonymous")]:
    r = ftp(login, pw_)
    check(isinstance(r, str) and r.startswith("530"), f"{what} is refused", str(r))

st, all_ = create("all")
f = ftp("all@ftp1.xcp.test", FPW)
check(not isinstance(f, str) and "public_html" in f.nlst(), "a login for the whole home sees the home", str(f))
if not isinstance(f, str):
    f.quit()

# A folder the user replaced with a symlink is refused at login.
st, swap = create("swap", "swap")
subprocess.run(["runuser", "-u", "ftp1", "--", "sh", "-c", f"rmdir {HOME}/swap && ln -s /etc {HOME}/swap"], check=True)
r = ftp("swap@ftp1.xcp.test", FPW)
check(isinstance(r, str) and r.startswith("530"), "a login whose folder became a symlink is refused", str(r))
st, r = user.call("PUT", f"/ftp/{swap['id']}", {"folder": "swap/inside", "quota_mb": 0})
j = wait_job(r["job_id"])
check(j["status"] == "succeeded" and "swap/inside" in str(j.get("result")) and not os.path.exists("/etc/inside"),
      "a folder through that symlink is not made, and the account's changes still apply", str(j)[:400])

# Changes reach xcp-ftpauth at once.
st, r = user.call("PUT", f"/ftp/{web['id']}/password", {"password": "a brand new ftp password"})
wait_job(r["job_id"])
check(isinstance(ftp("web@ftp1.xcp.test", FPW), str) and not isinstance(ftp("web@ftp1.xcp.test", "a brand new ftp password"), str),
      "after a password change only the new password works")
st, r = user.call("DELETE", f"/ftp/{all_['id']}")
wait_job(r["job_id"])
check(isinstance(ftp("all@ftp1.xcp.test", FPW), str), "a deleted login is refused")

# Other accounts.
other = Session()
other.login("ftp2", PW)
st, r = create("steal", session=other, account=ids["ftp2"])
check(st == 400, "another account cannot name a login after this account's domain", f"{st} {r}")
st, r = other.call("GET", f"/accounts/{acct}/ftp")
check(st == 404, "another account cannot see the logins", f"{st} {r}")

# Who does the work.
pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "xcp-ftpauth.service"], capture_output=True, text=True).stdout.strip()
status = open(f"/proc/{pid}/status").read()
caps = re.search(r"CapEff:\s*(\w+)", status).group(1)
check(re.search(r"Uid:\s*0\s", status) and int(caps, 16) == 1 << 2, "xcp-ftpauth runs as root with only CAP_DAC_READ_SEARCH", caps)
check(oct(os.stat("/run/xcp-ftpauth").st_mode & 0o777) == "0o700", "only root can reach the login socket")

# Suspension ends the sessions and refuses logins; unsuspending lets them in again.
f = ftp("web@ftp1.xcp.test", "a brand new ftp password")
check(not isinstance(f, str), "a session is open before suspending", str(f))
st, a = api("POST", f"/accounts/{acct}/suspend", {"reason": "e2e"})
wait_job(a["job_id"])
try:
    f.nlst()
    alive = True
except ftplib.all_errors:
    alive = False
check(not alive, "suspension ends the open FTP session")
r = ftp("web@ftp1.xcp.test", "a brand new ftp password")
check(isinstance(r, str) and r.startswith("530"), "a suspended account cannot log in", str(r))
st, a = api("POST", f"/accounts/{acct}/unsuspend")
wait_job(a["job_id"])
f = ftp("web@ftp1.xcp.test", "a brand new ftp password")
check(not isinstance(f, str) and "hello.txt" in f.nlst(), "after unsuspending the login works again", str(f))

subprocess.run(["systemctl", "restart", "xcp-ftpauth"], check=True)
for _ in range(20):  # the socket is there a moment after systemd starts it
    f = ftp("web@ftp1.xcp.test", "a brand new ftp password")
    if not isinstance(f, str):
        break
    time.sleep(0.5)
check(not isinstance(f, str), "logins work after xcp-ftpauth restarts", str(f))

for name, id_ in ids.items():
    st, t = api("POST", f"/accounts/{id_}/terminate", {"confirm": name})
    wait_job(t["job_id"])
check(not os.path.exists("/etc/xcp/ftp/accounts/ftp1.json"), "terminating the account removes its logins")
finish()
