#!/bin/sh
# End-to-end installer test in an Ubuntu 24.04 container with systemd.
# Usage (from the repo root, Docker running):  sh test/e2e/install/run.sh
set -eu
NAME=xcp-install-e2e
OUT=.dev/linux
mkdir -p "$OUT"
for b in xcp-agent xcp-api xcpctl xcp-install xcp-userd xcp-ftpauth xcp-cronrun xcp-logd; do
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$OUT/$b" "./cmd/$b"
done
# Pebble, Let's Encrypt's test CA, for acme.py: a pinned version, built from source.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
gobin=$(go env GOBIN); [ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
cp "$gobin/linux_amd64/pebble" "$OUT/pebble" 2>/dev/null || cp "$gobin/pebble" "$OUT/pebble"
docker build -q -t xcp-systemd test/e2e/install >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock -h panel.test.example xcp-systemd >/dev/null
LOG=$(mktemp)
trap 'docker rm -f "$NAME" >/dev/null; rm -f "$LOG" "$LOG.rc"' EXIT

# step TITLE CMD...: runs CMD, showing its output. When it fails, its
# failure lines become GitHub annotations, which can be read without the
# job's log; outside GitHub they are just more lines.
step() {
  title=$1
  shift
  echo "== $title"
  { rc=0; "$@" 2>&1 || rc=$?; echo "$rc" >"$LOG.rc"; } | tee "$LOG"
  rc=$(cat "$LOG.rc")
  [ "$rc" = 0 ] && return 0
  title=$(echo "$title" | sed 's/,/%2C/g; s/:/%3A/g') # property syntax of workflow commands
  { grep -E '^(FAIL|Traceback)|Error|error' "$LOG" || true; tail -n 3 "$LOG"; } | tail -n 8 | while IFS= read -r line; do
    echo "::error title=e2e $title::$line"
  done
  docker exec "$NAME" journalctl -p warning -n 5 --no-pager -o cat 2>/dev/null | while IFS= read -r line; do
    echo "::error title=e2e $title (journal)::$line"
  done
  exit "$rc"
}

docker cp "$OUT/." "$NAME:/opt/xcp/"
docker exec "$NAME" sh -c 'chmod +x /opt/xcp/* && until systemctl is-system-running --wait >/dev/null 2>&1 || [ "$(systemctl is-system-running)" = degraded ]; do sleep 1; done'
step "install" docker exec "$NAME" /opt/xcp/xcp-install --hostname panel.test.example
step "doctor" docker exec "$NAME" xcpctl doctor
for f in xcpe2e.py websites.py dns.py certificates.py databases.py mail.py files.py ftp.py cron.py stats.py backups.py serverinfo.py firewall.py websettings.py mailqueue.py acme.py acceptance.py; do docker cp "test/e2e/install/$f" "$NAME:/opt/xcp/$f"; done
echo "e2e test password 42" | docker exec -i "$NAME" xcpctl admin create --username e2etest
step "websites (accounts, domains, Apache, PHP-FPM, isolation)" docker exec "$NAME" python3 /opt/xcp/websites.py
step "DNS (PowerDNS zones, records)" docker exec "$NAME" python3 /opt/xcp/dns.py
step "SSL (uploaded certificate, HTTPS, force HTTPS, AutoSSL reasons)" docker exec "$NAME" python3 /opt/xcp/certificates.py
step "databases (MariaDB, privileges, phpMyAdmin sign-on)" docker exec "$NAME" python3 /opt/xcp/databases.py
step "mail (Postfix, Dovecot, Rspamd: delivery, forwarders, submission, DKIM)" docker exec "$NAME" python3 /opt/xcp/mail.py
step "files (file manager as the account user)" docker exec "$NAME" python3 /opt/xcp/files.py
step "FTP (Pure-FTPd, xcp-ftpauth: chroot, quota, FTPS, suspension)" docker exec "$NAME" python3 /opt/xcp/ftp.py
step "cron (jobs as the account user in its slice: last run, mail, no overlap, suspension)" docker exec "$NAME" python3 /opt/xcp/cron.py
step "usage and logs (xcp-logd: web, FTP and mail bytes once per domain; log viewers)" docker exec "$NAME" python3 /opt/xcp/stats.py
step "backups (full account archive: files, database, settings; download; root-only)" docker exec "$NAME" python3 /opt/xcp/backups.py
step "admin server pages (dashboard, services, job monitor, sessions, sign-in history)" docker exec "$NAME" python3 /opt/xcp/serverinfo.py
step "mail queue (list, try again, delete; admins only)" docker exec "$NAME" python3 /opt/xcp/mailqueue.py
step "web settings (error pages, hotlink protection, IP blocker, compression, caching)" docker exec "$NAME" python3 /opt/xcp/websettings.py
step "firewall (nftables rules in the kernel, bans, restrictions, closed policy that keeps the panel open, off again)" docker exec "$NAME" python3 /opt/xcp/firewall.py
step "ACME (AutoSSL issuing through Pebble, HTTP-01 via PowerDNS and Apache)" docker exec "$NAME" python3 /opt/xcp/acme.py
step "P1 acceptance (account, domain, DNS, AutoSSL, FTP site, database, HTTPS, mail with DKIM, backup, terminate, restore)" docker exec "$NAME" python3 /opt/xcp/acceptance.py
echo "== re-run";  docker exec "$NAME" /opt/xcp/xcp-install --hostname panel.test.example | grep -E "changed|no admin|installed"
