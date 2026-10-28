#!/bin/sh
# End-to-end installer test in an Ubuntu 24.04 container with systemd.
# Usage (from the repo root, Docker running):  sh test/e2e/install/run.sh
set -eu
NAME=xcp-install-e2e
OUT=.dev/linux
mkdir -p "$OUT"
for b in xcp-agent xcp-api xcpctl xcp-install; do
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$OUT/$b" "./cmd/$b"
done
docker build -q -t xcp-systemd test/e2e/install >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock -h panel.test.example xcp-systemd >/dev/null
trap 'docker rm -f "$NAME" >/dev/null' EXIT
docker cp "$OUT/." "$NAME:/opt/xcp/"
docker exec "$NAME" sh -c 'chmod +x /opt/xcp/* && until systemctl is-system-running --wait >/dev/null 2>&1 || [ "$(systemctl is-system-running)" = degraded ]; do sleep 1; done'
echo "== install"; docker exec "$NAME" /opt/xcp/xcp-install --hostname panel.test.example
echo "== doctor";  docker exec "$NAME" xcpctl doctor
echo "== websites (accounts, Apache, PHP-FPM, isolation)"
docker cp test/e2e/install/websites.py "$NAME:/opt/xcp/websites.py"
echo "e2e test password 42" | docker exec -i "$NAME" xcpctl admin create --username e2etest
docker exec "$NAME" python3 /opt/xcp/websites.py
echo "== re-run";  docker exec "$NAME" /opt/xcp/xcp-install --hostname panel.test.example | grep -E "changed|no admin|installed"
