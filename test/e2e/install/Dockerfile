# Ubuntu 24.04 with systemd as PID 1, to test xcp-install end to end.
# Used by test/e2e/install/run.sh; needs --privileged (systemd in a container).
FROM ubuntu:24.04
ENV container=docker
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates curl procps python3 \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \( -name '*udev*' -o -name '*getty*' -o -name 'systemd-logind*' \) -delete
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
