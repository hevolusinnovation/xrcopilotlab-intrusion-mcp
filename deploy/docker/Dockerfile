# syntax=docker/dockerfile:1.7
# The toolkit's server in a container: Ubuntu 24.04 with systemd, the guardians and the package, installed by the same
# install.sh a customer runs on a server. Build context: the repository root.
#
#   target server  the image for a real host (a VPS, a mini PC): no user, no password, no key in it. Every secret is made
#                  by the container at its first start (the VPN's key, the page's password and certificate, CrowdSec's
#                  credentials) and kept in its volumes. See deploy/docker/compose.yml.
#   target lab     lab-01 of the Docker lab: the server image, plus what the attack console needs to find (an account with
#                  a known password, a sample site, a VPN user whose key the attacker has). Never for a real network.
#
#   docker build -f deploy/docker/Dockerfile --target server -t xrcopilotlab-intrusion-server .
#   GUARDIANS: the guardians install.sh --with sets up at build (fail2ban and nginx are always there).

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS package
ARG TARGETARCH
ARG VERSION=0.0.0-docker
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props nuget.config ./
COPY src/ src/
COPY deploy/ deploy/
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
 && deploy/package.sh "$VERSION" "$RID" /out \
 && mv /out/xrcopilotlab-intrusion-mcp-*.tar.gz /out/package.tar.gz

FROM ubuntu:24.04 AS server
ARG GUARDIANS=crowdsec,suricata,falco,modsecurity,wireguard
ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Rome container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus nginx fail2ban rsyslog iptables iproute2 tzdata curl \
      ca-certificates openssl sudo \
 && rm -rf /var/lib/apt/lists/* \
 && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime

# A container runs only the services it needs: no getty, no udev, no timers. D-Bus stays: without it the toolkit
# (not root) cannot ask systemd which guardians run, and the page would show them all stopped.
RUN find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \
      -not -name '*journald*' -not -name '*systemd-tmpfiles*' -not -name '*systemd-user-sessions*' -not -name 'dbus.socket' -delete \
 && systemctl mask systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
      systemd-modules-load.service sys-kernel-config.mount sys-kernel-debug.mount getty.target \
 && systemctl set-default multi-user.target

# nginx's default site would take port 80 of the host: the customer's own sites go in /etc/nginx/sites-enabled.
# fail2ban: the package's sshd jail instead of Debian's (systemd backend, which sees nothing of the host's sshd).
# rsyslog: the kernel log is the host's, not the container's.
COPY deploy/docker/files/ /
RUN rm -f /etc/nginx/sites-enabled/default /etc/fail2ban/jail.d/defaults-debian.conf \
 && sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf \
 && install -m 0640 -o syslog -g adm /dev/null /var/log/auth.log \
 && chmod +x /usr/local/sbin/xrc-docker-start \
 && systemctl enable nginx.service fail2ban.service rsyslog.service

# The package, as a customer installs it. It stays in the image (/opt/xrcopilotlab-intrusion-mcp/package): the container
# runs install.sh again at every start, which makes what an image must not carry and keeps what is already there.
# Made here and removed at once: the page's password, certificate and key, CrowdSec's credentials. The VPN's key is
# never made in an image (xrc-vpn init, at the first start).
COPY --from=package /out/package.tar.gz /tmp/package.tar.gz
RUN install -d /opt/xrcopilotlab-intrusion-mcp/package \
 && tar -xzf /tmp/package.tar.gz -C /opt/xrcopilotlab-intrusion-mcp/package --strip-components=1 \
 && /opt/xrcopilotlab-intrusion-mcp/package/install.sh --no-start --with "$GUARDIANS" \
 && if [ -f /var/lib/suricata/rules/suricata.rules ]; then systemctl enable suricata.service; fi \
 && if [ -d /etc/crowdsec ]; then systemctl enable crowdsec.service; fi \
 && for u in falco-modern-bpf.service; do systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl enable "$u" || true; done \
 && rm -f /etc/nginx/xrcopilotlab-dashboard/tls.key /etc/nginx/xrcopilotlab-dashboard/tls.crt \
      /etc/nginx/xrcopilotlab-dashboard/htpasswd /etc/nginx/xrcopilotlab-dashboard/key.conf \
      /etc/xrcopilotlab-intrusion-mcp/dashboard.env /etc/xrcopilotlab-intrusion-mcp/env \
      /etc/crowdsec/local_api_credentials.yaml /etc/crowdsec/online_api_credentials.yaml \
 && rm -rf /tmp/package.tar.gz /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/xrc-docker-start"]

# ---- lab-01: the server image, plus what the attacks need to find. Only this stage writes the lab's marker. ----
FROM server AS lab
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server ulogd2 \
 && rm -rf /var/lib/apt/lists/*
# The lab's configuration: who can log in, what the firewall drops, what fail2ban watches, the sample site, the marker.
COPY lab/server/files/ /
RUN useradd -m -s /bin/bash -G sudo operatore && echo 'operatore:Alveo2026!' | chpasswd \
 && printf 'admin:%s\n' "$(openssl passwd -apr1 'Ferri#2026')" > /etc/nginx/lab.htpasswd \
 && sed -i "s#@MULTIARCH@#$(uname -m)-linux-gnu#" /etc/ulogd.conf \
 && chmod +x /usr/local/sbin/lab-firewall /usr/local/sbin/lab-entrypoint /usr/local/sbin/lab-vpn-user \
 && chmod 0644 /etc/xrcopilotlab-intrusion-mcp/lab.json \
 && systemctl disable ssh.socket \
 && systemctl enable ssh.service ulogd2.service lab-firewall.service \
 # lab-01 is isolated at runtime: CrowdSec runs with its local API only, or it stops on start reaching api.crowdsec.net.
 && if [ -f /etc/crowdsec/config.yaml ]; then sed -i '/^    online_client:/,+1d' /etc/crowdsec/config.yaml; fi \
 && suricata-update -q --no-test --local /etc/suricata/rules/lab.rules
# The lab's sites, after the package: they turn ModSecurity off for the API ("modsecurity off;"), a directive nginx only
# knows once --with modsecurity has loaded the module.
COPY lab/server/nginx-sites/ /etc/nginx/sites-enabled/
RUN nginx -t
ENTRYPOINT ["/usr/local/sbin/lab-entrypoint"]
