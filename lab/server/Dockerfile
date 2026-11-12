# syntax=docker/dockerfile:1.7
# lab-01: an Ubuntu 24.04 server as a customer would have it — sshd, nginx, fail2ban, a firewall that logs what it
# drops — with the intrusion package installed by its own install.sh, from the same tarball `make package` builds.
# Build context: the repository root (see lab/docker-compose.yml).

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS package
ARG TARGETARCH
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props nuget.config ./
COPY src/ src/
COPY deploy/ deploy/
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
 && deploy/package.sh 0.0.0-lab "$RID" /out \
 && mv /out/xrcopilotlab-intrusion-mcp-0.0.0-lab-*.tar.gz /out/package.tar.gz

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Rome container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus openssh-server nginx fail2ban rsyslog \
      ulogd2 iptables iproute2 tzdata curl ca-certificates openssl sudo \
 && rm -rf /var/lib/apt/lists/* \
 && ln -fs /usr/share/zoneinfo/Europe/Rome /etc/localtime

# A container runs only the services the lab needs: no getty, no udev, no timers.
RUN find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \
      -not -name '*journald*' -not -name '*systemd-tmpfiles*' -not -name '*systemd-user-sessions*' -delete \
 && systemctl mask systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
      systemd-modules-load.service sys-kernel-config.mount sys-kernel-debug.mount getty.target \
 && systemctl set-default multi-user.target

# The lab's configuration: who can log in, what the firewall drops, what fail2ban watches, how nginx answers.
COPY lab/server/files/ /
RUN useradd -m -s /bin/bash -G sudo operatore && echo 'operatore:Alveo2026!' | chpasswd \
 && printf 'admin:%s\n' "$(openssl passwd -apr1 'Ferri#2026')" > /etc/nginx/lab.htpasswd \
 && rm -f /etc/nginx/sites-enabled/default /etc/fail2ban/jail.d/defaults-debian.conf \
 && sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf \
 && sed -i "s#@MULTIARCH@#$(uname -m)-linux-gnu#" /etc/ulogd.conf \
 && chmod +x /usr/local/sbin/lab-firewall /usr/local/sbin/lab-entrypoint \
 && install -m 0640 -o syslog -g adm /dev/null /var/log/auth.log \
 && systemctl disable ssh.socket \
 && systemctl enable ssh.service nginx.service fail2ban.service rsyslog.service ulogd2.service lab-firewall.service

# The package, installed as the customer installs it, with Suricata and Falco from its --with option (here, at build,
# the only time lab-01 reaches the internet: the ET Open rules are fetched now). The key arrives at start (lab-entrypoint).
COPY --from=package /out/package.tar.gz /tmp/package.tar.gz
RUN mkdir /tmp/package && tar -xzf /tmp/package.tar.gz -C /tmp/package --strip-components=1 \
 && DASHBOARD_PASSWORD=AlveoLab2026! /tmp/package/install.sh --no-start --with suricata,falco,modsecurity \
 && suricata-update -q --no-test --local /etc/suricata/rules/lab.rules \
 && systemctl enable suricata.service falco-modern-bpf.service nginx.service \
 && rm -rf /tmp/package /tmp/package.tar.gz /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/lab-entrypoint"]
