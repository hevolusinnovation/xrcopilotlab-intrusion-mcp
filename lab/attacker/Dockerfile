# The attacker of the lab, and the console that drives it (http://localhost:8090). Fixed scenarios against lab-01
# only: there is no field for an address or a command. Its networks are internal: nothing leaves the lab.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Rome
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 nmap openssh-client sshpass iproute2 tzdata \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY entrypoint.sh console.py scenarios.py ./
COPY static/ static/
RUN chmod +x entrypoint.sh
EXPOSE 8090
ENTRYPOINT ["/lab/entrypoint.sh"]
