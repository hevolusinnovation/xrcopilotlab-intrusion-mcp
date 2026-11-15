# The attacker of the lab, and the console that drives it (http://localhost:8090). Fixed scenarios against lab-01
# only: there is no field for an address or a command. Its networks are internal: nothing leaves the lab.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Rome
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip nmap openssh-client sshpass iproute2 tzdata wireguard-tools iputils-ping \
 && rm -rf /var/lib/apt/lists/*

# The client for the optional Metasploit container (msfrpcd): the console drives Metasploit over RPC, it is not
# installed here. Small pure-Python package; Metasploit itself (~2 GB) lives in its own container, started on demand
# with  make lab-up-msf.  See lab/README.md.
RUN pip3 install --no-cache-dir --break-system-packages pymetasploit3==1.0.6

WORKDIR /lab
COPY entrypoint.sh console.py scenarios.py ./
COPY static/ static/
RUN chmod +x entrypoint.sh
EXPOSE 8090
ENTRYPOINT ["/lab/entrypoint.sh"]
