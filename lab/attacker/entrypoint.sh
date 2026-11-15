#!/usr/bin/env bash
# Gives the attacker the addresses of its personas (scenarios.py), each on the network of its range: lab-01 sees every
# one of them as a different machine, and the intrusion package places each in its invented city.
set -euo pipefail
iface_for() { ip -o -4 addr show | awk -v p="$1" 'index($4, p) == 1 { print $2; exit }'; }
python3 /lab/scenarios.py --addresses | while read -r ip; do
  case "$ip" in
    198.51.100.*) dev="$(iface_for 198.51.100.)" ;;
    203.0.113.*)  dev="$(iface_for 203.0.113.)" ;;
    192.0.2.*)    dev="$(iface_for 192.0.2.)" ;;
    *) continue ;;
  esac
  ip addr add "$ip/24" dev "$dev" 2>/dev/null || true
done
exec python3 -u /lab/console.py
