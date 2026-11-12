#!/usr/bin/env bash
# Turn a fresh Ubuntu 24.04 VM (Azure or Oracle Cloud) into a Cowrie honeypot sensor.
#
# Run ON THE VM, as your admin user, from the folder you copied the deploy kit into:
#     sudo bash setup_honeypot.sh uk-london                    # Oracle Cloud, London
#     sudo bash setup_honeypot.sh sweden-central --blocklists  # Azure Sweden Central: also takes the daily blocklist snapshots
#     sudo bash setup_honeypot.sh austria-east                 # Azure Austria East
#
# Works on Azure and on Oracle Cloud (Oracle's Ubuntu images ship with a host firewall that
# rejects everything except port 22; the script opens 50022, 2222 and 2223 BEFORE moving SSH).
#
# What it does (each step matches the ethics application):
#   1. Moves the REAL admin SSH to port 50022 with key-only login (cloud firewall: your IP only).
#   2. Runs Cowrie in Docker with host networking, so logs record attackers' real IP addresses.
#   3. Redirects ports 22 -> 2222 and 23 -> 2223 so attackers reach Cowrie, not the real SSH.
#   4. Blocks every NEW outbound connection made by Cowrie (it cannot be used to attack anyone,
#      and it cannot fetch the files attackers ask for: only the URL is logged).
#   5. Daily cron: hash and delete any file Cowrie saved; optionally snapshot the blocklists.
#
# Safe to run more than once.
set -euo pipefail

SENSOR="${1:?usage: sudo bash setup_honeypot.sh <sensor-name> [--blocklists]}"
WITH_BLOCKLISTS="${2:-}"
ADMIN_PORT=50022
COWRIE_UID=999          # the user the official cowrie/cowrie image runs as
BASE=/opt/honeypot
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ "$SENSOR" =~ ^[a-z0-9-]+$ ]] || { echo "Sensor name: lowercase letters, digits and dashes only."; exit 1; }

echo "== 1/6 packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q docker.io docker-compose-v2 python3 unattended-upgrades
systemctl enable --now docker unattended-upgrades

echo "== 2/6 firewall rules (inbound allow, redirect, outbound block), re-applied at every boot"
cat > /usr/local/sbin/honeypot-firewall.sh <<EOF
#!/usr/bin/env bash
add() { iptables -C "\$@" 2>/dev/null || iptables -A "\$@"; }
top() { local chain=\$1; shift; iptables -C "\$chain" "\$@" 2>/dev/null || iptables -I "\$chain" 1 "\$@"; }
# allow admin SSH and the honeypot ports ahead of any REJECT rule the image ships with (Oracle)
top INPUT -p tcp --dport $ADMIN_PORT -j ACCEPT
top INPUT -p tcp --dport 2222 -j ACCEPT
top INPUT -p tcp --dport 2223 -j ACCEPT
# attackers on 22/23 reach Cowrie on 2222/2223
add PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-ports 2222
add PREROUTING -t nat -p tcp --dport 23 -j REDIRECT --to-ports 2223
# Cowrie may answer connections, but may not START any outbound connection
add OUTPUT -m owner --uid-owner $COWRIE_UID -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
add OUTPUT -m owner --uid-owner $COWRIE_UID -j REJECT
EOF
chmod 755 /usr/local/sbin/honeypot-firewall.sh
cat > /etc/systemd/system/honeypot-firewall.service <<EOF
[Unit]
Description=Honeypot port redirect and outbound block
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now honeypot-firewall.service

echo "== 3/6 admin SSH -> port $ADMIN_PORT, keys only"
cat > /etc/ssh/sshd_config.d/10-honeypot-admin.conf <<EOF
Port $ADMIN_PORT
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sshd -t
systemctl daemon-reload
# Ubuntu 24.04 starts sshd through ssh.socket; restarting both applies the new port.
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh
echo "   Admin SSH now listens on $ADMIN_PORT. Keep THIS session open and test a new one on that port."

echo "== 4/6 Cowrie"
mkdir -p "$BASE"/var/log/cowrie "$BASE"/var/lib/cowrie/downloads "$BASE"/var/lib/cowrie/tty "$BASE"/var/run \
         "$BASE"/blocklists "$BASE"/hashes
chown -R $COWRIE_UID:$COWRIE_UID "$BASE"/var
cat > "$BASE"/docker-compose.yml <<EOF
volumes:
  cowrie-etc:
services:
  cowrie:
    image: cowrie/cowrie:latest
    restart: unless-stopped
    network_mode: host          # keeps attackers' real source IPs (bridge mode showed 172.x in the lab)
    environment:
      COWRIE_TELNET_ENABLED: "yes"
      COWRIE_HONEYPOT_SENSOR_NAME: "$SENSOR"
      COWRIE_HONEYPOT_HOSTNAME: "web-prod-02"
      COWRIE_HONEYPOT_TIMEZONE: "UTC"
    volumes:
      - cowrie-etc:/cowrie/cowrie-git/etc
      - $BASE/var:/cowrie/cowrie-git/var
    cap_drop: [ALL]
    read_only: true
    security_opt: ["no-new-privileges:true"]
EOF
docker compose -f "$BASE"/docker-compose.yml pull -q
docker compose -f "$BASE"/docker-compose.yml up -d

echo "== 5/6 daily jobs"
cat > /usr/local/sbin/honeypot-daily.sh <<EOF
#!/usr/bin/env bash
# Record SHA-256 of any file Cowrie saved, then delete the files (they are never run).
cd $BASE/var/lib/cowrie/downloads && for f in *; do
  [ -f "\$f" ] || continue
  echo "\$(date -u +%FT%TZ) \$(sha256sum "\$f")" >> $BASE/hashes/downloads_sha256.txt
  rm -f -- "\$f"
done
EOF
if [[ "$WITH_BLOCKLISTS" == "--blocklists" ]]; then
  cp "$HERE"/fetch_blocklists.py "$BASE"/fetch_blocklists.py
  echo "python3 $BASE/fetch_blocklists.py --out $BASE/blocklists >> $BASE/blocklists/fetch.log 2>&1" \
    >> /usr/local/sbin/honeypot-daily.sh
fi
chmod 755 /usr/local/sbin/honeypot-daily.sh
echo "15 6 * * * root /usr/local/sbin/honeypot-daily.sh" > /etc/cron.d/honeypot-daily
[[ "$WITH_BLOCKLISTS" == "--blocklists" ]] && /usr/local/sbin/honeypot-daily.sh || true

echo "== 6/6 checks"
sleep 8
docker compose -f "$BASE"/docker-compose.yml ps
iptables -t nat -S PREROUTING | grep REDIRECT
iptables -S OUTPUT | grep owner
iptables -S INPUT | grep -E 'dport (50022|2222|2223)'
tail -n 3 "$BASE"/var/log/cowrie/cowrie.log 2>/dev/null || echo "   (cowrie.log not written yet, check again in a minute)"
echo
echo "Done. Sensor '$SENSOR' is running. Nothing reaches it until you open ports 22/23 in the cloud firewall."
