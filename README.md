# SSH honeypot dissertation: toolkit

CPS6001 individual project, Nadiir Mahamed.
*Measuring attacks on internet-exposed SSH servers with honeypots: regional differences and the
effectiveness of public IP blocklists.*

## What's here

| Path | What it does | Research question |
|---|---|---|
| `lab/docker-compose.yml` | Cowrie SSH/Telnet honeypot for your laptop, reachable only from 127.0.0.1 | build/test |
| `lab/simulate_attacker.py` | Plays brute-forcer, recon bot and intruder against your local honeypot | test data |
| `analysis/parse_cowrie.py` | Turns Cowrie logs into sessions, commands, attackers, credentials, downloads; time to first attack per region | RQ1 |
| `analysis/attack_rules.py` | Maps attacker commands to MITRE ATT&CK techniques (the rule set you validate in Objective 5) | RQ1 |
| `scripts/fetch_blocklists.py` | Saves a daily snapshot of 7 public blocklists | RQ2 |
| `analysis/check_blocklists.py` | Were attackers listed *before* they attacked? How many sessions would blocking have stopped? | RQ2 |
| `docs/01-local-lab-guide.md` | Step-by-step for the local lab | |
| `deploy/setup_honeypot.sh` | Turns a fresh Ubuntu 24.04 Azure VM into a sensor: admin SSH on 50022, Cowrie with host networking (real attacker IPs), ports 22/23 redirected, Cowrie blocked from making outbound connections, daily hash-and-delete of saved files, optional daily blocklist snapshot | deploy |
| `deploy/pull_logs.ps1` | Copies logs and blocklists from the VMs to your OneDrive (Windows) | deploy |
| `docs/02-azure-deployment.md` | Rehearsal now (your IP only), go-live after ethics approval | |

The analysis and blocklist scripts only use the Python standard library. The simulator needs `paramiko`.

## How it was tested

- Cowrie itself was run and attacked from localhost; `parse_cowrie.py` was run on those real logs.
- Settings confirmed to work: `COWRIE_HONEYPOT_SENSOR_NAME` (labels every log line with the region),
  `COWRIE_HONEYPOT_HOSTNAME` (shell prompt shows `web-prod-02`, not the default giveaway `svr04`),
  `COWRIE_TELNET_ENABLED`.
- 15 test commands check the ATT&CK rules (e.g. `cat /etc/passwd` is account discovery, not a password change).
- `check_blocklists.py` was checked against hand-built cases: listed IP, IP inside a listed range,
  IP listed only after the attack, never-listed IP, attack before any snapshot, IPv6.
- `fetch_blocklists.py` was run against the live lists on 30 October 2026.
- `deploy/setup_honeypot.sh`: the firewall rules were tested against a running Cowrie (applied twice with no duplicates; Cowrie's user blocked from outbound connections while root can still fetch blocklists; inbound logins still work; an attacker `wget` is logged but fetches nothing). The daily hash-and-delete job was tested. The full script has not been run on an Azure VM yet: the rehearsal in `docs/02-azure-deployment.md` is that test.
- The lab `docker compose` setup was run successfully on Windows (Docker Desktop) on 31 October 2026.

## Two findings that matter for the dissertation

1. **Cowrie logs shell redirection as a "file download".** `echo key >> ~/.ssh/authorized_keys` produces a
   `cowrie.session.file_download` event with no URL. The parser records these as `redirect_write` so they
   don't inflate the malware-dropper count. Worth a sentence in your methodology.
2. **Blocklist snapshots can't be recreated later.** The FireHOL mirror keeps only the current version of
   each list. Snapshots must be taken every day of the deployment, or RQ2 has gaps.

## Plan

**November (now, no ethics approval needed)**
- [ ] Submit the ethics application (this is the critical path)
- [ ] Docker Desktop + Python installed, lab running (`docs/01-local-lab-guide.md`)
- [ ] Attack the lab by hand and with the simulator; run both analysis scripts
- [ ] Hand-label your lab sessions against `attack_rules.py`, note any rule you'd change
- [ ] Literature review draft (Provos 2004, Sophos 2019, Chen 2021, Valeros et al. 2023, Deri and Fusco 2023, Cossaro et al. 2025)
- [ ] Put the code (not data) in a private GitHub repo; `.gitignore` already excludes logs and outputs

**Next (before go-live, once approval is in sight)**
- Azure deployment: 3 VMs, admin SSH moved off port 22 and locked to your IP, honeypot on 22/23,
  outbound traffic blocked, daily log backup + blocklist snapshot via cron, downloaded files reduced to hashes.
- `golive.json` with the exact go-live time of each region.

**Later**
- Regional statistics (chi-square, Kruskal-Wallis), charts, validation of the ATT&CK mapping on 100 sessions.
