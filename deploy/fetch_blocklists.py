"""
Download today's snapshot of each public IP blocklist (RQ2 depends on these).

Run once a day, every day, for the whole deployment (on the cloud server this
will be scheduled with cron). A missed day cannot be recovered later: the FireHOL mirror only
keeps the latest version of each list, with no history.

Usage:
    python scripts/fetch_blocklists.py                  # saves to data/blocklists/YYYY-MM-DD/
    python scripts/fetch_blocklists.py --out somewhere

All lists come from FireHOL's GitHub mirror (github.com/firehol/blocklist-ipsets),
which re-publishes each original list in one consistent format and is reachable
from cloud servers that may be blocked by some list owners' sites.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
LISTS = {
    # name: (file in the FireHOL repo, why it is in the study)
    "firehol_level1": ("firehol_level1.netset", "FireHOL's recommended 'safe to block' aggregate"),
    "blocklist_de_ssh": ("blocklist_de_ssh.ipset", "fail2ban reports of SSH attacks, the closest match to this honeypot"),
    "blocklist_de_all": ("blocklist_de.ipset", "all attack types reported to blocklist.de"),
    "spamhaus_drop": ("spamhaus_drop.netset", "Spamhaus Don't Route Or Peer: hijacked and criminal networks"),
    "et_compromised": ("et_compromised.ipset", "Emerging Threats known-compromised hosts"),
    "ci_army": ("ciarmy.ipset", "CINS Army poor-reputation IPs"),
    "dshield_top": ("dshield.netset", "DShield top attacking /24 subnets"),
}


def fetch(url, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            print(f"  attempt {i + 1} failed: {exc}", file=sys.stderr)
            time.sleep(5 * (i + 1))
    return None


def header(text, field):
    m = re.search(rf"^#\s*{re.escape(field)}\s*:\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/blocklists")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    day_dir = Path(args.out) / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = day_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    failures = 0
    for name, (fname, why) in LISTS.items():
        print(f"{name} ...", end=" ", flush=True)
        text = fetch(BASE + fname)
        if text is None or not re.search(r"^\d", text, re.MULTILINE):
            print("FAILED")
            failures += 1
            continue
        (day_dir / f"{name}.txt").write_text(text, encoding="utf-8")
        entries = sum(1 for line in text.splitlines() if line and line[0].isdigit())
        manifest[name] = {
            "fetched_at": now.isoformat().replace("+00:00", "Z"),
            "source_file": BASE + fname,
            "original_source": header(text, "List source URL"),
            "list_file_date": header(text, "This File Date"),
            "entries": entries,
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "why": why,
        }
        print(f"{entries} entries (list dated {manifest[name]['list_file_date']})")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Saved to {day_dir}" + (f"  ({failures} list(s) FAILED, run again later today)" if failures else ""))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
