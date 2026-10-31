"""
RQ2: were the attackers already on public blocklists, and how much would blocking have stopped?

Usage (after parse_cowrie.py):
    python analysis/check_blocklists.py --parsed output --blocklists data/blocklists --out output

For every attacker IP it uses the blocklist snapshot a defender would actually have
had: the latest snapshot fetched BEFORE that IP's first contact. It also looks at
later snapshots to see whether (and how many days after) the IP was listed.

Outputs:
    blocklist_attackers.csv  per IP and list: listed before first attack? first date listed? lag in days
    blocklist_summary.txt    coverage per list and for "any list", by attacker category and by sensor,
                             plus the share of sessions that blocking would have prevented
IPv4 only (Cowrie on a typical cloud VM sees IPv4); IPv6 addresses are counted and skipped.
"""
import argparse
import bisect
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class IPSet:
    """Fast membership test for a list of IPv4 addresses and CIDR ranges."""

    def __init__(self, lines):
        ranges = []
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if not line or not line[0].isdigit():
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version == 4:
                ranges.append((int(net.network_address), int(net.broadcast_address)))
        ranges.sort()
        merged = []
        for lo, hi in ranges:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.starts = [r[0] for r in merged]
        self.ends = [r[1] for r in merged]

    def __contains__(self, ip_int):
        i = bisect.bisect_right(self.starts, ip_int) - 1
        return i >= 0 and ip_int <= self.ends[i]


def load_snapshots(root):
    """Return {list_name: [(fetched_at, IPSet), ...] sorted by time}."""
    snaps = defaultdict(list)
    for day in sorted(Path(root).iterdir()):
        mf = day / "manifest.json"
        if not mf.exists():
            continue
        for name, meta in json.loads(mf.read_text()).items():
            f = day / f"{name}.txt"
            if f.exists():
                snaps[name].append((ts(meta["fetched_at"]), IPSet(f.read_text().splitlines())))
    for name in snaps:
        snaps[name].sort(key=lambda x: x[0])
    return snaps


def listed_before(snaps_for_list, ip_int, when):
    """True/False using the latest snapshot fetched before `when`; None if no such snapshot."""
    times = [t for t, _ in snaps_for_list]
    i = bisect.bisect_right(times, when) - 1
    if i < 0:
        return None
    return ip_int in snaps_for_list[i][1]


def first_listed(snaps_for_list, ip_int):
    for t, s in snaps_for_list:
        if ip_int in s:
            return t
    return None


def pct(n, d):
    return f"{100 * n / d:5.1f}% ({n}/{d})" if d else "  n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parsed", default="output", help="folder with attackers.csv and sessions.csv")
    ap.add_argument("--blocklists", default="data/blocklists")
    ap.add_argument("--out", default="output")
    args = ap.parse_args()

    snaps = load_snapshots(args.blocklists)
    if not snaps:
        raise SystemExit("No blocklist snapshots found. Run scripts/fetch_blocklists.py daily first.")
    names = sorted(snaps)
    attackers = list(csv.DictReader(open(Path(args.parsed) / "attackers.csv", encoding="utf-8")))
    sessions = list(csv.DictReader(open(Path(args.parsed) / "sessions.csv", encoding="utf-8")))

    rows, skipped_v6 = [], 0
    ip_int = {}
    for a in attackers:
        try:
            addr = ipaddress.ip_address(a["src_ip"])
        except ValueError:
            continue
        if addr.version != 4:
            skipped_v6 += 1
            continue
        n = int(addr)
        ip_int[a["src_ip"]] = n
        first = ts(a["first_seen"])
        row = {"src_ip": a["src_ip"], "first_seen": a["first_seen"], "worst_category": a["worst_category"],
               "sensors": a["sensors"], "sessions": a["sessions"]}
        any_before, any_ever, any_snapshot = False, None, False
        for name in names:
            before = listed_before(snaps[name], n, first)
            any_snapshot = any_snapshot or before is not None
            fl = first_listed(snaps[name], n)
            row[f"{name}_before"] = {True: "yes", False: "no", None: "no_snapshot"}[before]
            row[f"{name}_lag_days"] = round((fl - first).total_seconds() / 86400, 2) if fl else ""
            any_before = any_before or bool(before)
            if fl and (any_ever is None or fl < any_ever):
                any_ever = fl
        row["any_before"] = "yes" if any_before else ("no" if any_snapshot else "no_snapshot")
        row["any_lag_days"] = round((any_ever - first).total_seconds() / 86400, 2) if any_ever else ""
        rows.append(row)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "blocklist_attackers.csv", "w", newline="", encoding="utf-8") as fh:
        if rows:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    # ---- summary
    L = [f"Snapshots: {', '.join(f'{n} ({len(snaps[n])} days)' for n in names)}",
         f"Attacker IPs analysed: {len(rows)}   (IPv6 skipped: {skipped_v6})", "",
         "== Attacker IPs already listed BEFORE their first attack"]
    for name in names + ["any"]:
        col = f"{name}_before"
        have = [r for r in rows if r[col] != "no_snapshot"]
        L.append(f"{name:18s} {pct(sum(r[col] == 'yes' for r in have), len(have))}")
    L += ["", "== Listed before first attack, by attacker category (any list)"]
    for cat in ["scanner", "brute_force", "intruder", "malware_dropper"]:
        rs = [r for r in rows if r["worst_category"] == cat and r["any_before"] != "no_snapshot"]
        L.append(f"{cat:18s} {pct(sum(r['any_before'] == 'yes' for r in rs), len(rs))}")
    L += ["", "== Listed before first attack, by sensor (any list)"]
    for sensor in sorted({s for r in rows for s in r["sensors"].split(";")}):
        rs = [r for r in rows if sensor in r["sensors"].split(";") and r["any_before"] != "no_snapshot"]
        L.append(f"{sensor:18s} {pct(sum(r['any_before'] == 'yes' for r in rs), len(rs))}")
    lags = [r["any_lag_days"] for r in rows if r["any_before"] == "no" and r["any_lag_days"] != ""]
    L += ["", f"Attackers listed only AFTER their first attack: {len(lags)}"
          + (f", median lag {sorted(lags)[len(lags) // 2]} days" if lags else "")]

    # session-level: would blocking with the latest snapshot have stopped this session?
    L += ["", "== Sessions that blocking would have prevented (latest snapshot before each session)"]
    for name in names + ["any"]:
        blocked = total = 0
        for s in sessions:
            n = ip_int.get(s["src_ip"])
            if n is None:
                continue
            when = ts(s["start"])
            results = [listed_before(snaps[x], n, when) for x in (names if name == "any" else [name])]
            if all(r is None for r in results):
                continue
            total += 1
            blocked += any(results)
        L.append(f"{name:18s} {pct(blocked, total)}")

    text = "\n".join(L) + "\n"
    (out / "blocklist_summary.txt").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
