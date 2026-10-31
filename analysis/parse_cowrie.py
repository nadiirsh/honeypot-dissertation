"""
Parse Cowrie JSON logs into analysis-ready CSV files.

Usage:
    python analysis/parse_cowrie.py data/logs --out output [--golive golive.json]

`data/logs` can hold any number of cowrie.json / cowrie.json.YYYY-MM-DD files from
any number of honeypots. The region of each event comes from Cowrie's "sensor"
field (set COWRIE_HONEYPOT_SENSOR_NAME on each server).

golive.json (optional) records when each honeypot went live, for time-to-first-attack:
    {"uk-south": "2026-12-01T10:00:00Z", "east-us": "2026-12-01T10:05:00Z"}

Outputs (in --out):
    sessions.csv     one row per session, with category and ATT&CK techniques
    commands.csv     one row per command, with ATT&CK techniques
    attackers.csv    one row per source IP, with first/last seen and worst category
    credentials.csv  username/password pairs and how often they were tried
    downloads.csv    files attackers fetched, uploaded or wrote (SHA-256 only, kind column says which)
    summary.txt      headline numbers per sensor, including time to first attack
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_rules import TECHNIQUE_NAMES, map_command  # noqa: E402

CATEGORY_ORDER = ["scanner", "brute_force", "intruder", "malware_dropper"]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def read_events(paths):
    files = []
    for p in paths:
        p = Path(p)
        files += sorted(p.glob("cowrie.json*")) if p.is_dir() else [p]
    seen, bad = set(), 0
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                # de-duplicate if the same log was copied twice
                key = (e.get("sensor"), e.get("session"), e.get("eventid"), e.get("timestamp"), e.get("input"))
                if key in seen:
                    continue
                seen.add(key)
                yield e
    if bad:
        print(f"warning: skipped {bad} malformed lines", file=sys.stderr)


def new_session():
    return {"sensor": None, "src_ip": None, "protocol": None, "dst_port": None,
            "start": None, "end": None, "duration_s": None, "client_version": "", "hassh": "",
            "login_failed": 0, "login_success": 0, "usernames": set(), "commands": [],
            "techniques": set(), "downloads": 0}


def classify(s):
    if s["downloads"] or "T1105" in s["techniques"]:
        return "malware_dropper"
    if s["commands"]:
        return "intruder"
    if s["login_failed"] or s["login_success"]:
        return "brute_force"
    return "scanner"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="log files or folders")
    ap.add_argument("--out", default="output")
    ap.add_argument("--golive", help="JSON file of go-live times per sensor")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    sessions = defaultdict(new_session)
    commands, downloads = [], []
    creds = Counter()

    for e in read_events(args.paths):
        sid = (e.get("sensor", "unknown"), e.get("session"))
        s = sessions[sid]
        t = e.get("timestamp")
        s["sensor"] = s["sensor"] or e.get("sensor", "unknown")
        s["src_ip"] = s["src_ip"] or e.get("src_ip")
        s["protocol"] = s["protocol"] or e.get("protocol")
        s["dst_port"] = s["dst_port"] or e.get("dst_port")
        if t:
            s["start"] = min(s["start"], t) if s["start"] else t
            s["end"] = max(s["end"], t) if s["end"] else t
        ev = e.get("eventid", "")
        if ev == "cowrie.client.version":
            s["client_version"] = e.get("version", "")
        elif ev == "cowrie.client.kex":
            s["hassh"] = e.get("hassh", "")
        elif ev in ("cowrie.login.failed", "cowrie.login.success"):
            s["login_failed" if ev.endswith("failed") else "login_success"] += 1
            s["usernames"].add(e.get("username", ""))
            s["techniques"].add("T1110.001")
            creds[(e.get("username", ""), e.get("password", ""), ev.rsplit(".", 1)[1])] += 1
        elif ev == "cowrie.command.input":
            cmd = e.get("input", "")
            tech = map_command(cmd)
            s["commands"].append(cmd)
            s["techniques"].update(tech)
            commands.append({"sensor": s["sensor"], "session": sid[1], "src_ip": s["src_ip"],
                             "timestamp": t, "command": cmd, "techniques": ";".join(tech)})
        elif ev.startswith("cowrie.session.file_download") or ev == "cowrie.session.file_upload":
            # Cowrie also logs files written with shell redirection (echo ... > file) as
            # file_download events with no URL. Count only real transfers as downloads.
            if ev == "cowrie.session.file_upload":
                kind = "upload"
            elif e.get("url"):
                kind = "download_failed" if ev.endswith(".failed") else "download"
            else:
                kind = "redirect_write"
            if kind in ("download", "download_failed", "upload"):
                s["downloads"] += 1
            downloads.append({"sensor": s["sensor"], "session": sid[1], "src_ip": s["src_ip"],
                              "timestamp": t, "kind": kind, "url": e.get("url", ""),
                              "destfile": e.get("destfile", ""), "sha256": e.get("shasum", "")})
        elif ev == "cowrie.session.closed" and e.get("duration") is not None:
            s["duration_s"] = e.get("duration")
        elif ev == "cowrie.session.closed" and e.get("duration_ms") is not None:
            s["duration_s"] = round(e["duration_ms"] / 1000, 3)

    # ---- sessions.csv
    rows = []
    for (sensor, sid), s in sessions.items():
        if not s["start"]:
            continue
        s["category"] = classify(s)
        rows.append({"sensor": sensor, "session": sid, "src_ip": s["src_ip"], "protocol": s["protocol"],
                     "dst_port": s["dst_port"], "start": s["start"], "end": s["end"],
                     "duration_s": s["duration_s"], "client_version": s["client_version"], "hassh": s["hassh"],
                     "login_failed": s["login_failed"], "login_success": s["login_success"],
                     "usernames": ";".join(sorted(u for u in s["usernames"] if u)),
                     "n_commands": len(s["commands"]), "downloads": s["downloads"],
                     "category": s["category"], "techniques": ";".join(sorted(s["techniques"]))})
    rows.sort(key=lambda r: r["start"])
    write_csv(out / "sessions.csv", rows)
    write_csv(out / "commands.csv", commands)
    write_csv(out / "downloads.csv", downloads)
    write_csv(out / "credentials.csv",
              [{"username": u, "password": p, "result": r, "count": n} for (u, p, r), n in creds.most_common()])

    # ---- attackers.csv (one row per IP)
    by_ip = defaultdict(lambda: {"sessions": 0, "sensors": set(), "first_seen": None, "last_seen": None,
                                 "category": "scanner", "techniques": set()})
    for r in rows:
        a = by_ip[r["src_ip"]]
        a["sessions"] += 1
        a["sensors"].add(r["sensor"])
        a["first_seen"] = min(a["first_seen"], r["start"]) if a["first_seen"] else r["start"]
        a["last_seen"] = max(a["last_seen"], r["end"]) if a["last_seen"] else r["end"]
        if CATEGORY_ORDER.index(r["category"]) > CATEGORY_ORDER.index(a["category"]):
            a["category"] = r["category"]
        a["techniques"].update(t for t in r["techniques"].split(";") if t)
    write_csv(out / "attackers.csv",
              [{"src_ip": ip, "sessions": a["sessions"], "n_sensors": len(a["sensors"]),
                "sensors": ";".join(sorted(a["sensors"])), "first_seen": a["first_seen"],
                "last_seen": a["last_seen"], "worst_category": a["category"],
                "techniques": ";".join(sorted(a["techniques"]))} for ip, a in by_ip.items()])

    # ---- summary.txt
    golive = json.loads(Path(args.golive).read_text()) if args.golive else {}
    lines = []
    for sensor in sorted({r["sensor"] for r in rows}):
        rs = [r for r in rows if r["sensor"] == sensor]
        start = ts(golive[sensor]) if sensor in golive else ts(rs[0]["start"])
        note = "from go-live" if sensor in golive else "from first event (no go-live time given)"

        def first(pred):
            hits = [r for r in rs if pred(r)]
            if not hits:
                return "none yet"
            delta = ts(hits[0]["start"]) - start
            return f"{delta.total_seconds() / 60:.1f} min"

        cats = Counter(r["category"] for r in rs)
        tech = Counter(t for r in rs for t in r["techniques"].split(";") if t)
        lines += [f"== {sensor}",
                  f"sessions: {len(rs)}   unique IPs: {len({r['src_ip'] for r in rs})}",
                  f"time to first connection ({note}): {first(lambda r: True)}",
                  f"time to first login attempt: {first(lambda r: r['login_failed'] or r['login_success'])}",
                  f"time to first command: {first(lambda r: r['n_commands'])}",
                  "categories: " + ", ".join(f"{c}={cats.get(c, 0)}" for c in CATEGORY_ORDER),
                  "top techniques: " + ", ".join(f"{t} {TECHNIQUE_NAMES.get(t, '')} ({n})" for t, n in tech.most_common(8)),
                  ""]
    top_creds = Counter()
    for (u, p, _), n in creds.items():
        top_creds[(u, p)] += n
    lines += ["== top credentials (all sensors)"] + [f"{u}/{p}: {n}" for (u, p), n in top_creds.most_common(10)]
    (out / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {len(rows)} sessions, {len(commands)} commands, {len(by_ip)} attacker IPs to {out}/")


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        if not rows:
            fh.write("")
            return
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
