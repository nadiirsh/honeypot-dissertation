"""
Rule set mapping attacker shell commands to MITRE ATT&CK (Enterprise, Linux) techniques.

Each rule is (technique_id, technique_name, regex). A command can match several rules.
These rules are the thing you validate in Objective 5: label 100 sessions by hand,
compare with what these rules say, and report the agreement.

Before the final write-up, check every ID still exists at https://attack.mitre.org
(ATT&CK is versioned and techniques are occasionally renamed or split), and record
the ATT&CK version you used in the dissertation.
"""
import re

RULES = [
    # Discovery
    ("T1082", "System Information Discovery",
     r"\buname\b|\bhostname\b|/proc/cpuinfo|\blscpu\b|\bnproc\b|\bfree\b|/proc/meminfo|\bdf\s+-h|/etc/os-release|\buptime\b|dmidecode"),
    ("T1033", "System Owner/User Discovery", r"\bwhoami\b|\bid\b(?!\w)|^\s*w\s*$|\blast\b|\bwho\b"),
    ("T1087.001", "Account Discovery: Local Account", r"/etc/passwd|/etc/shadow|/etc/group"),
    ("T1057", "Process Discovery", r"\bps\b(\s|$)|\btop\b|\bpgrep\b"),
    ("T1016", "System Network Configuration Discovery", r"\bifconfig\b|\bip\s+(a|addr|route)\b|/etc/resolv\.conf|\broute\b"),
    ("T1049", "System Network Connections Discovery", r"\bnetstat\b|\bss\s+-"),
    # Persistence and privilege
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", r"authorized_keys"),
    ("T1136.001", "Create Account: Local Account", r"\buseradd\b|\badduser\b"),
    ("T1053.003", "Scheduled Task/Job: Cron", r"\bcrontab\b|/etc/cron"),
    ("T1531", "Account Access Removal", r"\bchpasswd\b|(^|[;&|]\s*)(sudo\s+)?passwd(\s|$)"),
    # Execution and tool transfer
    ("T1105", "Ingress Tool Transfer", r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bscp\b|/dev/tcp/"),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell",
     r"\bsh\s+-c\b|\bbash\s+-c\b|\|\s*(ba)?sh\b|(^|[;&|]\s*)\./|(^|[;&|]\s*)/tmp/\S+|\bsh\s+\S+\.sh\b"),
    ("T1222.002", "File and Directory Permissions Modification: Linux",
     r"\bchmod\b|\bchattr\b|\bchown\b"),
    ("T1496", "Resource Hijacking", r"xmrig|minerd|cpuminer|stratum\+tcp|\bxmr\b|nicehash"),
    # Defence evasion
    ("T1070.003", "Indicator Removal: Clear Command History", r"history\s+-c|HISTFILE|\.bash_history"),
    ("T1070.004", "Indicator Removal: File Deletion", r"\brm\s+-(r|f|rf|fr)\b"),
    ("T1562.004", "Impair Defenses: Disable or Modify System Firewall", r"\biptables\s+-F\b|\bufw\s+disable\b"),
]

_COMPILED = [(tid, name, re.compile(rx, re.IGNORECASE)) for tid, name, rx in RULES]

TECHNIQUE_NAMES = {tid: name for tid, name, _ in RULES}
TECHNIQUE_NAMES["T1110.001"] = "Brute Force: Password Guessing"


def map_command(command: str) -> list[str]:
    """Return the sorted list of ATT&CK technique IDs matched by one command line."""
    return sorted({tid for tid, _, rx in _COMPILED if rx.search(command or "")})
