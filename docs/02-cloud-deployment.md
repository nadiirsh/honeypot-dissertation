# Cloud deployment guide

Three sensors, all free:

| Sensor name | Provider | Region | Role |
|---|---|---|---|
| `uk-london` | Oracle Cloud (Always Free) | UK South (London) | the UK sensor |
| `sweden-central` | Azure for Students | Sweden Central | EU sensor + daily blocklist snapshots |
| `austria-east` | Azure for Students | Austria East (Vienna) | EU sensor |

Your Azure for Students account only allows Denmark East, Austria East, Germany West Central, Norway East and
Sweden Central, so the UK sensor runs on Oracle. The cheap B-series sizes were not offered in Germany West Central,
so the second EU sensor is in Austria East. All data stays in the UK/EU.

Two stages:

- **Rehearsal (now, before approval):** build the servers and test them with the honeypot ports open **to your own
  IP only**. Nobody else can reach them, so no attacker data is collected.
- **Go-live (only after ethics approval):** open ports 22 and 23 to the internet.

Before you start: open https://ifconfig.me and note your public IP (`MY_IP` below). If you suddenly can't connect
later, check it again: home IPs change.

---

## Part A: Azure (Sweden Central first)

### A1. Budget alert
Portal → **Cost Management** → **Budgets** → **Add**: amount 100, alerts at 50% and 80%. Expected spend for two
B2ats_v2 servers over six weeks, including IPs and disks: about $25 to $40.

### A2. Create the VM
Portal → **Virtual machines** → **Create** → **Azure virtual machine**:

| Setting | Value |
|---|---|
| Resource group | Create new: `honeypot-rg` |
| Name | `hp-sweden-central` |
| Region | Sweden Central |
| Image | Ubuntu Server 24.04 LTS, x64 |
| Size | **Standard_B2ats_v2** (2 vCPU, 1 GiB): clear the size search box and type just `B2ats` |
| Disks | Standard SSD (not Premium) |
| Authentication | SSH public key, username `azureuser`, **Generate new key pair**, name `hp-key` |
| Inbound ports | Allow SSH (22) for now; you lock it down in A3 |
| Networking | defaults; tick **Delete public IP and NIC when VM is deleted** |

**Review + create** → **Create** → **Download private key**, and move `hp-key.pem` to `C:\Users\nadii\.ssh\`.

### A3. Lock down the firewall straight away
VM → **Networking** → **Network settings**:
1. Edit the SSH rule (port 22): **Source = My IP address**.
2. Add a rule: port **50022**, source **My IP address**, name `admin-ssh`, priority 310.

### A4. Copy the kit and run the setup (PowerShell, project root)
```
scp -i $HOME\.ssh\hp-key.pem deploy\setup_honeypot.sh deploy\fetch_blocklists.py azureuser@VM_IP:~/
ssh -i $HOME\.ssh\hp-key.pem azureuser@VM_IP
```
If SSH says the key is "UNPROTECTED": `icacls $HOME\.ssh\hp-key.pem /inheritance:r /grant:r "$($env:USERNAME):(R)"`

On the VM:
```
sudo bash setup_honeypot.sh sweden-central --blocklists
```
**Keep that window open.** In a second PowerShell window, check the new admin port works:
```
ssh -i $HOME\.ssh\hp-key.pem -p 50022 azureuser@VM_IP
```
Only then delete the old port-22 SSH rule in Azure. From now on always use `-p 50022`.

### A5. Rehearsal test (your IP only)
Add a rule: ports **22,23**, source **My IP address**, name `honeypot`, priority 300. From your laptop:
```
ssh -o UserKnownHostsFile=NUL root@VM_IP
```
Any password except `root`/`123456`. You should see `root@web-prod-02:~#`. Try `uname -a` and
`wget http://example.com/x.sh` (it must fail), then `exit`. Then, in your admin session:
```
sudo tail -n 3 /opt/honeypot/var/log/cowrie/cowrie.json
ls /opt/honeypot/blocklists
```
**Critical check:** `"src_ip"` must be **your home IP**, not 172.x or 10.x. Screenshot it. The blocklists folder should
have today's date.

### A6. Austria East
Repeat A2 to A5 with name `hp-austria-east`, region **Austria East**, size **Standard_B2ats_v2**, the **same** key
(choose "Use existing key" → `hp-key`), and `sudo bash setup_honeypot.sh austria-east` (no `--blocklists`).
If you get a vCPU quota error, the two B2ats_v2 servers (2 vCPUs each) may exceed your student limit: tell Claude.

---

## Part B: Oracle Cloud (London)

### B1. Sign up
https://www.oracle.com/uk/cloud/free/ → **Start for free**. Oracle asks for a debit/credit card **for identity checks
only**; Always Free resources are not charged, and you should **not** upgrade the account.

**Home region: choose UK South (London).** This can't be changed later, and Always Free servers only run in your
home region.

### B2. Create the instance
Menu → **Compute** → **Instances** → **Create instance**:

| Setting | Value |
|---|---|
| Name | `hp-uk-london` |
| Image | Canonical Ubuntu 24.04 |
| Shape | **VM.Standard.E2.1.Micro** (marked "Always Free-eligible") |
| Networking | defaults (new VCN, public IPv4 address) |
| SSH keys | **Generate a key pair**, download the private key, save it as `C:\Users\nadii\.ssh\oracle-key.key` |

If you get "out of host capacity", try another availability domain or try again later.

### B3. Cloud firewall (security list)
Instance → **Subnet** → **Security Lists** → **Default Security List** → **Ingress Rules**:
1. Edit the port 22 rule: source `MY_IP/32`.
2. Add: source `MY_IP/32`, TCP, destination port **50022**.
3. Add (rehearsal): source `MY_IP/32`, TCP, destination port **23**.

### B4. Setup and rehearsal
Same as A4 and A5, with user `ubuntu`, key `oracle-key.key`, and:
```
sudo bash setup_honeypot.sh uk-london
```
The script handles Oracle's built-in host firewall (it opens 50022, 2222 and 2223 before moving SSH). After checking
port 50022 works, change the port-22 rule's source to `MY_IP/32` only (it now reaches the honeypot, not admin SSH).

**Oracle may stop free servers that stay idle (CPU under 20%) for seven days.** The daily `pull_logs.ps1` run warns you if
`uk-london` is unreachable; restart it from the console the same day and record any gap as a limitation.

---

## Part C: daily log pull

Edit the top of `deploy\pull_logs.ps1` (the three IPs, users and key files, and your OneDrive folder), then:
```
.\deploy\pull_logs.ps1
```

## Pause until approval
Stop the two Azure VMs (Stop = no compute charge). Leave the Oracle one running (it's free). Keep running
`python scripts/fetch_blocklists.py` on your laptop each day until go-live.

## Go-live (ONLY after ethics approval)
1. Start the Azure VMs. On every sensor, change the honeypot rules for ports **22 and 23** to source **Any**
   (Azure: `*`; Oracle: `0.0.0.0/0`). Leave **50022** restricted to your IP. Note each go-live time (UTC).
2. Create `golive.json` in the project root, for example:
   ```
   {"uk-london": "2026-11-16T10:00:00Z", "sweden-central": "2026-11-16T10:20:00Z", "austria-east": "2026-11-16T10:40:00Z"}
   ```
3. Run `.\deploy\pull_logs.ps1` every day. Remove your own rehearsal sessions (your IP) before analysis.
4. After six weeks: delete resource group `honeypot-rg` in Azure and terminate the Oracle instance.
