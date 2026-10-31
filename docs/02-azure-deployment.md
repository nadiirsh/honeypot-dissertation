# Azure deployment guide

Two stages:

- **Rehearsal (now, before approval):** build one server in UK South and test everything with the honeypot
  ports open **to your own IP only**. Nobody else can reach it, so no attacker data is collected.
- **Go-live (only after ethics approval):** open ports 22 and 23 to the internet and build the other two servers.

## 0. Before anything: check your allowed regions

Azure for Students only lets you deploy to about five regions, and the list is different for each person.

Portal → search **Policy** → **Assignments** → open **Allowed resource deployment regions** → read **Allowed locations**.

You need **UK South**, **East US** and **Southeast Asia** (or close substitutes: UK West, another US region,
another Asian region). If no UK region is allowed, stop and tell Claude: the UK comparison is RQ1, and the
fallback is Oracle Cloud's Always Free tier in London.

## 1. Budget alert (2 minutes)

Portal → **Cost Management** → **Budgets** → **Add**: amount 100, alerts at 50% and 80%, your email.
Expected spend for the whole project: about $40 to $60.

## 2. Your public IP

Open https://ifconfig.me in your browser and note the address. Your home IP can change; if you suddenly can't
connect later, check it again and update the firewall rules.

## 3. Create the rehearsal VM

Portal → **Virtual machines** → **Create** → **Azure virtual machine**:

| Setting | Value |
|---|---|
| Resource group | Create new: `honeypot-rg` |
| Name | `hp-uk-south` |
| Region | UK South |
| Image | Ubuntu Server 24.04 LTS, x64 |
| Size | Standard_B1s (1 vCPU, 1 GiB) |
| Authentication | SSH public key, username `azureuser`, **Generate new key pair**, key name `hp-key` |
| Inbound ports | Allow SSH (22) for now; you lock it down in step 4 |
| Disks | defaults |
| Networking | defaults; tick **Delete public IP and NIC when VM is deleted** |

**Review + create** → **Create** → **Download private key**. Move `hp-key.pem` to `C:\Users\nadii\.ssh\`.

## 4. Lock down the firewall straight away

VM → **Networking** → **Network settings**:

1. Edit the SSH rule on port 22: **Source = My IP address**. Save.
2. Add an inbound rule: port **50022**, source **My IP address**, name `admin-ssh`, priority 310.

## 5. Copy the kit and run the setup

In PowerShell, from the project root (replace `VM_IP` with the VM's public IP):

```
ssh -i $HOME\.ssh\hp-key.pem azureuser@VM_IP "echo connected"
scp -i $HOME\.ssh\hp-key.pem deploy\setup_honeypot.sh deploy\fetch_blocklists.py azureuser@VM_IP:~/
ssh -i $HOME\.ssh\hp-key.pem azureuser@VM_IP
```

If SSH says the key is "UNPROTECTED", run this once and try again:
`icacls $HOME\.ssh\hp-key.pem /inheritance:r /grant:r "$($env:USERNAME):(R)"`

On the VM:

```
sudo bash setup_honeypot.sh uk-south --blocklists
```

It finishes with the Cowrie container `Up`, two REDIRECT rules and two owner rules. **Keep that window open**,
then in a **second** PowerShell window check that the new admin port works:

```
ssh -i $HOME\.ssh\hp-key.pem -p 50022 azureuser@VM_IP
```

Only when that works: in Azure, **delete** the old port-22 SSH rule from step 4. From now on you always use `-p 50022`.

## 6. Rehearsal test (your IP only)

Add an inbound rule: ports **22,23**, source **My IP address**, name `honeypot`, priority 300. Then from your laptop:

```
ssh -o UserKnownHostsFile=NUL root@VM_IP
```

Any password except `root`/`123456` works. You should land at `root@web-prod-02:~#`. Try `uname -a` and
`wget http://example.com/x.sh` (it must fail to download), then `exit`.

**The critical check:** on the VM (admin session on 50022):

```
sudo tail -n 3 /opt/honeypot/var/log/cowrie/cowrie.json
```

`"src_ip"` must be **your home IP from step 2**, not a 172.x or 10.x address. That proves real attacker IPs
will be recorded, which RQ2 depends on. Screenshot it.

Also check the first blocklist snapshot exists: `ls /opt/honeypot/blocklists`.

## 7. Test pulling the logs

Edit the top of `deploy\pull_logs.ps1`: the uk-south IP, your username, and the OneDrive folder. Then:

```
.\deploy\pull_logs.ps1
```

The log and blocklists should appear in your OneDrive `honeypot-data` folder.

## 8. Pause until approval

VM → **Stop**. Stopped (deallocated) VMs don't use compute credit; only the disk and IP cost a few pence a day.
The daily blocklist job only runs while the VM is on, so keep running `python scripts/fetch_blocklists.py`
on your laptop each day until go-live.

## Go-live (ONLY after ethics approval)

1. Start `hp-uk-south`. Edit the `honeypot` rule: source **Any**. Note the exact time (UTC).
2. Build `hp-east-us` (East US) and `hp-southeast-asia` (Southeast Asia) with steps 3 to 5, but run
   `sudo bash setup_honeypot.sh east-us` / `southeast-asia` **without** `--blocklists`. Add the `admin-ssh` rule
   and a `honeypot` rule (22,23, source **Any**) to each, noting each go-live time.
3. Create `golive.json` in the project root:
   ```
   {"uk-south": "2026-11-16T10:00:00Z", "east-us": "2026-11-16T10:20:00Z", "southeast-asia": "2026-11-16T10:40:00Z"}
   ```
4. Run `.\deploy\pull_logs.ps1` every day. Your rehearsal sessions came from your own IP: remove them before
   analysis (the ethics form says so).
5. After six weeks: **delete** the resource group `honeypot-rg` (deletes all three VMs, disks and IPs).
