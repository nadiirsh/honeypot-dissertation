# Copy honeypot logs (and blocklist snapshots) from the Azure VMs to your OneDrive.
# Run daily from the project root in PowerShell:
#     .\deploy\pull_logs.ps1
#
# Edit the three settings below once. Uses the ssh/scp built into Windows 10/11.

$Sensors = @{
    "uk-south"       = "203.0.113.11"   # <- replace with each VM's public IP
    "east-us"        = "203.0.113.12"
    "southeast-asia" = "203.0.113.13"
}
$BlocklistSensor = "uk-south"            # the VM you set up with --blocklists
$Dest = "$env:OneDrive\honeypot-data"   # master copy on your St Mary's OneDrive (per the ethics form)
$User = "azureuser"                      # the admin username you chose when creating the VMs
$Port = 50022

foreach ($name in $Sensors.Keys) {
    $ip = $Sensors[$name]
    $out = Join-Path $Dest "logs\$name"
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    Write-Host "== $name ($ip)"
    scp -P $Port -q "${User}@${ip}:/opt/honeypot/var/log/cowrie/cowrie.json*" "$out\"
    scp -P $Port -q "${User}@${ip}:/opt/honeypot/hashes/downloads_sha256.txt" "$out\" 2>$null
}

$ip = $Sensors[$BlocklistSensor]
$bl = Join-Path $Dest "blocklists"
New-Item -ItemType Directory -Force -Path $bl | Out-Null
Write-Host "== blocklists from $BlocklistSensor"
scp -P $Port -q -r "${User}@${ip}:/opt/honeypot/blocklists/*" "$bl\"

Write-Host "`nDone. Analyse with:"
Write-Host "  python analysis\parse_cowrie.py `"$Dest\logs\uk-south`" `"$Dest\logs\east-us`" `"$Dest\logs\southeast-asia`" --out output --golive golive.json"
Write-Host "  python analysis\check_blocklists.py --blocklists `"$bl`""
