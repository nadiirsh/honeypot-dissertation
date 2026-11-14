# Copy honeypot logs (and blocklist snapshots) from the three sensors to logs.
# Run daily from the project root in PowerShell:
#     .\deploy\pull_logs.ps1
#
# Uses the ssh/scp built into Windows 10/11. Admin SSH on every sensor is on port 50022.

$Sensors = [ordered]@{
    "uk-london"      = @{ Login = "ubuntu@132.145.53.28";     Key = "$HOME\.ssh\oracle-key.key" }      # Oracle Cloud, London
    "sweden-central" = @{ Login = "azureuser@20.240.247.170"; Key = "$HOME\.ssh\hp-sweden_key.pem" }   # Azure Sweden Central
    "austria-east"   = @{ Login = "azureuser@68.210.224.86";  Key = "$HOME\.ssh\hp-sweden_key.pem" }   # Azure Austria East (reuses the Sweden key)
}
$BlocklistSensor = "sweden-central"      # the sensor set up with --blocklists
$Dest = "$HOME\OneDrive - St Marys University\honeypot-data"   # master copy on your St Mary's OneDrive (per the ethics form); check the folder name matches yours
$Port = 50022

if (-not (Test-Path (Split-Path $Dest -Parent))) {
    Write-Host "OneDrive folder not found: $(Split-Path $Dest -Parent)"
    Write-Host "Sign in to OneDrive with your St Mary's account, then fix the `$Dest line in this script."
    exit 1
}

foreach ($name in $Sensors.Keys) {
    $s = $Sensors[$name]
    $out = Join-Path $Dest "logs\$name"
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    Write-Host "== $name ($($s.Login))"
    scp -i $s.Key -P $Port -q "$($s.Login):/opt/honeypot/var/log/cowrie/cowrie.json*" "$out"
    scp -i $s.Key -P $Port -q "$($s.Login):/opt/honeypot/hashes/downloads_sha256.txt" "$out" 2>$null
}

$s = $Sensors[$BlocklistSensor]
$bl = Join-Path $Dest "blocklists"
New-Item -ItemType Directory -Force -Path $bl | Out-Null
Write-Host "== blocklists from $BlocklistSensor"
scp -i $s.Key -P $Port -q -r "$($s.Login):/opt/honeypot/blocklists/*" "$bl"

Write-Host "`nDone. Analyse with:"
Write-Host "  python analysis\parse_cowrie.py `"$Dest\logs\uk-london`" `"$Dest\logs\sweden-central`" `"$Dest\logs\austria-east`" --out output --golive golive.json"
Write-Host "  python analysis\check_blocklists.py --blocklists `"$bl`""