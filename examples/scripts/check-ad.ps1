# Runs INSIDE the restored Windows guest (powershell -File).
$ErrorActionPreference = "Stop"
Write-Output "pbv check on $env:PBV_VM_NAME ($env:PBV_TEMP_VMID)"
$svc = Get-Service -Name NTDS, DNS, Netlogon
$bad = $svc | Where-Object Status -ne "Running"
if ($bad) { Write-Output ("not running: " + ($bad.Name -join ", ")); exit 1 }
# SYSVOL share present?
if (-not (Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue)) { exit 2 }
exit 0
