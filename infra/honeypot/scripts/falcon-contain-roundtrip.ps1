<#
  Falcon Contain -> Lift round-trip validator (Plan 0B Task 7).
  NO SECRETS IN THIS FILE. Pass creds via params or env (CS_ID/CS_SECRET/CS_BASE).
  Containing the honeypot briefly cuts its egress (Splunk telemetry pauses; the UF
  queues to disk and backfills). We lift immediately. Falcon cloud stays reachable.
  Usage:
    $env:CS_ID='...'; $env:CS_SECRET='...'; $env:CS_BASE='https://api.crowdstrike.com'
    ./falcon-contain-roundtrip.ps1 -Hostname 'vm-honeypot-win'
#>
param(
  [string]$ClientId   = $env:CS_ID,
  [string]$ClientSecret = $env:CS_SECRET,
  [string]$BaseUrl    = $env:CS_BASE,
  [Parameter(Mandatory=$true)][string]$Hostname
)
$ErrorActionPreference = 'Stop'

function Get-Token {
  $b = @{ client_id = $ClientId; client_secret = $ClientSecret }
  (Invoke-RestMethod -Method Post -Uri "$BaseUrl/oauth2/token" -Body $b `
     -ContentType 'application/x-www-form-urlencoded').access_token
}
function Get-Status($h, $aid) {
  $body = @{ ids = @($aid) } | ConvertTo-Json
  (Invoke-RestMethod -Method Post -Headers $h -Uri "$BaseUrl/devices/entities/devices/v2" `
     -Body $body -ContentType 'application/json').resources[0].status
}

$h = @{ Authorization = "Bearer $(Get-Token)" }

# 1. Resolve the honeypot AID by hostname (Hosts: Read)
$aid = (Invoke-RestMethod -Method Get -Headers $h `
  -Uri "$BaseUrl/devices/queries/devices/v1?filter=hostname:'$Hostname'").resources[0]
if (-not $aid) { throw "No host found for hostname '$Hostname'" }
Write-Host "AID = $aid · status = $(Get-Status $h $aid)"

# 2. Contain (Hosts: Write)
$body = @{ ids = @($aid) } | ConvertTo-Json
Invoke-RestMethod -Method Post -Headers $h `
  -Uri "$BaseUrl/devices/entities/devices-actions/v2?action_name=contain" `
  -Body $body -ContentType 'application/json' | Out-Null
Write-Host "Contain requested. Polling..."
for ($i=0; $i -lt 12; $i++) {
  Start-Sleep -Seconds 10
  $s = Get-Status $h $aid
  Write-Host "  status = $s"
  if ($s -eq 'contained') { break }
}

# 3. Lift containment
Invoke-RestMethod -Method Post -Headers $h `
  -Uri "$BaseUrl/devices/entities/devices-actions/v2?action_name=lift_containment" `
  -Body $body -ContentType 'application/json' | Out-Null
Write-Host "Lift requested. Polling..."
for ($i=0; $i -lt 12; $i++) {
  Start-Sleep -Seconds 10
  $s = Get-Status $h $aid
  Write-Host "  status = $s"
  if ($s -eq 'normal') { break }
}
Write-Host "Round-trip complete. Final status = $(Get-Status $h $aid)"
