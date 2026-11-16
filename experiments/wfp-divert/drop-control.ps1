param(
  [string] $Bin = "$env:RUNNER_TEMP\wfp-divert-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\wfp-native-control"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ruleName = 'Gateinto-WFP-positive-' + [guid]::NewGuid().ToString('N')
$code = 1
try {
  $external = [System.Net.Dns]::GetHostAddresses('api.github.com') |
    Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
  if (-not $external) { throw 'No external IPv4 address resolved for drop control' }
  New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Action Block -Direction Outbound `
    -Program (Join-Path $Bin 'app-b.exe') -RemoteAddress $external.IPAddressToString `
    -RemotePort 443 -Protocol TCP -Profile Any | Out-Null
  python "$PSScriptRoot\positive_control.py" --bin $Bin --out $OutDir --target $external.IPAddressToString
  $code = $LASTEXITCODE
} finally {
  Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
if ($code) { throw 'Native drop callback control was not verified; inspect summary.json' }
