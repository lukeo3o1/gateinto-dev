param(
  [Parameter(Mandatory)] [string] $Path,
  [Parameter(Mandatory)] [string] $Version
)

$ErrorActionPreference = 'Stop'

$out = (& $Path --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "$Path --version exited with $LASTEXITCODE" }
$out
if ($out -ne "gateinto $Version") { throw "$Path --version printed '$out', expected 'gateinto $Version'" }
