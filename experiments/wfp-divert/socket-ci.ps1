param(
  [string] $Bin = "$env:RUNNER_TEMP\wfp-divert-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\wfp-socket-results",
  [string] $Fixture = 'target\release\examples\wfp_lab.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Socket observation requires an elevated administrator'
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
& icacls $OutDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict socket evidence directory ACL' }
$privateDir = Join-Path (Split-Path $OutDir -Parent) 'wfp-socket-private'
New-Item -ItemType Directory -Force $privateDir | Out-Null
& icacls $privateDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict private fixture directory ACL' }
@{
  os = [Environment]::OSVersion.VersionString
  image = $env:ImageOS
  image_version = $env:ImageVersion
  commit = $env:GITHUB_SHA
  topology = 'single-host-local IPv4'
  observation = 'WinDivert SOCKET and NETWORK SNIFF with native stored-event reference'
  routing_authority = $false
} | ConvertTo-Json | Set-Content (Join-Path $OutDir 'environment.json')

python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
if ($LASTEXITCODE) { throw 'Socket observation helper tests failed' }
& "$Bin\socket-events.exe" --self-test
if ($LASTEXITCODE) { throw 'Native socket and address-format helper tests failed' }
$cases = @(
  @{ name='tcp-live'; protocol='tcp'; iterations=3; concurrency=0; hold=500 },
  @{ name='udp-live'; protocol='udp'; iterations=3; concurrency=0; hold=500 },
  @{ name='tcp-short'; protocol='tcp'; iterations=20; concurrency=0; hold=0 },
  @{ name='udp-short'; protocol='udp'; iterations=20; concurrency=0; hold=0 },
  @{ name='tcp-burst'; protocol='tcp'; iterations=1; concurrency=50; hold=0 },
  @{ name='udp-burst'; protocol='udp'; iterations=1; concurrency=50; hold=0 }
)
$failures = [System.Collections.Generic.List[string]]::new()
try {
  foreach ($case in $cases) {
    Write-Host "Running $($case.name)"
    python "$PSScriptRoot\socket_probe.py" --bin $Bin --fixture $Fixture --private-dir $privateDir `
      --out (Join-Path $OutDir $case.name) --protocol $case.protocol --iterations $case.iterations `
      --concurrency $case.concurrency --client-hold-ms $case.hold --seconds 35 --drain-ms 1000
    if ($LASTEXITCODE) { $failures.Add($case.name) }
  }
} finally {
  python "$PSScriptRoot\socket_results.py" --root $OutDir --out (Join-Path $OutDir 'aggregate-evidence.json')
  if ($LASTEXITCODE) { $failures.Add('aggregate-evidence') }
  @{
    failed_cases = @($failures)
    capture_only = $true
    routing_authority = $false
    driver_queue_loss_observable = $false
    qualification = 'Controlled observation coverage and timing only; no packet admission or proxy routing tested'
  } | ConvertTo-Json | Set-Content (Join-Path $OutDir 'ci-summary.json')
}
if ($failures.Count) { throw "Socket observation cases failed: $($failures -join ', ')" }
