param(
  [string] $Bin = "$env:RUNNER_TEMP\wfp-divert-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\wfp-socket-routing-results",
  [string] $Fixture = 'target\release\examples\wfp_lab.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Routing experiment requires an elevated administrator'
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
& icacls $OutDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict routing evidence directory ACL' }
$privateDir = Join-Path (Split-Path $OutDir -Parent) 'wfp-socket-routing-private'
New-Item -ItemType Directory -Force $privateDir | Out-Null
& icacls $privateDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict private fixture directory ACL' }
@{
  os = [Environment]::OSVersion.VersionString
  image = $env:ImageOS
  image_version = $env:ImageVersion
  commit = $env:GITHUB_SHA
  topology = 'single-host IPv4 loopback'
  experiment = 'TCP hold and proxy redirect, WFP versus SOCKET ownership'
  audit = 'Independent native WFP poll, 1000 ms interval, before engine startup'
  default_ownership_source = 'wfp'
} | ConvertTo-Json | Set-Content (Join-Path $OutDir 'environment.json')

python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
if ($LASTEXITCODE) { throw 'Routing experiment helper tests failed' }
& "$Bin\socket-events.exe" --self-test
if ($LASTEXITCODE) { throw 'WinDivert metadata filter helper tests failed' }

$profiles = @(
  @{ label='short-wfp'; source='wfp'; iterations=20; concurrency=0; sequential=$true },
  @{ label='short-socket'; source='socket'; iterations=20; concurrency=0; sequential=$true },
  @{ label='burst-wfp'; source='wfp'; iterations=1; concurrency=50; sequential=$false },
  @{ label='burst-socket'; source='socket'; iterations=1; concurrency=50; sequential=$false }
)
$cases = @()
foreach ($benchmarkRound in @(1, 2)) {
  $order = @($profiles)
  if ($benchmarkRound -eq 2) { [array]::Reverse($order) }
  foreach ($routingProfile in $order) {
    $cases += @{ name="$($routingProfile.label)-r$benchmarkRound"; source=$routingProfile.source;
      iterations=$routingProfile.iterations; concurrency=$routingProfile.concurrency;
      sequential=$routingProfile.sequential; round=$benchmarkRound; hold=1000; delay=0; leak=$false }
  }
}
$cases += @{ name='socket-leakcheck'; source='socket'; iterations=3; concurrency=0;
  sequential=$false; round=0; hold=100; delay=250; leak=$true }
$failures = [System.Collections.Generic.List[string]]::new()
try {
  foreach ($case in $cases) {
    Write-Host "Running $($case.name)"
    $arguments = @("$PSScriptRoot\run.py", '--bin', $Bin, '--fixture', $Fixture,
      '--out', (Join-Path $OutDir $case.name), '--private-dir', $privateDir,
      '--engine', 'inproc', '--mode', 'redirect', '--protocol', 'tcp', '--native-reference',
      '--ownership-source', $case.source, '--lookup-mode', 'async', '--filter-cache', 'on',
      '--enum-scope', 'legacy', '--window-before-ms', 500, '--hold-ms', $case.hold,
      '--delay-ms', $case.delay, '--iterations', $case.iterations, '--concurrency', $case.concurrency,
      '--benchmark-round', $case.round, '--seconds', 35)
    if ($case.sequential) { $arguments += '--sequential' }
    if ($case.concurrency -gt 0) { $arguments += '--synchronized-start' }
    if ($case.leak) { $arguments += @('--expect-leak', '--send-rst') }
    python @arguments
    if ($LASTEXITCODE) { $failures.Add($case.name) }
  }
} finally {
  python "$PSScriptRoot\routing_results.py" --root $OutDir --out (Join-Path $OutDir 'aggregate-evidence.json')
  if ($LASTEXITCODE) { $failures.Add('aggregate-evidence') }
  @{
    failed_cases = @($failures)
    controlled_routing = 'Selected app proxy; other app direct; exact CONNECT and echo verification'
    fault_control = 'Selected ownership deliberately delayed beyond hold; direct leak and checked reset'
    synchronized_bursts = $true
    driver_queue_loss_observable = $false
    qualification = 'Fresh controlled tuples only; no general lifecycle, zero-leak or production guarantee'
  } | ConvertTo-Json | Set-Content (Join-Path $OutDir 'ci-summary.json')
}
if ($failures.Count) { throw "Routing experiment cases failed: $($failures -join ', ')" }
