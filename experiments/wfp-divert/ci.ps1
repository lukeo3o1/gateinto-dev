param(
  [string] $Bin = "$env:RUNNER_TEMP\wfp-divert-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\wfp-divert-results",
  [string] $Fixture = 'target\release\examples\wfp_lab.exe'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
& icacls $OutDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict evidence directory ACL' }
$privateDir = Join-Path (Split-Path $OutDir -Parent) 'wfp-divert-private'
New-Item -ItemType Directory -Force $privateDir | Out-Null
& icacls $privateDir /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Could not restrict private manifest directory ACL' }
if (-not ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'The driver and audit experiment requires an elevated administrator'
}
@{
  os = [Environment]::OSVersion.VersionString
  image = $env:ImageOS
  image_version = $env:ImageVersion
  commit = $env:GITHUB_SHA
  topology = 'same-host-local; no remote destination or desktop Windows coverage'
  driver = 'official WinDivert v2.2.2 signed release'
  ownership = 'native WFP or Security 5156; never WinDivert SOCKET/FLOW'
} | ConvertTo-Json | Set-Content (Join-Path $OutDir 'environment.json')
$audit = Join-Path $OutDir 'audit-before.csv'
& auditpol /backup "/file:$audit"
if ($LASTEXITCODE) { throw 'Could not back up audit policy' }
$failures = [System.Collections.Generic.List[string]]::new()
try {
  & auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable
  if ($LASTEXITCODE) { throw 'Could not enable successful connection auditing' }
  & auditpol /get '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' |
    Set-Content (Join-Path $OutDir 'audit-effective.txt')
  & "$Bin\native-events.exe" --self-test
  if ($LASTEXITCODE) { throw 'Native collector helper tests failed' }
  python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
  if ($LASTEXITCODE) { throw 'Attribution model tests failed' }
  $cases = @(
    @{ name='hold-wfp-tcp'; source='wfp'; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false },
    @{ name='hold-security-tcp'; source='security5156'; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false },
    @{ name='hold-wfp-delayed'; source='wfp'; mode='hold'; protocol='tcp'; delay=100; hold=1000; skip=$false },
    @{ name='hold-wfp-missing'; source='wfp'; mode='hold'; protocol='tcp'; delay=0; hold=250; skip=$true },
    @{ name='hold-wfp-too-late'; source='wfp'; mode='hold'; protocol='tcp'; delay=1000; hold=250; skip=$false },
    @{ name='hold-wfp-udp'; source='wfp'; mode='hold'; protocol='udp'; delay=0; hold=1000; skip=$false },
    @{ name='hold-security-udp'; source='security5156'; mode='hold'; protocol='udp'; delay=0; hold=1000; skip=$false },
    @{ name='hold-security-udp-2000'; source='security5156'; mode='hold'; protocol='udp'; delay=0; hold=2000; skip=$false },
    @{ name='hold-security-delayed'; source='security5156'; mode='hold'; protocol='tcp'; delay=100; hold=2000; skip=$false },
    @{ name='hold-security-too-late'; source='security5156'; mode='hold'; protocol='tcp'; delay=1000; hold=250; skip=$false },
    @{ name='redirect-security-missing'; source='security5156'; mode='redirect'; protocol='tcp'; delay=0; hold=250; skip=$true },
    @{ name='redirect-wfp-missing'; source='wfp'; mode='redirect'; protocol='tcp'; delay=0; hold=250; skip=$true },
    @{ name='redirect-wfp'; source='wfp'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false },
    @{ name='redirect-security'; source='security5156'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false },
    @{ name='retransmit-security'; source='security5156'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false; scenario='retransmit' },
    @{ name='reuse-security'; source='security5156'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false; scenario='reuse' },
    @{ name='external-wfp-tcp'; source='wfp'; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false; external=$true },
    @{ name='external-security-tcp'; source='security5156'; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false; external=$true }
  )
  foreach ($api in @('subscribe4', 'poll')) {
    $cases += @(
      @{ name="hold-wfp-$api-tcp"; source='wfp'; api=$api; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false },
      @{ name="hold-wfp-$api-udp"; source='wfp'; api=$api; mode='hold'; protocol='udp'; delay=0; hold=1000; skip=$false },
      @{ name="hold-wfp-$api-delayed"; source='wfp'; api=$api; mode='hold'; protocol='tcp'; delay=100; hold=1000; skip=$false },
      @{ name="hold-wfp-$api-too-late"; source='wfp'; api=$api; mode='hold'; protocol='tcp'; delay=1000; hold=250; skip=$false },
      @{ name="hold-wfp-$api-missing"; source='wfp'; api=$api; mode='hold'; protocol='tcp'; delay=0; hold=250; skip=$true },
      @{ name="redirect-wfp-$api"; source='wfp'; api=$api; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false },
      @{ name="external-wfp-$api-tcp"; source='wfp'; api=$api; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false; external=$true }
    )
  }
  $cases += @(
    @{ name='retransmit-wfp-poll'; source='wfp'; api='poll'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false; scenario='retransmit' },
    @{ name='reuse-wfp-poll'; source='wfp'; api='poll'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false; scenario='reuse' },
    @{ name='hold-wfp-poll-tcp-repeat'; source='wfp'; api='poll'; mode='hold'; protocol='tcp'; delay=0; hold=1000; skip=$false },
    @{ name='redirect-wfp-poll-repeat'; source='wfp'; api='poll'; mode='redirect'; protocol='tcp'; delay=0; hold=1000; skip=$false }
  )
  foreach ($api in @('subscribe2', 'subscribe3', 'subscribe4')) {
    $cases += @{ name="hold-wfp-$api-drain"; source='wfp'; api=$api; mode='hold'; protocol='tcp';
                 delay=0; hold=2000; skip=$false; drain=1500 }
  }
  foreach ($case in $cases) {
    Write-Host "Running $($case.name)"
    $arguments = @("$PSScriptRoot\run.py", '--bin', $Bin, '--fixture', $Fixture,
      '--out', (Join-Path $OutDir $case.name), '--source', $case.source,
      '--private-dir', $privateDir,
      '--mode', $case.mode, '--protocol', $case.protocol,
      '--hold-ms', $case.hold, '--delay-ms', $case.delay, '--iterations', 3, '--seconds', 35)
    if ($case.skip) { $arguments += '--skip-all' }
    if ($case.ContainsKey('api')) { $arguments += @('--wfp-api', $case.api) }
    if ($case.ContainsKey('drain')) { $arguments += @('--callback-drain-ms', $case.drain) }
    if ($case.ContainsKey('scenario')) {
      $arguments += @('--scenario', $case.scenario)
      if ($case.scenario -eq 'reuse') { $arguments += @('--iterations', 1) }
    }
    if ($case.ContainsKey('external')) {
      try {
        $external = [System.Net.Dns]::GetHostAddresses('api.github.com') |
          Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
        if (-not $external) { throw 'No external IPv4 address resolved' }
        $arguments += @('--external-target', $external.IPAddressToString, '--external-port', 443, '--iterations', 1)
      } catch {
        $failures.Add($case.name + '-dns')
        Write-Host "External connect-only probe unavailable: $_"
        continue
      }
    }
    python @arguments
    if ($LASTEXITCODE) { $failures.Add($case.name) }
    $caseDir = Join-Path $OutDir $case.name
    foreach ($file in @('native.stdout.txt', 'packet.stdout.txt', 'restore.stdout.txt')) {
      $logPath = Join-Path $caseDir $file
      if (Test-Path $logPath) { Get-Content $logPath -Tail 12 }
    }
    $bridgeLog = Join-Path $caseDir 'bridge.jsonl'
    if (Test-Path $bridgeLog) { Get-Content $bridgeLog -Tail 20 | ForEach-Object { Write-Host "BRIDGE $($case.name) $_" } }
    $nativeLog = Join-Path $caseDir 'native.jsonl'
    if (Test-Path $nativeLog) {
      Get-Content $nativeLog | Where-Object { $_ -notmatch '"kind":"wfp_enum' -and $_ -match 'app-a.exe|app-b.exe|"kind":"error"|"kind":"wfp_poll_error"|"kind":"ready"|"kind":"summary"' } |
        Select-Object -First 30 | ForEach-Object { Write-Host "NATIVE $($case.name) $_" }
      Get-Content $nativeLog | Where-Object { $_ -match '"kind":"wfp_enum(5)?(_error|_summary)?"' } |
        Select-Object -First 100 | ForEach-Object { Write-Host "WFPENUM $($case.name) $_" }
    }
    $packetLog = Join-Path $caseDir 'packets.jsonl'
    if (Test-Path $packetLog) {
      Get-Content $packetLog | Select-Object -First 30 | ForEach-Object { Write-Host "PACKET $($case.name) $_" }
    }
  }
  $inprocCases = @(
    @{ name='hold-inproc-tcp'; mode='hold'; protocol='tcp' },
    @{ name='hold-inproc-udp'; mode='hold'; protocol='udp' },
    @{ name='redirect-inproc'; mode='redirect'; protocol='tcp' },
    @{ name='hold-inproc-tcp-repeat'; mode='hold'; protocol='tcp' },
    @{ name='redirect-inproc-repeat'; mode='redirect'; protocol='tcp' },
    @{ name='leakcheck-inproc'; mode='redirect'; protocol='tcp'; hold=100; delay=250; rst=$true; leak=$true },
    @{ name='concurrency-inproc'; mode='redirect'; protocol='tcp'; concurrency=50 },
    @{ name='quic-inproc'; mode='redirect'; protocol='udp'; quic=$true },
    @{ name='concurrency-inproc-cacheoff'; mode='redirect'; protocol='tcp'; concurrency=50; cache='off' },
    @{ name='hold-inproc-async-tcp'; mode='hold'; protocol='tcp'; lookup='async' },
    @{ name='hold-inproc-async-udp'; mode='hold'; protocol='udp'; lookup='async' },
    @{ name='redirect-inproc-async'; mode='redirect'; protocol='tcp'; lookup='async' },
    @{ name='redirect-inproc-async-repeat'; mode='redirect'; protocol='tcp'; lookup='async' },
    @{ name='concurrency-inproc-async'; mode='redirect'; protocol='tcp'; concurrency=50; lookup='async' },
    @{ name='leakcheck-inproc-async'; mode='redirect'; protocol='tcp'; hold=100; delay=250; rst=$true; leak=$true; lookup='async' },
    @{ name='quic-inproc-async'; mode='redirect'; protocol='udp'; quic=$true; lookup='async' },
    @{ name='ale-probe-inproc-tcp'; mode='hold'; protocol='tcp'; lookup='async'; ale=$true },
    @{ name='ale-probe-inproc-udp'; mode='hold'; protocol='udp'; lookup='async'; ale=$true }
  )
  foreach ($case in $inprocCases) {
    Write-Host "Running $($case.name)"
    $arguments = @("$PSScriptRoot\run.py", '--bin', $Bin, '--fixture', $Fixture,
      '--out', (Join-Path $OutDir $case.name), '--engine', 'inproc', '--private-dir', $privateDir,
      '--mode', $case.mode, '--protocol', $case.protocol,
      '--hold-ms', ($case.ContainsKey('hold') ? $case.hold : 1000), '--seconds', 35)
    if ($case.ContainsKey('concurrency')) { $arguments += @('--concurrency', $case.concurrency) }
    if ($case.ContainsKey('quic')) { $arguments += '--quic' }
    if ($case.ContainsKey('rst')) { $arguments += '--send-rst' }
    if ($case.ContainsKey('delay')) { $arguments += @('--delay-ms', $case.delay) }
    if ($case.ContainsKey('leak')) { $arguments += '--expect-leak' }
    if ($case.ContainsKey('lookup')) { $arguments += @('--lookup-mode', $case.lookup) }
    if ($case.ContainsKey('cache')) { $arguments += @('--filter-cache', $case.cache) }
    if ($case.ContainsKey('ale')) { $arguments += '--ale-probe' }
    python @arguments
    if ($LASTEXITCODE) { $failures.Add($case.name) }
    $caseDir = Join-Path $OutDir $case.name
    foreach ($file in @('inproc.stdout.txt')) {
      $logPath = Join-Path $caseDir $file
      if (Test-Path $logPath) { Get-Content $logPath -Tail 12 }
    }
    $engineSummary = Join-Path $caseDir 'engine-summary.json'
    if (Test-Path $engineSummary) { Get-Content $engineSummary | ForEach-Object { Write-Host "ENGINE $($case.name) $_" } }
    $aleLog = Join-Path $caseDir 'ale-endpoints.jsonl'
    if (Test-Path $aleLog) {
      Get-Content $aleLog | Select-Object -Last 20 | ForEach-Object { Write-Host "ALE $($case.name) $_" }
    }
    $packetLog = Join-Path $caseDir 'packets.jsonl'
    if (Test-Path $packetLog) {
      Get-Content $packetLog | Where-Object { $_ -match '"kind":"(ready|ownership|enum_filter_fallback|decision|translation|rst|leaked|error|summary|complete)"' } |
        Select-Object -First 256 | ForEach-Object { Write-Host "PACKET $($case.name) $_" }
    }
    $bridgeLog = Join-Path $caseDir 'bridge.jsonl'
    if (Test-Path $bridgeLog) { Get-Content $bridgeLog -Tail 20 | ForEach-Object { Write-Host "BRIDGE $($case.name) $_" } }
  }
} finally {
  & auditpol /restore "/file:$audit"
  if ($LASTEXITCODE) { $failures.Add('audit-policy-restore') }
  Get-ChildItem $OutDir -Recurse -Filter 'private-manifest.json' | Remove-Item -Force
  @{ failed_cases = @($failures); windows_desktop = 'NOT RUN'; remote_topology = 'NOT RUN';
     udp_forwarding = 'NOT IMPLEMENTED'; external_retransmit_reuse_stress = 'NOT RUN';
     inproc_engine = 'RUN (hold, redirect, repeats, leak-check, concurrency stress, QUIC drop)' } |
    ConvertTo-Json | Set-Content (Join-Path $OutDir 'ci-summary.json')
}
if ($failures.Count) { throw "PoC cases failed: $($failures -join ', ')" }
