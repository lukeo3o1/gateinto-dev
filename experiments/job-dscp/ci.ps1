param(
  [string] $Bin = "$env:RUNNER_TEMP\job-dscp-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\job-dscp-results"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Restrict-Directory([string] $Path, [string] $Sid) {
  New-Item -ItemType Directory -Force $Path | Out-Null
  & icacls $Path /inheritance:r /grant:r "*${Sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE) { throw 'Could not restrict directory ACL' }
  return (Resolve-Path $Path).Path
}

function Invoke-Quiet([string[]] $Arguments) {
  $rest = @($Arguments | Select-Object -Skip 1)
  try {
    & $Arguments[0] @rest *> $null
  } catch {
    Write-Host "Cleanup step failed: $($Arguments -join ' ')"
  }
}

$failures = [System.Collections.Generic.List[string]]::new()
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$OutDir = Restrict-Directory $OutDir $identity.User.Value
$privateDir = Restrict-Directory (Join-Path (Split-Path $OutDir -Parent) 'job-dscp-private') $identity.User.Value
$aggregatePath = Join-Path $OutDir 'aggregate-evidence.json'
$summaryPath = Join-Path $OutDir 'ci-summary.json'
$environmentPath = Join-Path $OutDir 'environment.json'
$markdownPath = Join-Path $OutDir 'summary.md'
foreach ($path in @($aggregatePath, $summaryPath, $environmentPath, $markdownPath)) {
  if (Test-Path $path) { Remove-Item $path -Force }
}
$policyName = "gateinto-job-dscp-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$policyCreated = $false
$qosStatus = 'unavailable'
$qosReason = ''

try {
  if (-not ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $qosReason = 'not_elevated'
    throw 'The job DSCP probe requires an elevated administrator'
  }
  python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
  if ($LASTEXITCODE) { throw 'Python unit tests failed' }
  & "$Bin\probe.exe" self-test
  if ($LASTEXITCODE) { throw 'Native self-test failed' }

  if (Get-Command New-NetQosPolicy -ErrorAction SilentlyContinue) {
    try {
      New-NetQosPolicy -Name $policyName -AppPathNameMatchCondition 'probe-qos.exe' -DSCPAction 30 `
        -NetworkProfile All -PolicyStore ActiveStore | Out-Null
      $policyCreated = $true
      $qosStatus = 'created'
    } catch {
      $qosStatus = 'failed'
      $qosReason = 'create_failed'
      Write-Host "QoS policy creation failed: $($_.Exception.GetType().Name)"
    }
  } else {
    $qosReason = 'cmdlet_missing'
  }
  Write-Host "QoS control policy: $qosStatus $qosReason"

  python "$PSScriptRoot\harness.py" --bin $Bin --results $OutDir --private $privateDir `
    --qos-policy-status $qosStatus --qos-policy-reason $qosReason
  if ($LASTEXITCODE) { $failures.Add('harness') }
} catch {
  $failures.Add('setup')
  Write-Host "Harness failure: $($_.Exception.Message)"
} finally {
  if ($policyCreated) {
    try {
      Remove-NetQosPolicy -Name $policyName -PolicyStore ActiveStore -Confirm:$false
    } catch {
      $failures.Add('qos-policy-cleanup')
      Write-Host 'QoS policy removal failed'
    }
  }
  if (Get-Command pktmon -ErrorAction SilentlyContinue) {
    Invoke-Quiet @('pktmon', 'stop')
    Invoke-Quiet @('pktmon', 'filter', 'remove')
  }
  Get-Process -Name 'probe', 'probe-qos' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

  if (-not (Test-Path $aggregatePath)) {
    $failures.Add('aggregate-missing')
    @{ schema = 'job-dscp-v1'; harness_failed = $true } | ConvertTo-Json | Set-Content $aggregatePath
  } else {
    try {
      Get-Content -Raw $aggregatePath | ConvertFrom-Json | Out-Null
    } catch {
      $failures.Add('aggregate-invalid')
    }
  }
  if (-not (Test-Path $environmentPath)) {
    @{ schema = 'job-dscp-v1'; image = $env:ImageOS; image_version = $env:ImageVersion } | ConvertTo-Json |
      Set-Content $environmentPath
  }
  $summary = $null
  if (Test-Path $summaryPath) {
    try { $summary = Get-Content -Raw $summaryPath | ConvertFrom-Json } catch { $summary = $null }
  }
  if ($null -eq $summary) {
    $summary = [pscustomobject]@{ schema = 'job-dscp-v1'; harness_ok = $false; capture_only = $true }
  }
  if ($failures.Count) {
    $summary | Add-Member -NotePropertyName harness_ok -NotePropertyValue $false -Force
  }
  $summary | Add-Member -NotePropertyName failed_steps -NotePropertyValue @($failures) -Force
  $summary | ConvertTo-Json | Set-Content $summaryPath

  Write-Host '=== JOB-DSCP AGGREGATE BEGIN ==='
  Write-Host (Get-Content -Raw $aggregatePath)
  Write-Host '=== JOB-DSCP AGGREGATE END ==='
  if ($env:GITHUB_STEP_SUMMARY) {
    if (Test-Path $markdownPath) {
      Get-Content -Raw $markdownPath | Add-Content $env:GITHUB_STEP_SUMMARY
    } else {
      "### Job DSCP probe`n`nNo verdicts: the harness failed before writing results.`n" | Add-Content $env:GITHUB_STEP_SUMMARY
    }
    if ($failures.Count) {
      "`nHarness failures: $($failures -join ', ')`n" | Add-Content $env:GITHUB_STEP_SUMMARY
    }
  }
}
if ($failures.Count) { throw "Job DSCP harness failures: $($failures -join ', ')" }
