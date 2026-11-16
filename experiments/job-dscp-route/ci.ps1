param(
  [string] $Bin = "$env:RUNNER_TEMP\job-dscp-route-bin",
  [string] $OutDir = "$env:RUNNER_TEMP\job-dscp-route-results",
  [string] $Lab = (Join-Path $PSScriptRoot '..\..\target\release\examples\wfp_lab.exe')
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
    Write-Host "Cleanup step failed: $($Arguments[0])"
  }
}

function Remove-QosPolicies {
  if (-not (Get-Command Get-NetQosPolicy -ErrorAction SilentlyContinue)) { return 0 }
  $policies = @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'gateinto-job-dscp-route-qos*' })
  foreach ($policy in $policies) {
    try {
      Remove-NetQosPolicy -Name $policy.Name -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
    } catch {
      Write-Host "QoS policy removal failed: $($_.Exception.GetType().Name)"
    }
  }
  return @(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'gateinto-job-dscp-route-qos*' }).Count
}

$failures = [System.Collections.Generic.List[string]]::new()
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$privateDir = Join-Path (Split-Path $OutDir -Parent) 'job-dscp-route-private'
$aggregatePath = Join-Path $OutDir 'aggregate-evidence.json'
$summaryPath = Join-Path $OutDir 'ci-summary.json'
$environmentPath = Join-Path $OutDir 'environment.json'
$markdownPath = Join-Path $OutDir 'summary.md'
$policyName = "gateinto-job-dscp-route-qos-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$qosCurl = Join-Path $Bin 'curl-qos.exe'
$qosStatus = 'unavailable'
$qosReason = ''
$stage = 'directories'

try {
  Restrict-Directory $OutDir $identity.User.Value | Out-Null
  Restrict-Directory $privateDir $identity.User.Value | Out-Null
  foreach ($path in @($aggregatePath, $summaryPath, $environmentPath, $markdownPath)) {
    if (Test-Path $path) { Remove-Item $path -Force }
  }
  $stage = 'elevation'
  if (-not ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The job DSCP route experiment requires an elevated administrator'
  }
  $stage = 'unit-tests'
  python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v
  if ($LASTEXITCODE) { throw 'Python unit tests failed' }
  $stage = 'self-test'
  & "$Bin\route.exe" self-test
  if ($LASTEXITCODE) { throw 'Native self-test failed' }
  $stage = 'lab-binary'
  if (-not (Test-Path $Lab)) { throw 'Lab fixture binary missing' }
  $Lab = (Resolve-Path $Lab).Path

  $stage = 'qos-policy'
  $leftover = Remove-QosPolicies
  if ($leftover) {
    $qosStatus = 'failed'
    $qosReason = 'create_failed'
    Write-Host 'Leftover QoS policies could not be removed'
  }
  if (-not $qosReason) {
    try {
      Copy-Item (Join-Path $env:SystemRoot 'System32\curl.exe') $qosCurl -Force
    } catch {
      $qosStatus = 'failed'
      $qosReason = 'copy_failed'
      Write-Host "curl copy failed: $($_.Exception.GetType().Name)"
    }
  }
  if (-not $qosReason) {
    if (Get-Command New-NetQosPolicy -ErrorAction SilentlyContinue) {
      try {
        New-NetQosPolicy -Name $policyName -AppPathNameMatchCondition 'curl-qos.exe' -DSCPAction 46 `
          -NetworkProfile All -PolicyStore ActiveStore | Out-Null
        $qosStatus = 'created'
      } catch {
        $qosStatus = 'failed'
        $qosReason = 'create_failed'
        Write-Host "QoS policy creation failed: $($_.Exception.GetType().Name)"
      }
    } else {
      $qosReason = 'cmdlet_missing'
    }
  }
  Write-Host "QoS policy: $qosStatus $qosReason"

  $stage = 'harness'
  $harnessArgs = @('--bin', $Bin, '--lab', $Lab, '--results', $OutDir, '--private', $privateDir,
    '--qos-policy-status', $qosStatus, '--qos-curl', $qosCurl)
  if ($qosReason) { $harnessArgs += @('--qos-policy-reason', $qosReason) }
  python "$PSScriptRoot\harness.py" @harnessArgs
  if ($LASTEXITCODE) { $failures.Add('harness') }
} catch {
  $failures.Add($stage)
  Write-Host "Harness failure at stage ${stage}: $($_.Exception.GetType().Name)"
} finally {
  try { New-Item -ItemType Directory -Force $OutDir | Out-Null } catch { $failures.Add('results-directory') }
  Get-Process -Name 'route', 'wfp_lab', 'curl-qos' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  try {
    if ((Remove-QosPolicies) -ne 0) { $failures.Add('qos-policy-cleanup') }
  } catch {
    $failures.Add('qos-policy-cleanup')
  }
  Invoke-Quiet @('netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=gateinto-job-dscp-route-bridge')
  if (Get-Command pktmon -ErrorAction SilentlyContinue) {
    Invoke-Quiet @('pktmon', 'stop')
    Invoke-Quiet @('pktmon', 'filter', 'remove')
  }

  try {
    if (-not (Test-Path $aggregatePath)) {
      $failures.Add('aggregate-missing')
      @{ schema = 'job-dscp-route-v2'; harness_failed = $true } | ConvertTo-Json | Set-Content $aggregatePath
    } else {
      try {
        $parsed = Get-Content -Raw $aggregatePath | ConvertFrom-Json
        if (@($parsed.verdicts.PSObject.Properties | Where-Object { $_.Value -eq 'PENDING' }).Count) {
          $failures.Add('aggregate-pending')
        }
      } catch {
        $failures.Add('aggregate-invalid')
      }
    }
    if (-not (Test-Path $environmentPath)) {
      @{ schema = 'job-dscp-route-v2'; image = $env:ImageOS; image_version = $env:ImageVersion } | ConvertTo-Json |
        Set-Content $environmentPath
    }
    $summary = $null
    if (Test-Path $summaryPath) {
      try { $summary = Get-Content -Raw $summaryPath | ConvertFrom-Json } catch { $summary = $null }
    }
    if ($null -eq $summary) {
      $summary = [pscustomobject]@{ schema = 'job-dscp-route-v2'; harness_ok = $false }
    }
    if ($failures.Count) {
      $summary | Add-Member -NotePropertyName harness_ok -NotePropertyValue $false -Force
    }
    $summary | Add-Member -NotePropertyName failed_steps -NotePropertyValue @($failures) -Force
    $summary | ConvertTo-Json | Set-Content $summaryPath
  } catch {
    $failures.Add('results-write')
    Write-Host "Result writing failed: $($_.Exception.GetType().Name)"
  }

  $aggregateText = '{"schema":"job-dscp-route-v2","harness_failed":true}'
  try {
    if (Test-Path $aggregatePath) { $aggregateText = Get-Content -Raw $aggregatePath }
  } catch {
    $failures.Add('aggregate-read')
  }
  Write-Host '=== JOB-DSCP-ROUTE AGGREGATE BEGIN ==='
  Write-Host $aggregateText
  Write-Host '=== JOB-DSCP-ROUTE AGGREGATE END ==='
  if ($env:GITHUB_STEP_SUMMARY) {
    try {
      if (Test-Path $markdownPath) {
        Get-Content -Raw $markdownPath | Add-Content $env:GITHUB_STEP_SUMMARY
      } else {
        "### Job DSCP route`n`nNo verdict: the harness failed before writing results.`n" |
          Add-Content $env:GITHUB_STEP_SUMMARY
      }
      if ($failures.Count) {
        "`nHarness failures: $($failures -join ', ')`n" | Add-Content $env:GITHUB_STEP_SUMMARY
      }
    } catch {
      Write-Host "Step summary failed: $($_.Exception.GetType().Name)"
    }
  }
}
if ($failures.Count) {
  Write-Host "Job DSCP route harness failures: $($failures -join ', ')"
  exit 1
}
exit 0
