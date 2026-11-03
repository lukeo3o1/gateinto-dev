param(
  [Parameter(Mandatory)] [string] $Path,
  [Parameter(Mandatory)] [string] $Imports,
  [string[]] $AllowList = @(Join-Path $PSScriptRoot 'win7-imports.txt')
)

$ErrorActionPreference = 'Stop'

$allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in Get-Content -LiteralPath $AllowList) {
  if ($entry.Trim()) { [void]$allowed.Add(($entry.Trim() -split '\s+') -join ' ') }
}

$found = [System.Collections.Generic.List[string]]::new()
$dll = $null
$inImports = $false
foreach ($line in Get-Content -LiteralPath $Imports) {
  if ($line -match '^\s+Section contains the following delay load imports:') { throw 'Delay-load imports are not audited' }
  if ($line -match '^\s+Section contains the following imports:') { $inImports = $true; continue }
  if ($line -match '^\s+Summary\s*$') { $inImports = $false; continue }
  if (-not $inImports) { continue }
  if ($line -match '^\s{4}(\S+\.dll)\s*$') { $dll = $Matches[1].ToLowerInvariant(); continue }
  if (-not $dll) { continue }
  if ($line -match '^\s+[0-9A-Fa-f]+\s+(\S+)\s*$') { $found.Add("$dll $($Matches[1])") }
  elseif ($line -match '^\s+Ordinal\s+(\d+)\s*$') { $found.Add("$dll #$($Matches[1])") }
}
$found = @($found | Sort-Object -Unique)
if (-not ($found | Where-Object { $_ -like 'kernel32.dll *' })) { throw "No kernel32.dll imports parsed from $Imports; cannot trust the import list" }

Write-Output "== Static imports of ${Path}: $($found.Count)"
$found | ForEach-Object { $_.Split(' ')[0] } | Sort-Object -Unique | ForEach-Object { "  $_" }

$win8 = 'ProcessPrng|GetSystemTimePreciseAsFileTime|WaitOnAddress|WakeByAddressSingle|WakeByAddressAll|CreateFile2|GetCurrentThreadStackLimits|SetThreadDescription|GetThreadDescription|GetTempPath2W|Tbsi_GetDeviceInfo|BCryptHash|bcryptprimitives|api-ms-win-core-synch-l1-2-0|SetProcessDpiAwarenessContext|GetDpiForWindow|GetDpiForMonitor|GetSystemMetricsForDpi|AdjustWindowRectExForDpi'
$text = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Path))
$strings = @([regex]::Matches($text, "($win8)") | ForEach-Object { $_.Value } | Sort-Object -Unique)
Write-Output '== Names of Windows 8+ APIs present as strings in the binary (possible GetProcAddress lookups)'
$strings | ForEach-Object { "  $_" }

$unknown = @($found | Where-Object { -not $allowed.Contains($_) })
Write-Output "== Static imports not in the Windows 7 allow-lists $($AllowList -join ', ')"
$unknown | ForEach-Object { "  $_" }

$failed = $false
foreach ($import in $unknown) {
  Write-Output "::error title=Import not known to exist on Windows 7::$import is not in the Windows 7 allow-list. Check its minimum supported client; add it to the allow-list only if it exists on Windows 7 SP1, otherwise resolve it at runtime."
  $failed = $true
}
if ($strings -contains 'ProcessPrng') {
  Write-Output '::error title=ProcessPrng found::AWS-LC loads ProcessPrng from bcryptprimitives.dll at runtime and calls abort() when it is missing, so this binary would abort on Windows 7. Build AWS-LC with the cc builder, which defines _WIN32_WINNT=0x0601 for -win7-windows- targets.'
  $failed = $true
}
if ($failed) { throw "$Path would not run on Windows 7" }
