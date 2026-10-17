param(
  [Parameter(Mandatory)] [string] $Path,
  [string] $Dumpbin
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Path not found" }

if (-not $Dumpbin) {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $Dumpbin = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
  if (-not $Dumpbin) { throw 'dumpbin.exe not found' }
}

$output = & $Dumpbin /nologo /dependents $Path
if ($LASTEXITCODE -ne 0) { throw "dumpbin exited with $LASTEXITCODE" }

$dependencies = @($output | Where-Object { $_ -match '^\s+\S+\.dll\s*$' } | ForEach-Object { $_.Trim() })
"Dependencies of ${Path}:"
$dependencies | ForEach-Object { "  $_" }

if (-not ($dependencies -contains 'KERNEL32.dll')) { throw 'dumpbin output lists no KERNEL32.dll; cannot trust the dependency list' }

$crt = @($dependencies | Where-Object { $_ -match '^(vcruntime\d.*|msvcp\d.*|msvcr\d.*|concrt\d.*|vcomp\d.*|vccorlib\d.*|ucrtbase.*|api-ms-win-crt-.*)\.dll$' })
if ($crt) { throw "$Path links the C runtime dynamically: $($crt -join ', ')" }
