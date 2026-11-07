param([string] $OutDir = "$env:RUNNER_TEMP\wfp-divert-bin")
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$archive = Join-Path $OutDir 'WinDivert-2.2.2-A.zip'
Invoke-WebRequest 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $archive
Expand-Archive $archive -DestinationPath $OutDir -Force
$sdk = Join-Path $OutDir 'WinDivert-2.2.2-A'
$driver = Join-Path $sdk 'x64\WinDivert64.sys'
$signature = Get-AuthenticodeSignature $driver
if ($signature.Status -ne 'Valid') { throw "Official driver signature verification failed: $($signature.Status)" }
@{
  release = 'v2.2.2'
  archive_sha256 = (Get-FileHash $archive -Algorithm SHA256).Hash
  driver_sha256 = (Get-FileHash $driver -Algorithm SHA256).Hash
  signature_status = [string]$signature.Status
  signer = $signature.SignerCertificate.Subject
} | ConvertTo-Json | Set-Content (Join-Path $OutDir 'driver-manifest.json')
Copy-Item (Join-Path $sdk 'x64\WinDivert.dll'), $driver -Destination $OutDir -Force

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC x64 tools not found' }
Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'

$sources = $PSScriptRoot
Push-Location $OutDir
try {
  & cl /nologo /std:c++17 /EHsc /W4 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000006 /DUNICODE /D_UNICODE "$sources\native-events.cpp" /Fe:native-events.exe /link Fwpuclnt.lib Wevtapi.lib Ws2_32.lib Advapi32.lib
  if ($LASTEXITCODE) { throw 'Native collector compilation failed' }
  & cl /nologo /std:c++17 /EHsc /W4 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000006 "$sources\ale-endpoints.cpp" /Fe:ale-endpoints.exe /link Fwpuclnt.lib Ws2_32.lib
  if ($LASTEXITCODE) { throw 'ALE endpoint probe compilation failed' }
  & cl /nologo /std:c++17 /EHsc /W4 /D_WIN32_WINNT=0x0A00 "/I$sdk\include" "$sources\packets.cpp" /Fe:packets.exe /link "/LIBPATH:$sdk\x64" WinDivert.lib Ws2_32.lib
  if ($LASTEXITCODE) { throw 'Packet collector compilation failed' }
  & cl /nologo /std:c++17 /EHsc /W4 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000006 /DUNICODE /D_UNICODE "/I$sdk\include" "$sources\inproc.cpp" /Fe:inproc.exe /link "/LIBPATH:$sdk\x64" WinDivert.lib Fwpuclnt.lib Ws2_32.lib Advapi32.lib
  if ($LASTEXITCODE) { throw 'In-process engine compilation failed' }
  foreach ($name in @('app-a', 'app-b')) {
    & cl /nologo /std:c++17 /EHsc /W4 "$sources\client.cpp" "/Fe:$name.exe" /link Ws2_32.lib
    if ($LASTEXITCODE) { throw "Client compilation failed: $name" }
  }
} finally {
  Pop-Location
}
