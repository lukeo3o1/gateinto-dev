#Requires -Version 7
[CmdletBinding()]
param(
    [string] $Binary = (Join-Path $PSScriptRoot '..\..\target\release\gateinto.exe'),
    [string] $Output = (Join-Path $PSScriptRoot '..\..\target\wix\gateinto.msi'),
    [ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
    [ValidatePattern('^[0-9A-Za-z.+-]+$')] [string] $DisplayVersion,
    [ValidateSet('x64', 'x86')] [string] $Arch = 'x64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $Version) {
    $cargoToml = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\Cargo.toml')
    if ($cargoToml -notmatch '(?m)^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
        throw 'Cargo.toml has no plain major.minor.patch package version'
    }
    $Version = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
}
$name = if ($DisplayVersion) { "Gateinto $DisplayVersion" } else { 'Gateinto' }

$binary = (Resolve-Path $Binary).Path
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null

wix build (Join-Path $PSScriptRoot 'gateinto.wxs') `
    -arch $Arch `
    -d "Version=$Version" `
    -d "ProductName=$name" `
    -d "BinaryPath=$binary" `
    -o $Output
if ($LASTEXITCODE -ne 0) { throw "wix build exited with $LASTEXITCODE" }

"built $Output ($Arch, version $Version, name $name)"
