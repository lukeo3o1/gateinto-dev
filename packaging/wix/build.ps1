#Requires -Version 7
[CmdletBinding()]
param(
    [string] $Binary = (Join-Path $PSScriptRoot '..\..\target\release\gateinto.exe'),
    [string] $Output = (Join-Path $PSScriptRoot '..\..\target\wix\gateinto.msi')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$cargoToml = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\Cargo.toml')
if ($cargoToml -notmatch '(?m)^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
    throw 'Cargo.toml has no plain major.minor.patch package version'
}
$version = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

$binary = (Resolve-Path $Binary).Path
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null

wix build (Join-Path $PSScriptRoot 'gateinto.wxs') `
    -arch x64 `
    -d "Version=$version" `
    -d "BinaryPath=$binary" `
    -o $Output
if ($LASTEXITCODE -ne 0) { throw "wix build exited with $LASTEXITCODE" }

"built $Output (version $version)"
