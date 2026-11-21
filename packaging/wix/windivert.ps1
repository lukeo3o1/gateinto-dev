#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('x64', 'x86')] [string] $Arch,
    [string] $Archive,
    [string] $Directory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$entries = foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'windivert.txt')) {
    $fields = $line.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($fields.Count -ne 4 -or $fields[3] -cnotmatch '^[0-9a-f]{64}$') { throw 'windivert.txt has a malformed line' }
    [pscustomobject] @{ Kind = $fields[0]; Source = $fields[1]; Name = $fields[2]; Sha256 = $fields[3] }
}
$release = @($entries | Where-Object Kind -CEQ 'archive')
$files = @($entries | Where-Object Kind -CEQ $Arch)
if ($release.Count -ne 1 -or $files.Count -eq 0) { throw "windivert.txt does not name one archive and the files for $Arch" }

function Assert-Pinned([string] $Path, [pscustomobject] $Pinned) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$($Pinned.Name) is missing" }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Pinned.Sha256) {
        throw "$($Pinned.Name) does not have the pinned SHA-256"
    }
}

if ($Archive) { Assert-Pinned $Archive $release[0] }
if ($Directory) {
    foreach ($file in $files) { Assert-Pinned (Join-Path $Directory $file.Name) $file }
    $unexpected = @(Get-ChildItem -LiteralPath $Directory -Force | Where-Object Name -NotIn $files.Name)
    if ($unexpected.Count -ne 0) { throw "the WinDivert directory holds $($unexpected.Count) entries not pinned for $Arch" }
}

[pscustomobject] @{ Archive = $release[0]; Files = $files }
