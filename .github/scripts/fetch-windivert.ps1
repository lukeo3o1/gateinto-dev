#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('x64', 'x86')] [string] $Arch,
    [Parameter(Mandatory)] [string] $Output
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$verify = Join-Path $PSScriptRoot '..\..\packaging\wix\windivert.ps1'
$pinned = & $verify -Arch $Arch
$work = (New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))).FullName
try {
    $zip = Join-Path $work $pinned.Archive.Name
    Invoke-WebRequest -Uri $pinned.Archive.Source -OutFile $zip -MaximumRetryCount 3 -RetryIntervalSec 5
    $null = & $verify -Arch $Arch -Archive $zip
    $Output = (New-Item -ItemType Directory -Path $Output).FullName
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($file in $pinned.Files) {
            $entry = $archive.GetEntry($file.Source)
            if ($null -eq $entry) { throw "$($pinned.Archive.Name) has no $($file.Source)" }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Output $file.Name))
        }
    } finally {
        $archive.Dispose()
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
$null = & $verify -Arch $Arch -Directory $Output

"fetched and verified $($pinned.Files.Count) WinDivert files for $Arch"
