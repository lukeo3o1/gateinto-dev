param([Parameter(Mandatory)] [string] $Path)

$ErrorActionPreference = 'Stop'

$file = Get-Item -LiteralPath $Path
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$($file.FullName).sha256", "$hash  $($file.Name)`n")
Get-Content -LiteralPath "$($file.FullName).sha256"
