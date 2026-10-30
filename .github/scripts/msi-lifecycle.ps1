param(
  [Parameter(Mandatory)] [string] $Msi,
  [Parameter(Mandatory)] [string] $Exe,
  [Parameter(Mandatory)] [string] $LogDir
)

$ErrorActionPreference = 'Stop'

$Msi = (Resolve-Path -LiteralPath $Msi).Path
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$outside = Join-Path $LogDir 'gateinto-outside.exe'
Copy-Item -LiteralPath $Exe -Destination $outside
$installDir = "$env:LOCALAPPDATA\Programs\Gateinto"
$installed = "$installDir\gateinto.exe"
$installedGui = "$installDir\gateinto-gui.exe"
$shortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Gateinto.lnk"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$approvedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$guiValue = 'Gateinto App'
$probe = 'Gateinto Lifecycle Probe'
$probeData = '"C:\gateinto-lifecycle-probe.exe"'
$approvedOn = [byte[]] (2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
$script:spki = $null
$script:written = @()
$script:guis = @()

Add-Type -Namespace Lifecycle -Name Win32 -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern IntPtr FindWindowW(string className, IntPtr windowName);
'@

function Step([string] $Name, [scriptblock] $Body) {
  "::group::$Name"
  try { & $Body } finally { '::endgroup::' }
}

function Invoke-Msiexec([string] $Action, [string] $LogName, [string[]] $Properties = @()) {
  $log = Join-Path $LogDir $LogName
  $arguments = @($Action, "`"$Msi`"", '/qn', '/norestart') + $Properties + @('/l*v', "`"$log`"")
  $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $arguments
  if ($process.ExitCode -ne 0) { Get-Content $log -Tail 200 | Out-Host; throw "msiexec $Action exited with $($process.ExitCode) (3010 means a restart was needed)" }
  $log
}

function Assert-GuiInstalled {
  if (-not (Test-Path $installedGui)) { throw "$installedGui is missing" }
  if (-not (Test-Path $shortcut)) { throw "the Start Menu shortcut $shortcut is missing" }
  $target = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut).TargetPath
  "shortcut target: $target"
  if ($target -ne $installedGui) { throw "the Start Menu shortcut points to '$target', expected '$installedGui'" }
  if ($null -ne (Get-ItemProperty $runKey -Name 'Gateinto App' -ErrorAction SilentlyContinue)) {
    throw 'the installer created the GUI sign-in value Gateinto App'
  }
  $running = @(Get-Process -Name gateinto, gateinto-gui -ErrorAction SilentlyContinue)
  if ($running) { throw "the installer started $(($running | ForEach-Object { $_.Name }) -join ', ')" }
}

function Assert-GuiRemoved {
  if (Test-Path $installedGui) { throw "$installedGui still exists after uninstall" }
  if (Test-Path $shortcut) { throw "the Start Menu shortcut $shortcut still exists after uninstall" }
}

function Get-Value([string] $Key, [string] $Name) {
  $item = Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $item) { $null } else { $item.$Name }
}

function Set-Value([string] $Key, [string] $Name, $Value, [string] $Type) {
  if (-not (Test-Path -LiteralPath $Key)) { New-Item -Path $Key -Force | Out-Null }
  New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
  $script:written += , @($Key, $Name)
}

function Remove-Value([string] $Key, [string] $Name) {
  Remove-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue
}

function Same-Bytes($Actual, [byte[]] $Expected) {
  ($null -ne $Actual) -and (($Actual -join ',') -eq ($Expected -join ','))
}

function Start-Gui {
  $gui = Start-Process $installedGui -PassThru
  $script:guis += $gui
  $deadline = (Get-Date).AddSeconds(30)
  while ([Lifecycle.Win32]::FindWindowW('GateintoWindow', [IntPtr]::Zero) -eq [IntPtr]::Zero) {
    if ($gui.HasExited) { throw "the GUI exited with $($gui.ExitCode) before showing its window" }
    if ((Get-Date) -gt $deadline) {
      Stop-Process -Id $gui.Id -Force -ErrorAction SilentlyContinue
      Write-Host '::warning::the GUI showed no GateintoWindow within 30 seconds (no interactive desktop?); closing it on uninstall is not checked'
      return $null
    }
    Start-Sleep -Milliseconds 250
  }
  Write-Host "GUI window shown by process $($gui.Id)"
  $gui
}

function Test-UserPathHasInstallDir {
  $userPath = (Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).Path
  [bool] ($userPath -split ';' | Where-Object { $_.TrimEnd('\') -eq $installDir })
}

$touched = @(@($runKey, $guiValue), @($runKey, $probe), @($approvedKey, $guiValue), @($approvedKey, 'Gateinto'))
foreach ($value in $touched) {
  if ($null -ne (Get-Value $value[0] $value[1])) { throw "$($value[0]) already has a value '$($value[1])'; remove it before running this script" }
}

try {
  Step 'Install silently per user' {
    $null = Invoke-Msiexec '/i' 'install-1.log'
  }

  Step 'Check the exe, the GUI and its shortcut, PATH, the gateinto:// handler, the uninstall entry, that nothing was started and that no key was created' {
    if (-not (Test-Path $installed)) { throw "$installed is missing" }
    Assert-GuiInstalled
    "user PATH: $((Get-ItemProperty 'HKCU:\Environment').Path)"
    if (-not (Test-UserPathHasInstallDir)) { throw "the user PATH does not contain $installDir" }
    $command = (Get-ItemProperty 'HKCU:\Software\Classes\gateinto\shell\open\command').'(default)'
    $expected = "`"$installed`" open -- `"%1`""
    "handler: $command"
    if ($command -ne $expected) { throw "the handler command is '$command', expected '$expected'" }
    $scheme = Get-ItemProperty 'HKCU:\Software\Classes\gateinto'
    if ($null -eq $scheme.'URL Protocol') { throw 'HKCU\Software\Classes\gateinto has no URL Protocol value' }
    if ($null -ne (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Gateinto -ErrorAction SilentlyContinue)) {
      throw 'the autostart entry exists although AUTOSTART was not set'
    }
    $uninstall = Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
      Get-ItemProperty | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'Gateinto' }
    if (-not $uninstall) { throw 'no uninstall entry with DisplayName Gateinto' }
    $uninstall | Select-Object PSPath, DisplayName, DisplayVersion, UninstallString | Format-List | Out-String
    $stderrFile = Join-Path $LogDir 'key-info-before-setup.err'
    & $installed key info 2> $stderrFile
    $code = $LASTEXITCODE
    $keyInfoError = Get-Content -Raw $stderrFile
    "key info stderr: $keyInfoError"
    if ($code -eq 0) { throw 'a device key exists right after installing; the installer must not create one' }
    if ($keyInfoError -notmatch 'no device key named') { throw 'key info failed for another reason than a missing device key' }
  }

  Step 'gateinto setup (Microsoft Software Key Storage Provider, not a TPM)' {
    $out = & $installed setup --backend software | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto setup exited with $LASTEXITCODE" }
    $out
    if ($out -notmatch '(?m)^device-key: created\r?$') { throw 'the first setup did not create the key' }
    if ($out -notmatch '(?m)^provider: Microsoft Software Key Storage Provider\r?$') { throw 'setup did not use the Software KSP' }
    $handler = [regex]::Escape("`"$installed`" open -- `"%1`"")
    if ($out -notmatch "(?m)^uri-handler: gateinto: $handler\r?$") { throw 'setup did not report the installed handler' }
    if ($out -match '(?m)^spki-sha256: ([0-9a-f]{64})\r?$') { $script:spki = $Matches[1] } else { throw 'setup printed no spki-sha256' }
    $status = & $installed status | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto status exited with $LASTEXITCODE" }
    $status
    if ($status -notmatch "(?m)^spki-sha256: $script:spki\r?$") { throw 'status did not report the key from setup' }
  }

  Step 'Uninstall while the agent runs, then check what is removed and what is kept' {
    $agent = Start-Process $installed -ArgumentList 'agent' -PassThru -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(30)
    while ((& $installed status | Out-String) -notmatch '(?m)^agent: running\r?$') {
      if ((Get-Date) -gt $deadline) { throw 'the agent did not start within 30 seconds' }
      Start-Sleep -Milliseconds 250
    }
    $gui = Start-Gui
    Set-Value $runKey $guiValue "`"$installedGui`"" String
    Set-Value $approvedKey $guiValue $approvedOn Binary
    Set-Value $runKey $probe $probeData String
    $log = Invoke-Msiexec '/x' 'uninstall-1.log' @('MSIRESTARTMANAGERCONTROL=Disable')
    if (-not (Select-String -Path $log -SimpleMatch -Quiet 'Doing action: StopAgent')) { throw 'the uninstall log has no StopAgent action' }
    if (-not (Select-String -Path $log -SimpleMatch -Quiet 'Doing action: UninstallGui')) { throw 'the uninstall log has no UninstallGui action' }
    if (Select-String -Path $log -SimpleMatch -Quiet 'Doing action: QuitGui') { throw 'a plain uninstall ran QuitGui' }
    if (-not $agent.WaitForExit(30000)) { Stop-Process -Id $agent.Id -Force; throw 'the uninstaller did not stop the agent' }
    if ($gui -and -not $gui.WaitForExit(1000)) { Stop-Process -Id $gui.Id -Force; throw 'the uninstaller did not close the GUI' }
    if ($null -ne (Get-Value $runKey $guiValue)) { throw "the $guiValue Run value still exists after uninstall" }
    if ($null -ne (Get-Value $approvedKey $guiValue)) { throw "the $guiValue StartupApproved value still exists after uninstall" }
    if ((Get-Value $runKey $probe) -ne $probeData) { throw "the uninstaller changed the unrelated Run value $probe" }
    if (Test-Path $installed) { throw "$installed still exists after uninstall" }
    Assert-GuiRemoved
    if (Test-Path 'HKCU:\Software\Classes\gateinto') { throw 'the gateinto:// handler still exists after uninstall' }
    if (Test-UserPathHasInstallDir) { throw "the user PATH still contains $installDir" }
    $out = & $outside key info | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto key info exited with $LASTEXITCODE after uninstall" }
    $out
    if ($out -notmatch "(?m)^spki-sha256: $script:spki\r?$") { throw 'the device key changed or vanished after uninstall' }
  }

  Step 'Reinstall with AUTOSTART=1 and set up again (Software KSP)' {
    $null = Invoke-Msiexec '/i' 'install-2.log' @('AUTOSTART=1')
    Assert-GuiInstalled
    $run = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Gateinto -ErrorAction SilentlyContinue).Gateinto
    $expected = "`"$installed`" agent --detach"
    "autostart: $run"
    if ($run -ne $expected) { throw "the autostart entry is '$run', expected '$expected'" }
    $out = & $installed setup --backend software | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto setup exited with $LASTEXITCODE" }
    $out
    if ($out -notmatch '(?m)^device-key: reused\r?$') { throw 'setup after reinstall did not reuse the key' }
    if ($out -notmatch "(?m)^spki-sha256: $script:spki\r?$") { throw 'setup after reinstall reported another SPKI' }
  }

  Step 'Purge the device identity, then setup creates a new one (Software KSP)' {
    $prefix = $script:spki.Substring(0, 16)
    $wrong = if ($prefix.StartsWith('0')) { '1' * 16 } else { '0' * 16 }
    & $installed reset --purge-device-identity --confirm-spki $wrong
    if ($LASTEXITCODE -eq 0) { throw 'reset accepted a wrong SPKI prefix' }
    '' | & $installed reset --purge-device-identity
    if ($LASTEXITCODE -eq 0) { throw 'reset without a terminal or --confirm-spki succeeded' }
    $out = & $installed key info | Out-String
    if ($out -notmatch "(?m)^spki-sha256: $script:spki\r?$") { throw 'a refused reset changed the key' }

    $out = & $installed reset --purge-device-identity --confirm-spki $prefix | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto reset exited with $LASTEXITCODE" }
    $out
    & $installed key info
    if ($LASTEXITCODE -eq 0) { throw 'the device key still exists after reset' }
    $status = & $installed status | Out-String
    $status
    if ($status -notmatch '(?m)^device-key: absent') { throw 'status did not report the key as absent' }
    if ($status -notmatch '(?m)^uri-handler: gateinto: ') { throw 'reset removed the gateinto:// handler' }

    $out = & $installed setup --backend software | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto setup exited with $LASTEXITCODE" }
    $out
    if ($out -notmatch '(?m)^device-key: created\r?$') { throw 'setup after reset did not create a key' }
    if ($out -match '(?m)^spki-sha256: ([0-9a-f]{64})\r?$') { $new = $Matches[1] } else { throw 'setup printed no spki-sha256' }
    if ($new -eq $script:spki) { throw 'setup after reset reported the purged SPKI' }
    $script:spki = $new
  }

  Step 'Uninstall the AUTOSTART install and check that the autostart entry, the GUI and its shortcut are gone and values the GUI did not write are kept' {
    $elsewhere = "`"$LogDir\gateinto-gui.exe`""
    Set-Value $runKey $guiValue $elsewhere String
    Set-Value $approvedKey $guiValue $approvedOn Binary
    Set-Value $approvedKey 'Gateinto' $approvedOn Binary
    $null = Invoke-Msiexec '/x' 'uninstall-2.log'
    if ($null -ne (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Gateinto -ErrorAction SilentlyContinue)) {
      throw 'the autostart entry still exists after uninstall'
    }
    if ((Get-Value $runKey $guiValue) -ne $elsewhere) { throw "the uninstaller removed a $guiValue Run value that points at another copy" }
    if (-not (Same-Bytes (Get-Value $approvedKey $guiValue) $approvedOn)) { throw "the uninstaller changed the $guiValue StartupApproved value of another copy" }
    if (-not (Same-Bytes (Get-Value $approvedKey 'Gateinto') $approvedOn)) { throw 'the uninstaller changed the StartupApproved value of the agent autostart entry' }
    if ((Get-Value $runKey $probe) -ne $probeData) { throw "the uninstaller changed the unrelated Run value $probe" }
    if (Test-Path $installed) { throw "$installed still exists after uninstall" }
    Assert-GuiRemoved
  }
} finally {
  Step 'Clean up the key, the test values and the installation' {
    $script:guis | Where-Object { -not $_.HasExited } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    foreach ($value in $script:written) { Remove-Value $value[0] $value[1] }
    if ($script:spki -and (Test-Path $outside)) {
      & $outside reset --purge-device-identity --confirm-spki $script:spki
    }
    Start-Process msiexec.exe -Wait -ArgumentList '/x', "`"$Msi`"", '/qn', '/norestart'
  }
}

exit 0
