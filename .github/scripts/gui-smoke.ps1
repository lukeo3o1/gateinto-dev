param(
  [Parameter(Mandatory)] [string] $Bin,
  [Parameter(Mandatory)] [string] $OutDir,
  [Parameter(Mandatory)] [string] $WorkDir,
  [int] $UpstreamPort = 18443,
  [int] $ListenPort = 18736
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class GuiSmoke {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left, Top, Right, Bottom; }

  delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);

  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder text, int max);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern uint GetDlgItemText(IntPtr hwnd, int id, StringBuilder text, int max);
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
  [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out RECT rect, int size);
  [DllImport("user32.dll")] static extern int GetSystemMetrics(int index);
  [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int command);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint msg, UIntPtr wp, IntPtr lp);

  public static IntPtr[] Windows(int pid) {
    var found = new List<IntPtr>();
    EnumWindows((hwnd, _) => {
      uint owner;
      GetWindowThreadProcessId(hwnd, out owner);
      if (owner == (uint)pid) found.Add(hwnd);
      return true;
    }, IntPtr.Zero);
    return found.ToArray();
  }

  public static string Title(IntPtr hwnd) {
    var text = new StringBuilder(512);
    GetWindowText(hwnd, text, text.Capacity);
    return text.ToString();
  }

  public static string Class(IntPtr hwnd) {
    var text = new StringBuilder(256);
    GetClassName(hwnd, text, text.Capacity);
    return text.ToString();
  }

  public static string MessageBoxText(IntPtr hwnd) {
    var text = new StringBuilder(2048);
    GetDlgItemText(hwnd, 0xffff, text, text.Capacity);
    return text.ToString();
  }

  public static RECT Bounds(IntPtr hwnd) {
    RECT rect;
    if (DwmGetWindowAttribute(hwnd, 9, out rect, Marshal.SizeOf(typeof(RECT))) != 0) GetWindowRect(hwnd, out rect);
    return rect;
  }

  public static RECT Screen() {
    int x = GetSystemMetrics(76), y = GetSystemMetrics(77);
    return new RECT { Left = x, Top = y, Right = x + GetSystemMetrics(78), Bottom = y + GetSystemMetrics(79) };
  }

  public static void Key(byte vk, bool up) {
    keybd_event(vk, 0, up ? 2u : 0u, UIntPtr.Zero);
  }

  public static int Colours(byte[] bgra, int cap) {
    var seen = new HashSet<int>();
    for (int i = 0; i + 3 < bgra.Length; i += 4) {
      seen.Add(bgra[i] | bgra[i + 1] << 8 | bgra[i + 2] << 16);
      if (seen.Count >= cap) break;
    }
    return seen.Count;
  }

  public static double Luma(byte[] bgra) {
    double sum = 0;
    long n = 0;
    for (int i = 0; i + 3 < bgra.Length; i += 4) {
      sum += 0.0722 * bgra[i] + 0.7152 * bgra[i + 1] + 0.2126 * bgra[i + 2];
      n++;
    }
    return n == 0 ? 0 : sum / n;
  }
}
'@

$null = [GuiSmoke]::SetProcessDPIAware()

$gateinto = Join-Path $Bin 'gateinto.exe'
$guiExe = Join-Path $Bin 'gateinto-gui.exe'
$upstreamExe = Join-Path $Bin 'examples\test_upstream.exe'
$configDir = Join-Path $env:APPDATA 'Gateinto'
$config = Join-Path $configDir 'gateinto.toml'
$themeKey = 'HKCU:\Software\Gateinto\App'
$pages = 'sessions', 'gateways', 'device', 'log', 'settings'
$flyoutTitles = @{ 'English' = 'Gateinto status'; 'zh-TW' = "Gateinto $([char] 0x72c0)$([char] 0x614b)" }
$VK_CONTROL = 0x11
$VK_TAB = 0x09
$VK_ESCAPE = 0x1b
$VK_MENU = 0x12
$WM_TRAY = 0x8001
$NIN_SELECT = 0x400
$WM_LBUTTONUP = 0x202

New-Item -ItemType Directory -Force -Path $OutDir, $WorkDir | Out-Null
$script:processes = @()
$script:spki = $null
$script:agent = $null
$logs = [ordered]@{}
foreach ($name in 'upstream', 'agent', 'open') {
  $logs[$name] = @((Join-Path $WorkDir "$name.out"), (Join-Path $WorkDir "$name.err"))
}

function Step([string] $Name, [scriptblock] $Body) {
  "::group::$Name"
  try { & $Body } finally { '::endgroup::' }
}

function Wait-Port([int] $Port, $Process, [string] $Name) {
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    if ($Process.HasExited) { throw "$Name exited with $($Process.ExitCode) before listening on port $Port" }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
      $client.Connect('127.0.0.1', $Port)
      return
    } catch {
      Start-Sleep -Milliseconds 250
    } finally {
      $client.Dispose()
    }
  }
  throw "$Name did not listen on port $Port within 60 seconds"
}

function Get-AgentStatus {
  $out = & $gateinto status | Out-String
  [pscustomobject] @{ Text = $out; Running = $out -match '(?m)^agent: running\r?$' }
}

function Get-GateintoIds {
  (Get-Process -Name gateinto -ErrorAction SilentlyContinue | ForEach-Object Id | Sort-Object) -join ','
}

function Get-ConfigHash {
  (Get-FileHash -Algorithm SHA256 -LiteralPath $config).Hash
}

function Set-Appearance([string] $Theme, [string] $Language) {
  New-Item -Force -Path $themeKey | Out-Null
  Set-ItemProperty -Path $themeKey -Name Theme -Value $Theme -Type String
  Set-ItemProperty -Path $themeKey -Name Language -Value $Language -Type String
}

function Assert-Gui($Gui) {
  if ($Gui.HasExited) { throw "gateinto-gui.exe exited with $($Gui.ExitCode)" }
  foreach ($hwnd in [GuiSmoke]::Windows($Gui.Id)) {
    if ([GuiSmoke]::Class($hwnd) -eq '#32770' -and [GuiSmoke]::IsWindowVisible($hwnd)) {
      throw "gateinto-gui.exe shows a message box '$([GuiSmoke]::Title($hwnd))': $([GuiSmoke]::MessageBoxText($hwnd))"
    }
  }
}

function Find-Window($Process, [string] $Class, [string] $Title) {
  foreach ($hwnd in [GuiSmoke]::Windows($Process.Id)) {
    if ([GuiSmoke]::Class($hwnd) -eq $Class -and [GuiSmoke]::Title($hwnd) -eq $Title -and [GuiSmoke]::IsWindowVisible($hwnd)) {
      return $hwnd
    }
  }
  [IntPtr]::Zero
}

function Start-Gui([string] $Theme, [string] $Language = 'English', [switch] $Demo) {
  Set-Appearance $Theme $Language
  $title = if ($Demo) { 'Gateinto Demo' } else { 'Gateinto' }
  $gui = if ($Demo) { Start-Process -FilePath $guiExe -ArgumentList '--demo' -PassThru } else { Start-Process -FilePath $guiExe -PassThru }
  $null = $gui.Handle
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    Assert-Gui $gui
    $hwnd = Find-Window $gui 'GateintoWindow' $title
    if ($hwnd -ne [IntPtr]::Zero) {
      Start-Sleep -Seconds 3
      Assert-Gui $gui
      return [pscustomobject] @{ Process = $gui; Hwnd = $hwnd; Theme = $Theme; Language = $Language }
    }
    Start-Sleep -Milliseconds 250
  }
  throw "gateinto-gui.exe showed no visible top-level window titled $title within 60 seconds"
}

function Stop-Gui($Gui) {
  Assert-Gui $Gui.Process
  $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($Gui.Process.Id)")
  if ($children.Count -gt 0) {
    throw "gateinto-gui.exe started child processes: $(($children | ForEach-Object { "$($_.Name) ($($_.ProcessId))" }) -join ', ')"
  }
  $theme = (Get-ItemProperty -Path $themeKey -Name Theme).Theme
  if ($theme -ne $Gui.Theme) { throw "gateinto-gui.exe changed the Theme value from $($Gui.Theme) to $theme" }
  $language = (Get-ItemProperty -Path $themeKey -Name Language).Language
  if ($language -ne $Gui.Language) { throw "gateinto-gui.exe changed the Language value from $($Gui.Language) to $language" }
  Stop-Process -Id $Gui.Process.Id -Force
  $Gui.Process.WaitForExit()
}

function Set-Foreground($Gui, [IntPtr] $Hwnd) {
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    Assert-Gui $Gui.Process
    if ([GuiSmoke]::GetForegroundWindow() -eq $Hwnd) { return }
    $null = [GuiSmoke]::ShowWindow($Hwnd, 9)
    $null = [GuiSmoke]::SetForegroundWindow($Hwnd)
    Start-Sleep -Milliseconds 200
    if ([GuiSmoke]::GetForegroundWindow() -eq $Hwnd) { return }
    # Windows grants SetForegroundWindow to the process that received the last input event.
    [GuiSmoke]::Key($VK_MENU, $false)
    [GuiSmoke]::Key($VK_MENU, $true)
    $null = [GuiSmoke]::SetForegroundWindow($Hwnd)
    Start-Sleep -Milliseconds 200
  }
  throw "could not bring the window '$([GuiSmoke]::Title($Hwnd))' to the foreground"
}

function Send-Keys($Gui, [int[]] $Modifiers, [int] $Key, [int] $Times = 1) {
  Set-Foreground $Gui $Gui.Hwnd
  for ($i = 0; $i -lt $Times; $i++) {
    foreach ($m in $Modifiers) { [GuiSmoke]::Key($m, $false) }
    [GuiSmoke]::Key($Key, $false)
    [GuiSmoke]::Key($Key, $true)
    [array]::Reverse($Modifiers)
    foreach ($m in $Modifiers) { [GuiSmoke]::Key($m, $true) }
    [array]::Reverse($Modifiers)
    Start-Sleep -Milliseconds 150
  }
  Start-Sleep -Milliseconds 1000
  Assert-Gui $Gui.Process
}

function Save-Window($Gui, [IntPtr] $Hwnd, [string] $Name) {
  Assert-Gui $Gui.Process
  $window = [GuiSmoke]::Bounds($Hwnd)
  $screen = [GuiSmoke]::Screen()
  $left = [Math]::Max($window.Left, $screen.Left)
  $top = [Math]::Max($window.Top, $screen.Top)
  $width = [Math]::Min($window.Right, $screen.Right) - $left
  $height = [Math]::Min($window.Bottom, $screen.Bottom) - $top
  if ($width -le 0 -or $height -le 0) { throw "${Name}: the window lies outside the screen" }
  if ($width -ne $window.Right - $window.Left -or $height -ne $window.Bottom - $window.Top) {
    Write-Host "::warning::${Name}: the window extends past the screen; only the visible part was captured"
  }
  $format = [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
  $bitmap = [System.Drawing.Bitmap]::new($width, $height, $format)
  try {
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try { $graphics.CopyFromScreen($left, $top, 0, 0, $bitmap.Size) } finally { $graphics.Dispose() }
    $data = $bitmap.LockBits([System.Drawing.Rectangle]::new(0, 0, $width, $height), [System.Drawing.Imaging.ImageLockMode]::ReadOnly, $format)
    try {
      $pixels = [byte[]]::new($data.Stride * $height)
      [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $pixels, 0, $pixels.Length)
    } finally {
      $bitmap.UnlockBits($data)
    }
    $path = Join-Path $OutDir "$Name.png"
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  } finally {
    $bitmap.Dispose()
  }
  $colours = [GuiSmoke]::Colours($pixels, 4096)
  $luma = [GuiSmoke]::Luma($pixels)
  Write-Host "${Name}.png: ${width}x${height} at ($left, $top), $(if ($colours -ge 4096) { '4096+' } else { $colours }) colours, mean luma $([Math]::Round($luma, 1))"
  if ($colours -lt 2) { throw "$Name.png is blank: every pixel has the same colour" }
  Assert-Gui $Gui.Process
  [pscustomobject] @{
    Name = $Name
    Hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($pixels))
    Luma = $luma
  }
}

function Assert-Distinct([object[]] $Shots, [string] $What) {
  $groups = @($Shots | Group-Object Hash | Where-Object Count -gt 1)
  if ($groups.Count -gt 0) {
    throw "$What are pixel-identical: $(($groups | ForEach-Object { ($_.Group.Name) -join ' = ' }) -join '; ')"
  }
}

function Save-Flyout($Gui, [string] $Name) {
  Set-Foreground $Gui $Gui.Hwnd
  $screen = [GuiSmoke]::Screen()
  $x = $screen.Right - 40
  $y = $screen.Bottom - 20
  $anchor = [UIntPtr]::new([uint64] ((($y -band 0xffff) -shl 16) -bor ($x -band 0xffff)))
  foreach ($message in $NIN_SELECT, $WM_LBUTTONUP) {
    $null = [GuiSmoke]::PostMessage($Gui.Hwnd, $WM_TRAY, $anchor, [IntPtr] $message)
    $deadline = (Get-Date).AddSeconds(3)
    while ((Get-Date) -lt $deadline) {
      $flyout = Find-Window $Gui.Process 'GateintoFlyout' $flyoutTitles[$Gui.Language]
      if ($flyout -ne [IntPtr]::Zero) {
        Start-Sleep -Milliseconds 800
        $shot = Save-Window $Gui $flyout $Name
        [GuiSmoke]::Key($VK_ESCAPE, $false)
        [GuiSmoke]::Key($VK_ESCAPE, $true)
        Start-Sleep -Milliseconds 500
        return $shot
      }
      Start-Sleep -Milliseconds 200
    }
  }
  Write-Host "::warning::the tray flyout did not appear after a simulated tray icon click; $Name.png was not captured"
}

function Invoke-Theme([string] $Theme, [string] $Language = 'English') {
  $before = Get-GateintoIds
  $gui = Start-Gui $Theme $Language
  $prefix = $Theme.ToLowerInvariant()
  if ($Language -ne 'English') { $prefix = "$prefix-$($Language.ToLowerInvariant())" }
  $shots = @(Save-Window $gui $gui.Hwnd "$prefix-0-startup")
  for ($i = 0; $i -lt $pages.Count; $i++) {
    Send-Keys $gui @($VK_CONTROL) (0x31 + $i)
    $shots += Save-Window $gui $gui.Hwnd "$prefix-$($i + 1)-$($pages[$i])"
  }
  Assert-Distinct @($shots | Select-Object -Skip 1) "the $Theme page screenshots after Ctrl+1..Ctrl+5"
  Send-Keys $gui @($VK_CONTROL) 0x32
  Send-Keys $gui @() $VK_TAB 3
  $focus = Save-Window $gui $gui.Hwnd "$prefix-2-gateways-focus"
  Assert-Distinct @(($shots | Where-Object Name -eq "$prefix-2-gateways"), $focus) "the $Theme Gateways screenshots before and after Tab"
  $flyout = Save-Flyout $gui "$prefix-tray-flyout"
  Stop-Gui $gui
  $after = Get-GateintoIds
  if ($after -ne $before) { throw "gateinto.exe processes changed while gateinto-gui.exe ran: before [$before], after [$after]" }
  if (-not $script:agent -or $script:agent.HasExited) { throw 'the agent exited while gateinto-gui.exe ran' }
  $shots | Where-Object Name -eq "$prefix-1-sessions"
}

try {
  Step 'Start the local test upstream' {
    if (Test-Path -LiteralPath $config) { throw "$config already exists; this job expects a fresh runner profile" }
    $upstream = Start-Process -FilePath $upstreamExe -PassThru -NoNewWindow `
      -ArgumentList '--port', $UpstreamPort, '--ca-out', "`"$(Join-Path $WorkDir 'upstream-ca.pem')`"" `
      -RedirectStandardOutput $logs.upstream[0] -RedirectStandardError $logs.upstream[1]
    $null = $upstream.Handle
    $script:processes += $upstream
    Wait-Port $UpstreamPort $upstream 'test upstream'
  }

  Step 'Write the default config file' {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    $ca = Join-Path $WorkDir 'upstream-ca.pem'
    $text = @"
[device_session]
gateway = "local"
listen = "127.0.0.1:$ListenPort"
auth = "os_user"

[gateways.local]
host = "127.0.0.1"
port = $UpstreamPort
server_name = "localhost"
ca_file = '$ca'
"@
    [System.IO.File]::WriteAllText($config, $text)
    Get-Content -LiteralPath $config
  }

  Step 'gateinto setup (Microsoft Software Key Storage Provider, not a TPM)' {
    $out = & $gateinto setup --backend software | Out-String
    if ($LASTEXITCODE -ne 0) { throw "gateinto setup exited with $LASTEXITCODE" }
    $out
    if ($out -notmatch '(?m)^provider: Microsoft Software Key Storage Provider\r?$') { throw 'setup did not use the Software KSP' }
    if ($out -match '(?m)^spki-sha256: ([0-9a-f]{64})\r?$') { $script:spki = $Matches[1] } else { throw 'setup printed no spki-sha256' }
  }

  Step 'Start the agent and tunnel through the device session' {
    $env:RUST_LOG = 'info'
    $script:agent = Start-Process -FilePath $gateinto -PassThru -NoNewWindow -ArgumentList 'agent' `
      -RedirectStandardOutput $logs.agent[0] -RedirectStandardError $logs.agent[1]
    $null = $script:agent.Handle
    $script:processes += $script:agent
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Get-AgentStatus).Running) {
      if ($script:agent.HasExited) { throw "the agent exited with $($script:agent.ExitCode)" }
      if ((Get-Date) -gt $deadline) { throw 'the agent did not report running within 60 seconds' }
      Start-Sleep -Milliseconds 250
    }
    Wait-Port $ListenPort $script:agent 'the device session'
    $status = curl.exe -sS -o NUL -w "%{http_code}" -x "http://127.0.0.1:$ListenPort" https://example.com/
    if ($LASTEXITCODE -ne 0) { throw "curl.exe through the device session exited with $LASTEXITCODE" }
    if ($status -ne '200') { throw "HTTPS through the device session returned $status, expected 200" }
    "HTTPS through the device session: $status"
  }

  Step 'Start a browser session through the local gateway' {
    $open = Start-Process -FilePath $gateinto -PassThru -NoNewWindow `
      -ArgumentList 'open', '--', 'gateinto://connect?profile=local' `
      -RedirectStandardOutput $logs.open[0] -RedirectStandardError $logs.open[1]
    $null = $open.Handle
    if (-not $open.WaitForExit(60000)) {
      Stop-Process -Id $open.Id -Force
      "::warning::gateinto open did not return within 60 seconds (a credentials dialog may have appeared); continuing without a browser session"
    } elseif ($open.ExitCode -ne 0) {
      "::warning::gateinto open exited with $($open.ExitCode); continuing without a browser session"
    }
    Get-Content $logs.open
    Start-Sleep -Seconds 5
    & $gateinto session list
    (Get-AgentStatus).Text
  }

  $hash = Get-ConfigHash
  "config SHA-256 before gateinto-gui.exe: $hash"

  Step 'Light theme: pages, focus ring and tray flyout' { $script:light = Invoke-Theme 'Light' }
  Step 'Dark theme: pages, focus ring and tray flyout' { $script:dark = Invoke-Theme 'Dark' }
  if ($script:light.Hash -eq $script:dark.Hash) { throw 'the Light and Dark Sessions screenshots are pixel-identical' }
  if ($script:light.Luma -le $script:dark.Luma) { throw "the Light Sessions screenshot (mean luma $($script:light.Luma)) is not brighter than the Dark one ($($script:dark.Luma))" }
  Step 'Traditional Chinese: pages, focus ring and tray flyout' { $script:chinese = Invoke-Theme 'Light' 'zh-TW' }
  if ($script:light.Hash -eq $script:chinese.Hash) { throw 'the English and Traditional Chinese Sessions screenshots are pixel-identical' }

  Step 'Stop the agent, then check that gateinto-gui.exe does not start one' {
    & $gateinto stop
    if ($LASTEXITCODE -ne 0) { throw "gateinto stop exited with $LASTEXITCODE" }
    if (-not $script:agent.WaitForExit(30000)) { throw 'the agent did not exit within 30 seconds of gateinto stop' }
    $gui = Start-Gui 'Light'
    Start-Sleep -Seconds 10
    $null = Save-Window $gui $gui.Hwnd 'light-1-sessions-agent-stopped'
    $ids = Get-GateintoIds
    if ($ids) { throw "gateinto.exe runs although the agent was stopped: $ids" }
    if ((Get-AgentStatus).Running) { throw 'an agent is running although only gateinto-gui.exe was started' }
    Stop-Gui $gui
  }

  Step 'Demo: pages and tray flyout without an agent' {
    $gui = Start-Gui 'Dark' 'zh-TW' -Demo
    $shots = @(Save-Window $gui $gui.Hwnd 'demo-0-startup')
    for ($i = 0; $i -lt $pages.Count; $i++) {
      Send-Keys $gui @($VK_CONTROL) (0x31 + $i)
      $shots += Save-Window $gui $gui.Hwnd "demo-$($i + 1)-$($pages[$i])"
    }
    Assert-Distinct @($shots | Select-Object -Skip 1) 'the demo page screenshots after Ctrl+1..Ctrl+5'
    $null = Save-Flyout ([pscustomobject] @{ Process = $gui.Process; Hwnd = $gui.Hwnd; Language = 'English' }) 'demo-tray-flyout'
    $ids = Get-GateintoIds
    if ($ids) { throw "gateinto.exe runs although only the demo was started: $ids" }
    Stop-Gui $gui
  }

  $after = Get-ConfigHash
  "config SHA-256 after gateinto-gui.exe: $after"
  if ($after -ne $hash) { throw 'gateinto-gui.exe changed the config file' }
} finally {
  Step 'Clean up the GUI, the agent, the upstream and the device key' {
    Get-Process -Name gateinto-gui -ErrorAction SilentlyContinue | Stop-Process -Force
    if ($script:agent -and -not $script:agent.HasExited) { & $gateinto stop }
    foreach ($process in $script:processes) {
      if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
      $process.WaitForExit()
    }
    if ($script:spki) { & $gateinto reset --purge-device-identity --confirm-spki $script:spki }
    foreach ($name in $logs.Keys) {
      foreach ($file in $logs[$name]) {
        if (Test-Path $file) { "--- $file ---"; Get-Content $file }
      }
    }
  }
}

exit 0
