# Gateinto MSI (WiX v5)

`gateinto.wxs` builds a standard Windows Installer package. Gateinto then shows up in
Settings → Apps → Installed apps, and Windows Installer writes the uninstall (ARP) entry.

## Per-user scope

The package is `Scope="perUser"`. It installs without elevation to
`%LOCALAPPDATA%\Programs\Gateinto` and writes only to `HKEY_CURRENT_USER`, the user's own
Start Menu and, when it does not exist yet, the config file in the user's own `%APPDATA%`.
This scope fits the rest of Gateinto:

- The `gateinto://` handler goes in `HKCU\Software\Classes\gateinto`, the same per-user scope
  that `gateinto uri register` uses, so no `HKLM` handler competes with it.
- The device key is a per-user CNG key. A per-user package always runs as the user who
  installs it, never as `SYSTEM` or as an elevated installer service account.
- No custom action creates or opens a device key. `gateinto setup` (or the first
  `gateinto key init`) creates the key later, as the user who will use it.

A machine-wide install for several users is not provided.

## What the package contains

| Item | Where | Removed by uninstall |
|---|---|---|
| `gateinto.exe` | `%LOCALAPPDATA%\Programs\Gateinto` | yes |
| `gateinto-gui.exe`, the GUI | `%LOCALAPPDATA%\Programs\Gateinto`, next to `gateinto.exe`, where its Start agent looks for it | yes |
| Start Menu shortcut **Gateinto** to `gateinto-gui.exe` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Gateinto.lnk` (`ProgramMenuFolder` of a per-user package) | yes |
| Install folder appended to the user `PATH` | `HKCU\Environment` | yes |
| `gateinto://` handler | `HKCU\Software\Classes\gateinto`, command `"<INSTALLFOLDER>gateinto.exe" open -- "%1"` | yes, the whole key |
| Logon autostart (optional, off by default) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Gateinto` = `"<INSTALLFOLDER>gateinto.exe" agent --detach` | yes |
| Install markers (`InstallFolder`, `Gui`), the key paths of the components | `HKCU\Software\Gateinto\Installer` | yes |
| Config template `gateinto.toml`, only when no file of that name exists | `%APPDATA%\Gateinto\gateinto.toml` | no, permanent |
| Marker `ConfigTemplate`, the key path of the template's component | `HKCU\Software\Gateinto\Installer` | no, permanent |
| Uninstall entry | written by Windows Installer | yes |

The handler command uses the same format that `gateinto uri register` writes for an executable
without `--config`, so `gateinto uri unregister` and `gateinto status` recognise it as
Gateinto's. Without `--config`, `gateinto open` and the agent read the per-user default config
file `%APPDATA%\Gateinto\gateinto.toml`.

The config template is [gateinto.toml](gateinto.toml): [config.example.toml](../../config.example.toml)
with every setting commented out, so it parses to the built-in defaults (a unit test in
`src/config.rs` checks both). `AppSearch` sets `CONFIGEXISTS` when
`%APPDATA%\Gateinto\gateinto.toml` exists, and the `ConfigTemplate` component's condition is
`NOT CONFIGEXISTS`, so a file that exists at the first install is left alone. The design intent
below is not yet verified on Windows. The condition is not `Transitive`, so Windows Installer
evaluates it only when it first installs the component; a transitive condition that turns false
on a repair would ask Windows Installer to remove the component, which is the case to avoid. The
component is `NeverOverwrite`, so a repair (including `msiexec /fa`) or an upgrade skips it while
its key path, the `ConfigTemplate` value, exists, instead of reinstalling the file over the
user's edits. It is `Permanent`, so an uninstall keeps the file and the value even when the user
never changed the file. As the value stays, a deleted file is not recreated by a later install
unless the value is deleted too. A unit test in `src/config.rs` checks the condition, `NeverOverwrite`
and `Permanent`, and that `Transitive` is absent. A per-user
package runs as the installing user, so `AppDataFolder` is that user's roaming `%APPDATA%`, the
folder `gateinto::config::default_path` reads. The component is separate from the device key:
no custom action runs `gateinto`, and `gateinto setup` still creates the key. Its folder has a
`RemoveFolder` entry for ICE64; as the component is permanent it never runs.

The shortcut is not advertised and sits directly in the Start Menu's `Programs` folder, so the
package creates no Start Menu folder of its own. It belongs to the GUI's component, whose key path
is the `HKCU` marker value `Gui`, as a per-user component with a shortcut needs. Keeping the
shortcut with its target file avoids a cross-component file reference (ICE69).
The package never runs the GUI or the agent after installing. Its custom actions are deferred,
impersonated, ignore failures, run before `RemoveFiles` and only when `REMOVE~="ALL"`:
`StopAgent` (`gateinto.exe stop --remove-stale-profiles`); `UninstallGui`
(`gateinto-gui.exe --uninstall`) when `NOT UPGRADINGPRODUCTCODE`, which closes a running GUI of
the user and deletes the GUI's own `Gateinto App` Run value and its StartupApproved entry if the
value runs the installed GUI; and `QuitGui` (`gateinto-gui.exe --quit`) when a major upgrade
removes the old version, which only closes the GUI so the user's **Start the app at sign-in**
choice survives the upgrade. The package never writes `Gateinto App`; only the GUI's switch
does. See [docs/install.md](../../docs/install.md).

`MajorUpgrade` replaces an older version in place, and a
downgrade to a lower `major.minor.patch` is refused with "A newer version of Gateinto is already
installed. Uninstall it first, then install this one." `AllowSameVersionUpgrades="yes"` makes an
MSI with the same version replace the installed one too: every alpha, beta and latest build has
version `0.0.0`, so without it a second build would be installed next to the first as another
product. Between builds of the same version any MSI replaces any other, including an older
commit. The x64 and x86 MSIs share the `UpgradeCode`, the component GUIDs and the install
folder, so each is expected to replace the other; swapping between them is untested. A release
MSI (`0.0.0`) over a local build with the `Cargo.toml` version (for example `0.1.0`) is a
downgrade and is refused; uninstall the local build first. ICE validation can report ICE61
("This product should remove only older versions of itself") as a warning for this; it is
expected, and `build.ps1` does not treat warnings as errors. CI does not yet install one build
over another of the same version or of the other architecture.

## Build

The release workflow builds the MSI from the release's `gateinto.exe` and `gateinto-gui.exe` with the same `build.ps1` and
WiX 5.0.2 and attaches an x64 MSI and an x86 MSI to each release (see
[install](../../docs/install.md#releases)). It passes `-Version 0.0.0 -DisplayVersion
0.0.0-<commit>`. To build it from a checkout instead you need the Rust toolchain, the .NET SDK
and WiX v5:

```powershell
dotnet tool install --global wix --version 5.0.2
cargo build --release --locked -p gateinto -p gateinto-gui
pwsh packaging/wix/build.ps1
```

`build.ps1` reads the version from `Cargo.toml`, takes `target\release\gateinto.exe` and
`target\release\gateinto-gui.exe` and writes `target\wix\gateinto.msi`. Use `-Binary`,
`-GuiBinary` and `-Output` to choose other paths. Other parameters:

- `-Arch x64` (default) or `-Arch x86`, passed to `wix build -arch`. The package is per-user,
  installs into `%LOCALAPPDATA%\Programs\Gateinto` and writes only `HKCU` keys that both
  registry views share, so nothing in `gateinto.wxs` depends on the architecture. Build the x86
  MSI from the `i686-pc-windows-msvc` `gateinto.exe` and `gateinto-gui.exe`.
- `-Version X.Y.Z` sets the MSI version instead of the `Cargo.toml` one.
- `-DisplayVersion <text>` names the product `Gateinto <text>` in **Installed apps**; without it
  the name is `Gateinto`.

## Install

```powershell
msiexec /i gateinto.msi                         # interactive
msiexec /i gateinto.msi /qn                     # silent
msiexec /i gateinto.msi /qn AUTOSTART=1         # silent, start the agent at logon
```

After installing, open a new terminal (the install folder is appended to the user `PATH`) and
run `gateinto setup` once as the user who will use Gateinto. It creates the
device key, or reuses the existing one after a reinstall, and prints its `spki-sha256`.

## Uninstall

Use Settings → Apps → Installed apps → Gateinto → Uninstall, or `msiexec /x gateinto.msi /qn`.

Before removing files, a deferred custom action runs
`gateinto.exe stop --remove-stale-profiles` as the installing user. That closes the agent's
listeners and sessions, ends their browsers and deletes the Gateinto browser profiles
under `%LOCALAPPDATA%\Gateinto\profiles`. Failures are ignored, for example when no agent is
running. `stop` waits up to 15 seconds for the agent process to exit, so `gateinto.exe` is not
in use when its file is removed. The uninstall then removes the files and registry entries
listed above. During an interactive uninstall a console window may flash briefly for this
step. A major upgrade runs the old version's step too, which stops the agent without starting
it again.

The uninstall keeps:

- the device key, so a reinstall followed by `gateinto setup` keeps the same `spki-sha256` and
  device identity;
- the config file `%APPDATA%\Gateinto\gateinto.toml` and any other config file;
- the user's own Chrome and Edge profiles, which Gateinto never touches.

The device key is not an MSI component. The config file is one only when the installer created
it from the template, and that component is permanent, so Windows Installer is designed never to
remove the file (not yet verified on Windows); a file the user created is not part of the package at all.

## Purge

A silent or normal uninstall never deletes the device identity. To delete it, run this before
uninstalling (or from a copy of `gateinto.exe` afterwards):

```powershell
gateinto reset --purge-device-identity                    # asks for the SPKI prefix
gateinto reset --purge-device-identity --confirm-spki <first 16+ hex digits of spki-sha256>
gateinto reset --purge-device-identity --purge-config ...  # also delete the config file
```

`reset` deletes only the Gateinto key with the configured name, after it confirms the SPKI. It
does not revoke the device at any gateway, and it does not remove the `gateinto://` handler.
See [docs/install.md](../../docs/install.md).

## Verification status

CI (`windows-latest`, Microsoft Software Key Storage Provider) builds an x64 MSI and an x86 MSI
(the latter with the i686 debug build, run under WOW64), installs and uninstalls each silently,
checks that the GUI and its Start Menu shortcut are installed and removed and that installing
starts nothing, that uninstalling closes a running GUI (when the runner shows its window) and
removes only the GUI's own `Gateinto App` sign-in value, and checks that the SPKI survives a reinstall and changes only after a
purge. The config template checks in that script (created on the first install, kept with an
edited content across `msiexec /fa`, `msiexec /f`, a same-version major upgrade to a second build
and back, both uninstalls, a reinstall and another `msiexec /fa`) were added after the last
recorded CI run and have not run on Windows yet. The following are not verified by CI and need manual testing: opening the GUI from the
shortcut, closing the GUI during an interactive uninstall or an upgrade, keeping `Gateinto App`
across an upgrade between two versions, TPM keys, interactive
install, the Windows 10/11 matrix, the x86 MSI on real 32-bit Windows (it is untested on Windows
7, where the i686 executable does not start) and clicking a real `gateinto://` link.

No WinGet package exists, so `winget install` does not install Gateinto.
