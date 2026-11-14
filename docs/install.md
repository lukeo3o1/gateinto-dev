# Installing, uninstalling and resetting Gateinto

This page covers the Windows installer, the Linux tarball and the commands that manage the
device identity across installs: `gateinto setup`, `gateinto status` and `gateinto reset`. The
MSI is built from [packaging/wix](../packaging/wix/README.md). The Linux tarball, built from
[packaging/linux](../packaging/linux/README), is covered in [Linux tarball](#linux-tarball); it is
not yet verified on a real Linux desktop. Linux has no device key yet, so on Linux `setup` and
`reset` check their input and then stop with an error; each section below says what differs on
Linux.

No WinGet package exists. `winget install` and `winget uninstall` do not install or remove
Gateinto; [packaging/winget](../packaging/winget/README.md) only holds unsubmitted manifest
templates. To build the MSI yourself, use `packaging/wix/build.ps1` as described in
[packaging/wix](../packaging/wix/README.md#build).

## Releases

The repository is private, so its GitHub Releases are for the owner's own downloads; nothing is
published for anyone else. There are exactly three releases, one per channel, each with a tag of
the same name that points at the commit it was built from. Every channel, `latest` included, is
a pre-release, not externally security reviewed; GitHub marks each one as a prerelease, so none
is shown as the repository's latest release:

| Channel | Published | Marked on GitHub |
| --- | --- | --- |
| `alpha` | automatically, after CI passes on a push to `master` and the release workflow's own build and tests pass | prerelease |
| `beta` | by hand: Actions → Release → Run workflow, channel `beta`, and a full commit SHA (recommended), branch or tag (default `master`) | prerelease |
| `latest` | by hand, the same way with channel `latest` | prerelease |

Every publish replaces the whole release: the workflow deletes the release and its tag and
creates both again at the built commit, so the files, the tag and the notes always describe one
commit. While the new files upload, that release and its URLs are briefly missing. If a publish
fails after deleting the release, the channel stays missing until a later run publishes it:
rerun the failed run, or for `alpha` wait for the next push to `master` (a rerun of an `alpha`
run whose commit is no longer the tip of `master` publishes nothing). A rerun of an older
`alpha` run never moves `alpha` back to an older commit.

Give the manual run a full commit SHA, so that the release is built from exactly the commit you
checked; a branch is resolved when the run starts. Only commits that contain this release
workflow's `.github/actions` and `.github/scripts` can be released, so commits from before the
release channels were added cannot be published. Publishing also needs the Linux tarball, so
commits without the Linux packaging (`packaging/linux` and `.github/scripts/linux-tarball.sh`)
can no longer be published on any channel.

The release notes start with "Pre-release, not externally security reviewed." and the title and
notes name the channel, the full commit SHA and the build date, followed by a notice that the
files are not code-signed, that TPM keys, real browsers, physical Windows machines and Windows 7
are not yet verified on real hardware
([#23](https://github.com/lukeo3o1/gateinto-dev/issues/23)), and, for `alpha` and `beta`, that
the Windows 7 build is experimental and can use only the Microsoft Software Key Storage
Provider. They also say that the Linux tarball and its scripts are not yet verified on a real
Linux desktop and that Linux has no device key yet.

Each file is attached twice: with the first 12 characters of the commit in its name, and as a
copy without it. The copy keeps the same download URL from one publish to the next:

| File without the commit | `latest` | `alpha`, `beta` |
| --- | --- | --- |
| `gateinto-x86_64-pc-windows-msvc.exe`, Windows 10/11 x64 | yes | yes |
| `gateinto-x86_64-pc-windows-msvc.msi`, the per-user installer below, 64-bit | yes | yes |
| `gateinto-i686-pc-windows-msvc.exe`, 32-bit Windows 10 | yes | yes |
| `gateinto-i686-pc-windows-msvc.msi`, the per-user installer below, 32-bit (x86) | yes | yes |
| `gateinto-i686-win7-windows-msvc-experimental.exe` | no | yes |
| `gateinto-x86_64-unknown-linux-gnu.tar.gz`, the [Linux tarball](#linux-tarball), x86_64 glibc | yes | yes |

Each file has a `.sha256` next to it, one line with the lowercase SHA-256, two spaces and the
file name. The names with the commit are `gateinto-<commit>-<target>.exe` and so on, for
example `gateinto-0123456789ab-x86_64-pc-windows-msvc.exe`. The fixed URLs are

```text
https://github.com/lukeo3o1/gateinto-dev/releases/download/<channel>/<file without the commit>
https://github.com/lukeo3o1/gateinto-dev/releases/download/latest/gateinto-x86_64-pc-windows-msvc.msi
```

While the repository is private they work only when signed in to GitHub as someone with access,
or through the GitHub CLI:

```powershell
gh release download latest --repo lukeo3o1/gateinto-dev --pattern 'gateinto-x86_64-pc-windows-msvc.msi*'
```

Verify a download in PowerShell before running or installing it:

```powershell
$file = "gateinto-x86_64-pc-windows-msvc.msi"   # the file you downloaded, with its .sha256 next to it
$expected = (Get-Content "$file.sha256").Split(" ")[0]
$actual = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 mismatch: do not use this file" }
```

The checksum only proves that the download matches the file the workflow published next to it;
nothing is signed.

Release builds are versioned `0.0.0-<commit>`: `gateinto --version` prints for example
`gateinto 0.0.0-0123456789ab`, and the MSI appears in **Installed apps** as
`Gateinto 0.0.0-0123456789ab`. A Windows Installer version must be numeric, so the MSI's own
version is `0.0.0` for every release build. Installing any release MSI, x64 or x86, from any
channel therefore replaces whichever release build is installed, older or newer; see
[packaging/wix](../packaging/wix/README.md).

An MSI built locally with `packaging/wix/build.ps1` and no `-Version` has the `Cargo.toml`
version, for example `0.1.0`, and is named plain `Gateinto`. Windows Installer sees a release
MSI (`0.0.0`) over it as a downgrade and refuses with "A newer version of Gateinto is already
installed. Uninstall it first, then install this one." Uninstall the local build first (see
[Uninstall](#uninstall)); the device key and the config file are kept.

The x86 MSI installs the `i686-pc-windows-msvc` executables, which need Windows 10 or later. The
GUI is not released for Windows 7 and is not part of the experimental Windows 7 release build.
An experimental `i686-win7-windows-msvc` build of the GUI exists only as a CI artifact of
[windows7.yml](../.github/workflows/windows7.yml); it has had only a static import audit and has
never been run (see [windows7-feasibility.md](windows7-feasibility.md#gui-static-import-audit)).
CI runs the x86 build only under WOW64 on 64-bit Windows Server; it has not been tested on a
real 32-bit Windows 10 installation, and it is untested on Windows 7, where that executable does
not start.

## Install

The MSI is a per-user package (`Scope="perUser"`). It installs without elevation or a UAC
prompt, for the user who runs it:

```powershell
msiexec /i gateinto.msi                   # interactive
msiexec /i gateinto.msi /qn               # silent
msiexec /i gateinto.msi /qn AUTOSTART=1   # silent, also start the agent at logon
```

It installs:

- `%LOCALAPPDATA%\Programs\Gateinto\gateinto.exe`, with that folder appended to the user
  `PATH` (`HKCU\Environment`). Open a new terminal after installing so that `gateinto` is
  found; terminals that were already open keep the old `PATH`;
- the GUI, `%LOCALAPPDATA%\Programs\Gateinto\gateinto-gui.exe`, next to `gateinto.exe`, where
  its **Start agent** button looks for it;
- a Start Menu shortcut named **Gateinto** in the user's own Start Menu
  (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Gateinto.lnk`) that opens the GUI;
- the `gateinto://` handler in `HKCU\Software\Classes\gateinto`, with the command
  `"%LOCALAPPDATA%\Programs\Gateinto\gateinto.exe" open -- "%1"` (the path is written out in
  full). The handler is per-user only; the MSI writes no `HKLM` handler. The executable path is
  quoted, and the URI is passed as a single quoted argument after `--`, so it can never become
  an option or a second command;
- optionally, when `AUTOSTART=1` is set or the "Start the Gateinto agent at logon" feature is
  selected, the value `Gateinto` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, which
  runs `"…\gateinto.exe" agent --detach` at logon. `--detach` starts the agent as a
  background process and waits until it accepts requests; if an agent already runs it does
  nothing. The agent runs without a console; a console window may flash briefly at logon. It
  is off by default;
- the config file `%APPDATA%\Gateinto\gateinto.toml`, only when no file of that name exists
  yet. It is a template ([packaging/wix/gateinto.toml](../packaging/wix/gateinto.toml)) based on
  [config.example.toml](../config.example.toml) in which every setting is commented out, so
  it changes nothing until a line is uncommented: Gateinto behaves as with no config file.
  The installer is designed never to overwrite an existing file and to keep it on uninstall
  (see [Config file location](#config-file-location)); this is not yet verified on Windows;
- the uninstall entry under Settings → Apps → Installed apps, written by Windows Installer.

The package creates no other shortcuts. Installing starts neither the GUI nor the agent, and does
not write the GUI's own `Gateinto App` value in the Run key (the GUI's **Start the app at
sign-in** switch); only that switch writes it. A full uninstall removes it (see below). The package does not create a device key,
and none of its custom actions creates a key: the installer never creates a key as
`SYSTEM` or as an elevated installer account; `gateinto setup` does that later. Windows
Installer runs a per-user package as the installing user, so the config template lands in that
user's own `%APPDATA%`.

### Why per-user

The `gateinto://` handler, the device key (a per-user CNG key) and the agent (a per-user named
pipe) all belong to one Windows user. A machine-wide install would need an `HKLM` handler that
competes with per-user ones, and would run its custom actions as `SYSTEM`. There is no machine
service mode and no shared local proxy; sessions run only for a logged-on user.

## First run: `gateinto setup`

Run this once after installing, as the Windows user who will use Gateinto:

```powershell
gateinto setup
gateinto setup --config D:\gateinto.toml --backend software
```

`setup`:

1. refuses to run as LocalSystem (`S-1-5-18`), LocalService (`S-1-5-19`) or NetworkService
   (`S-1-5-20`), so a script, scheduled task or service running as one of those accounts cannot
   create a key for the wrong account. When run elevated, it notes on stderr that the key still
   belongs to the current Windows user, not to the machine;
2. reads the config file, `--config` or the default `%APPDATA%\Gateinto\gateinto.toml`, and
   prints its path and each gateway as `gateway: <name>: <host>:<port>, route <route> (config)`, then the
   gateways added from `gateinto://` links as `... (linked)`. A config that does not
   parse stops `setup` before any key is touched;
3. does what `gateinto key init` does. It reuses an existing key named `[device_key] name`
   (default `gateinto-device-v1`) in either provider, or creates one only when none exists. It
   never replaces a key that exists, and it stops on the same errors as `key init`: keys in
   both providers, a TPM that is present but not ready, or a key that cannot be opened. It
   takes the `key init` flags: `--name`, `--backend`, `--software-fallback` and
   `--no-software-fallback`;
4. reports the `gateinto://` handler of the current user.

Output (example):

```text
config: C:\Users\me\AppData\Roaming\Gateinto\gateinto.toml (default location)
gateway: office: proxy.example.com:443, route mixed (config)
linked-gateways: none (no directory at C:\Users\me\AppData\Roaming\Gateinto\gateways)
key-name: gateinto-device-v1
device-key: created
provider: Microsoft Platform Crypto Provider
backend: tpm
algorithm: ECDSA P-256
spki-sha256: 3f0c…
trust: hardware-protected private key (TPM)
uri-handler: gateinto: "C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" open -- "%1"
```

`device-key` is `created` or `reused`. `setup` exits nonzero on any error.

Commands that run with logging (`agent`, `session browser`, `check-upstream`) log at
`info` which default config file they loaded.

`setup` is the only step besides `key init` that creates a key. `key init` refuses the same
service accounts as `setup`. `gateinto agent`,
`gateinto open` (and with it a clicked `gateinto://` link), `session browser` and `check-upstream`
only open the device key. If it is missing, a gateway with `client_certificate = "required"`
fails with "no device key named …; run `gateinto setup` to create it". The agent can be started
by the logon autostart or by a web page's link, with no console to show what was created or why
a TPM was skipped, so it does not create keys implicitly.

### `setup` on Linux

Linux has no device key yet
([design/linux-support.md](design/linux-support.md#area-7-device-identity-open-decision)), so
`setup` on Linux creates nothing and always exits nonzero. It:

1. refuses when the home directory, or `$XDG_CONFIG_HOME` or `$XDG_DATA_HOME` when it is
   outside the home directory, belongs to another user, as under `sudo` with the caller's
   `HOME`, and prints on stderr `warning: running as root, which can bypass every
   check Gateinto makes and is outside its security model; run Gateinto as the user who uses
   it` when run as root;
2. reads and prints the config file and the linked gateways as on Windows; a config that does
   not parse stops it here;
3. fails with the error shown in the last line of the output below.

It does not register the `gateinto://` handler; `install.sh` does that with
`gateinto uri register` (see [Linux tarball](#linux-tarball)). Output (example):

```text
config: /home/me/.config/gateinto/gateinto.toml (default location)
gateway: office: proxy.example.com:443, route mixed (config)
linked-gateways: none (no directory at /home/me/.config/gateinto/gateways)
error: setup is not available on Linux yet: it creates the device key, and no device key backend for Linux has been decided; run `gateinto uri register` to register the gateinto:// handler on its own
```

Without a device key, Gateinto on Linux connects without a device certificate: a gateway with
`client_certificate = "required"` fails, because the device key cannot be opened, and a gateway
that requires a client certificate rejects the connection
([details](design/linux-support.md#running-without-a-device-certificate)).

## Config file location

Without `--config`, every command reads the default config file when that file exists:
`%APPDATA%\Gateinto\gateinto.toml` on Windows, and `$XDG_CONFIG_HOME/gateinto/gateinto.toml` on
Linux, or `~/.config/gateinto/gateinto.toml` when `XDG_CONFIG_HOME` is unset, empty or not an
absolute path. The installed handler and the autostart entry pass no `--config`, and neither
does the handler that `install.sh` registers on Linux, so this is where an installed Gateinto
finds its gateways. On Linux nothing creates the file: `install.sh` writes no configuration, so
create it yourself, for example from [config.example.toml](../config.example.toml), and restart
the agent. On Windows, the installer creates this file from a
template with every setting commented out, only if it does not exist yet, and records this in
the value `ConfigTemplate` under `HKCU\Software\Gateinto\Installer`. The design intent, not yet verified on Windows,
is that Windows Installer never overwrites or removes the file afterwards: a repair or an
upgrade skips the template while that value exists, and an uninstall keeps both the file and the
value. A deleted file therefore does not come back as the template, not even after an uninstall
and a new install, unless the `ConfigTemplate` value is deleted too. Uncomment a setting, then restart the agent: it reads the file
only when it starts. On Windows, `gateinto reset --purge-device-identity --purge-config`
deletes the file (see [Purge](#purge-gateinto-reset---purge-device-identity)); on Linux `reset`
deletes nothing (see [`reset` on Linux](#reset-on-linux)).

Gateways that the user approved from a `gateinto://` link are kept separately in the `gateways`
folder next to the default config file, one file per gateway
(`%APPDATA%\Gateinto\gateways\proxy.corp.example.toml` on Windows,
`~/.config/gateinto/gateways/proxy.corp.example.toml` or the `gateinto/gateways` directory under
`$XDG_CONFIG_HOME` on Linux), also when `--config` names another file. Gateinto writes only that
file, never the config file; on a name collision the config file wins. `gateinto gateway list`
shows every gateway with its default route and source and `gateinto gateway forget <name>`
removes one added from a link. See
[protocol/launch-uri.md](protocol/launch-uri.md#linked-gateways).

## Where settings are stored

- The config file (above) holds the gateways and the `[limits]`, `[browser]` and
  `[device_key]` settings. The agent reads it when it starts. The GUI only reads it and opens
  it in the system's editor on request; it never writes it.
- The GUI's own preferences are stored per user as the values `Theme` and `Language` in
  `HKCU\Software\Gateinto\App`. They apply when chosen in Settings and do not involve the agent.
- **Start the app at sign-in** is the GUI's value `Gateinto App` in
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. The agent's own start at sign-in is the
  installer's value `Gateinto` in the same key (see [Install](#install)); the GUI only reads it
  and never writes it.

On Linux there is no GUI and no registry. Each `XDG_*` variable below is used only when it is an
absolute path; otherwise the default under `~` applies:

- the config file and the linked gateways, in `$XDG_CONFIG_HOME/gateinto/` (default
  `~/.config/gateinto/`), as above;
- the `gateinto://` handler: the desktop file `$XDG_DATA_HOME/applications/gateinto.desktop`
  (default `~/.local/share/applications/gateinto.desktop`) and the line
  `x-scheme-handler/gateinto=gateinto.desktop` under `[Default Applications]` in
  `$XDG_CONFIG_HOME/mimeapps.list` (default `~/.config/mimeapps.list`); see
  [`uri register` on Linux](#uri-register-and-uri-unregister-on-linux);
- the browser profiles of the agent's sessions, in `$XDG_STATE_HOME/gateinto/profiles/` (default
  `~/.local/state/gateinto/profiles/`), deleted when their session closes;
- the agent's socket, `$XDG_RUNTIME_DIR/gateinto/agent.sock`, or
  `~/.local/state/gateinto/agent.sock` when `XDG_RUNTIME_DIR` is not an absolute path;
- the optional user unit, `~/.config/systemd/user/gateinto-agent.service`, only when you copied
  it there (see [Optional user unit](#optional-user-unit)).

## Status: `gateinto status`

```powershell
gateinto status
```

`status` changes nothing: it never creates a key, starts an agent or writes the registry. It
prints only non-secret information:

```text
key-name: gateinto-device-v1
device-key: present
provider: Microsoft Platform Crypto Provider
spki-sha256: 3f0c…
config: C:\Users\me\AppData\Roaming\Gateinto\gateinto.toml (default location)
gateway: office: proxy.example.com:443, route mixed (config)
linked-gateways: C:\Users\me\AppData\Roaming\Gateinto\gateways
gateway: corp: proxy.corp.example:443, route mixed (linked)
agent: running
session: 2 browser office 127.0.0.1:50123
uri-handler: gateinto: "C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" open -- "%1"
```

`device-key` is `present`, `absent`, `unavailable` (not Windows; on Linux `unavailable: no device key backend on Linux; connections are unauthenticated`) or `error: …`. Gateways show
only name, host, port, default route (`mixed`, the default, or `gateway`) and source (`config` or `linked`); CA files, certificate files, portal
URLs and credentials are not printed. `gateinto gateway list` adds each portal's origin, never
its path or query. Sessions come from the running agent, the same lines as `gateinto session list`.
`uri-handler` is `not registered`, `gateinto: <command>` or `another program: <command>`.
On Linux, `status` also prints `uri-handler-warning` when Gateinto's desktop file is installed
but another installed default overrides it or no installed default is found,
`terminal-sessions: not supported on Linux yet`, `terminal-containment` (`available` when every
containment prerequisite of terminal sessions is present, otherwise `unavailable: <the first
missing one>`; see [design/linux-support.md](design/linux-support.md#area-3-session-containment))
and `os-user` (whether `pidfd_open` works on this kernel). See [`setup` on Linux](#setup-on-linux).

On Linux, `status` writes no file either. Output after `install.sh` (example; `terminal-containment`
depends on the system):

```text
key-name: gateinto-device-v1
device-key: unavailable: no device key backend on Linux; connections are unauthenticated
config: /home/me/.config/gateinto/gateinto.toml (default location)
gateway: office: proxy.example.com:443, route mixed (config)
linked-gateways: none (no directory at /home/me/.config/gateinto/gateways)
agent: not running
uri-handler: gateinto: "/home/me/.local/bin/gateinto" open -- %u
terminal-sessions: not supported on Linux yet
terminal-containment: unavailable: terminal sessions need the cgroup v2 hierarchy mounted at /sys/fs/cgroup
os-user: not offered by any session on Linux yet; pidfd_open is available
```

## Uninstall

On Linux, run `uninstall.sh` from the tarball instead; see
[Uninstall on Linux](#uninstall-on-linux). On Windows, use Settings → Apps → Installed apps →
Gateinto → Uninstall, or:

```powershell
msiexec /x gateinto.msi /qn
```

| Resource | Default uninstall |
|---|---|
| `gateinto.exe` | removed |
| `gateinto-gui.exe` and the **Gateinto** Start Menu shortcut | removed |
| Install folder in the user `PATH` | removed |
| `gateinto://` handler (`HKCU\Software\Classes\gateinto`) | removed |
| Logon autostart entry created by the installer | removed |
| Uninstall entry | removed |
| Running agent, its listeners, tunnels and sessions | closed (see below) |
| Gateinto browser profiles in `%LOCALAPPDATA%\Gateinto\profiles` | deleted |
| Device key | **kept** |
| Config file(s), including `%APPDATA%\Gateinto\gateinto.toml`, also when the installer created it | **kept** (by design for the template, not yet verified on Windows) |
| The installer's `ConfigTemplate` marker in `HKCU\Software\Gateinto\Installer` | **kept** (by design, not yet verified on Windows) |
| Gateways added from links, `%APPDATA%\Gateinto\gateways\*.toml` | **kept** |
| The user's own Chrome and Edge profiles, other programs' keys | never touched |

Before files are removed, the uninstaller runs `gateinto.exe stop --remove-stale-profiles` as
the installing user. A running agent closes every session, ends their browsers, deletes their
profiles and exits; `stop` waits up to 15 seconds until the agent process has exited, so
`gateinto.exe` is no longer in use when Windows Installer removes it. Then the Gateinto-marked profile directories left by a crashed agent are
deleted. A profile still held open by a running browser cannot be deleted and is left in
place. The step's failure does not stop the uninstall, for example when no agent is running.
Only directories that Gateinto created and marked are deleted.

During an interactive uninstall a console window may flash briefly while `gateinto.exe stop`
runs, because `gateinto.exe` is a console program. A major upgrade (installing a newer MSI over
an older one) runs the same step for the old version: it stops a running agent and does not
start it again. The next `gateinto://` link or `gateinto agent --detach` starts a new one.

Also before files are removed, the uninstaller runs `gateinto-gui.exe --uninstall` as the
installing user. It looks for windows of the GUI's own window classes (`GateintoWindow` and
the demo's `GateintoDemoWindow`) that belong to a process of the same user and the same
`gateinto-gui.exe` file, posts each a private exit message that closes it like **Exit** in the
tray menu (also when it would hide to the tray), and waits at most 5 seconds for those
processes to end. Secrets the window held are cleared as on any other exit. It then deletes
the GUI's `Gateinto App` value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` only
if that value is a plain string that runs exactly the installed `gateinto-gui.exe` (the path is
compared without regard to case), and in that case also the `Gateinto App` value under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`, where Task
Manager records whether the entry is turned off. A value that points at another copy, has
another type or cannot be read is left in place, and so is every other value, including the
installer's `Gateinto` value and its StartupApproved entry. A GUI that does not close in time
is not ended by force; Windows Installer may then need a restart to remove the file. The step's
failure does not stop the uninstall. An interactive uninstall may still ask to close the GUI
before this step runs; this is not tested.

A major upgrade removes the old version with `gateinto-gui.exe --quit` instead: it closes
the GUI the same way but keeps the `Gateinto App` value and its StartupApproved entry, so
**Start the app at sign-in** stays on. Only an old version that already has this step runs
it during an upgrade. Installing never runs the GUI.

An uninstall does not revoke anything and does not delete the device identity.

## Reinstall

On Linux, see [Upgrade and reinstall on Linux](#upgrade-and-reinstall-on-linux). On Windows,
install the MSI again and run `gateinto setup`. It finds the kept key, prints
`device-key: reused` and the same `spki-sha256`, so gateways that know the device still
recognise it. A reinstall never creates a new device ID. A new identity is only created after a
purge.

## Purge: `gateinto reset --purge-device-identity`

Purging deletes the device identity permanently. It is never part of an uninstall, silent or
interactive. To purge, run `reset` before uninstalling, or afterwards from any copy of
`gateinto.exe`:

```powershell
gateinto reset --purge-device-identity
```

`reset` first shows what it deletes and what that means:

```text
This permanently deletes the Gateinto device key:
  provider: Microsoft Software Key Storage Provider
  key name: gateinto-device-v1 (current Windows user)
  spki-sha256: 3f0c…

- The device identity becomes invalid. Gateways that enrolled this key will not recognise the device; a new key may need to be enrolled again.
- Deleting the key locally does NOT revoke the device at any gateway. Ask the gateway operator to revoke it.
- The key cannot be recovered. No other key, provider or TPM is changed.
- The gateinto:// handler stays registered; use the installer or `gateinto uri unregister` to remove it.

Type the first 16 characters of the spki-sha256 above to delete the key:
```

It deletes the key only if the typed text is at least the first 16 hex digits of that
`spki-sha256`. For scripts, pass the confirmation instead:

```powershell
gateinto reset --purge-device-identity --confirm-spki 3f0c1a2b4c5d6e7f
```

Rules:

- `--confirm-spki` takes 16 to 64 hex digits that must be a prefix of the key's `spki-sha256`;
  anything else is refused and nothing is deleted. Without `--confirm-spki` and without a
  terminal on stdin, `reset` refuses before it opens any key.
- `reset` stops a running agent first (`stop`), so sessions close and their profiles are
  deleted, and waits up to 15 seconds until the agent process has exited. If the agent cannot
  be stopped or does not exit in time, nothing is deleted.
- It deletes only the key named `[device_key] name` (or `--name`), in the current user's scope.
  It opens that key in its provider with `NCryptOpenKey`, checks its SPKI against the
  confirmation again and deletes that handle with `NCryptDeleteKey`. It never deletes other
  keys, never clears a key storage provider and never clears or resets the TPM. If keys with the
  name exist in both providers, it refuses and deletes neither.
- `--purge-config` also deletes the config file, the one named with `--config` or
  `%APPDATA%\Gateinto\gateinto.toml`, and the gateways added from links,
  the regular `*.toml` files in `%APPDATA%\Gateinto\gateways\`, then that folder if it is
  empty. The config file must be a regular file that parses as a Gateinto config; links and
  reparse points are never followed, and nothing is deleted recursively. Both are named in the
  warning and covered by the same confirmation.
  If neither exists, `reset` refuses and deletes nothing.
- When no device key exists, `--purge-config` still deletes these files. There is no SPKI to
  confirm then, so `reset` prints that no key was deleted and asks you to type `purge`, or
  takes `--yes` instead of the prompt. `--yes` only works together with `--purge-config` and
  never replaces the SPKI confirmation of an existing key.
- `reset` does not unregister the `gateinto://` handler. The uninstaller removes it, or
  `gateinto uri unregister` for a development registration.
- After a purge, `gateinto setup` creates a new key with a new `spki-sha256`. That is a new
  device identity, which gateways have to enroll again.

### `reset` on Linux

Linux has no device key, so there is no device identity to purge. `reset` on Linux deletes
nothing, does not stop the agent and exits nonzero, also with `--purge-config`. It first makes
the same checks as on Windows: without `--confirm-spki`, `--yes` or a terminal it refuses as
above, and with `--purge-config` it refuses when neither a config file nor linked gateways
exist. Then it fails with `error: device keys are only supported on Windows`, before it would
stop the agent or delete any file.

To remove the configuration on Linux, delete it yourself: the config file and the `gateways`
directory in `~/.config/gateinto/` (or `$XDG_CONFIG_HOME/gateinto/`). `uninstall.sh` keeps them
(see [Uninstall on Linux](#uninstall-on-linux)).

## Development: `gateinto uri register`

On Windows, `gateinto uri register [--config <file>]` writes the same per-user handler as the
MSI for the `gateinto.exe` it is run from, and `gateinto uri unregister` removes it; both are for
development without the MSI. They refuse to change a handler that is not Gateinto's, and
they recognise the MSI's handler as Gateinto's. Registering after installing replaces the MSI's
command until the next uninstall or repair.

### `uri register` and `uri unregister` on Linux

On Linux, `install.sh` runs `uri register` and `uninstall.sh` runs `uri unregister`; run them
yourself only for a copy of `gateinto` that you did not install with `install.sh`. The handler
command is `"<absolute path of the executable>" open -- %u`, with `--config "<file>"` before
`--` when `--config` is given (a relative path is made absolute, and the file must parse). The
executable must be named `gateinto`, and neither path may contain quotes, backticks, dollar
signs, backslashes, percent signs or control characters; otherwise nothing is written.

`uri register` writes two files, creating any missing directory on the way to them with mode
`0700`:

- the desktop file `$XDG_DATA_HOME/applications/gateinto.desktop` (default
  `~/.local/share/applications/gateinto.desktop`), with mode `0600`:

  ```ini
  [Desktop Entry]
  Type=Application
  Name=Gateinto
  Exec="/home/me/.local/bin/gateinto" open -- %u
  NoDisplay=true
  MimeType=x-scheme-handler/gateinto;
  X-Gateinto-Handler=1
  ```

- the default `x-scheme-handler/gateinto=gateinto.desktop` in the `[Default Applications]`
  section of `$XDG_CONFIG_HOME/mimeapps.list` (default `~/.config/mimeapps.list`). Every other
  line of the file is kept; the section is added when it is missing, a new file gets mode
  `0644`, and an existing file keeps its mode.

It refuses, and changes nothing, when `gateinto.desktop` exists but is not Gateinto's handler
entry, when that `mimeapps.list` names another desktop file as the default for
`x-scheme-handler/gateinto`, when either file is a symbolic link or not a regular file, and when
the home directory (or `$XDG_CONFIG_HOME` or `$XDG_DATA_HOME` when it is outside the home
directory), or a directory below it on the way to either file, is owned by another user, as under
`sudo` with the caller's `HOME`. It warns on stderr when run as root. An unset, empty or
relative `XDG_CONFIG_HOME` or `XDG_DATA_HOME` is ignored, and `~/.config` or `~/.local/share`
is used instead. When another default
takes precedence, for example in `$XDG_CONFIG_HOME/<desktop>-mimeapps.list` for a desktop
named in `XDG_CURRENT_DESKTOP`, `uri register` still succeeds and prints
`warning: … sets "<id>" as the default for x-scheme-handler/gateinto, so gateinto:// links may
open that application instead of Gateinto`, and `status` shows the same text as
`uri-handler-warning`. Gateinto does not lock `mimeapps.list`: a desktop tool that writes it at
the same moment can lose its change or Gateinto's.

`uri unregister` removes the `x-scheme-handler/gateinto` line from that `mimeapps.list` and the
desktop file, and prints `removed the gateinto:// handler of the current user`, or `no
gateinto:// handler is registered for the current user` when there is nothing to remove. It
keeps the rest of `mimeapps.list`, including a `[Default Applications]` header that `register`
added, and it refuses the same foreign entries as `register`.

Not verified: that a `gateinto://` link clicked in Firefox, Chrome or Chromium on a real GNOME
or KDE desktop opens Gateinto, that `NoDisplay=true` keeps the entry out of menus while still
handling the scheme, and Snap and Flatpak browsers, which go through the desktop portal. CI
checks the files and, where `gio` is installed, that `gio` reads the default
([design/linux-support.md](design/linux-support.md#area-1-gateinto-handler)).

## Linux tarball

Not yet verified on a real Linux desktop. Linux has no device key yet, so Gateinto connects from
Linux without a device certificate. No distribution package exists; the tarball is the only
Linux release file.

The release build needs glibc 2.38 or newer on x86_64. It is built on Ubuntu 24.04 (glibc
2.39). This was measured with `objdump -T` and `readelf -V` on a release build made locally on
Ubuntu 24.04: the newest glibc symbol version it requires is `GLIBC_2.38` (`__isoc23_strtol`,
`__isoc23_sscanf`), and its `GLIBC_2.39` symbols (`pidfd_spawnp`, `pidfd_getpid`) are weak, so
the dynamic loader does not require them. It has not been run on any system with an older glibc
or on any other distribution.

Download the tarball and its `.sha256`, verify it, extract it into a new, empty directory and run
`install.sh` there, as the user who uses Gateinto, not as root and not through `sudo`:

```sh
gh release download latest --repo lukeo3o1/gateinto-dev --pattern 'gateinto-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c gateinto-x86_64-unknown-linux-gnu.tar.gz.sha256 &&
  mkdir gateinto-tarball &&
  tar -xzf gateinto-x86_64-unknown-linux-gnu.tar.gz -C gateinto-tarball --strip-components=1 &&
  cd gateinto-tarball &&
  ./install.sh
```

Do not use the tarball if `sha256sum -c` does not print `OK`. The commands are chained with `&&`,
so they stop at the first failure: nothing is extracted or run when the checksum does not match,
and nothing is extracted into or run from an existing `gateinto-tarball`, because `mkdir` then
fails. Files of an earlier tarball are therefore not mixed in by these commands. The tarball
holds one directory with the commit in its name, `gateinto-<commit>-x86_64-unknown-linux-gnu/`,
with `gateinto`, `install.sh`, `uninstall.sh`, the optional systemd user unit
`gateinto-agent.service`, a `README` and the license files;
`--strip-components=1` puts them directly in `gateinto-tarball`. No script is published for
piping into a shell.

`install.sh` copies `gateinto` to `~/.local/bin/gateinto`, creating `~/.local/bin` (mode
`0755`) if needed and replacing an earlier copy, runs `~/.local/bin/gateinto uri register` and
warns when `~/.local/bin` is not on `PATH`. It creates no device key and writes no
configuration; the handler it registers passes no `--config`, so Gateinto reads the
[default config file](#config-file-location). What `uri register` writes is described in
[`uri register` on Linux](#uri-register-and-uri-unregister-on-linux).

`install.sh` takes no arguments. It refuses to run as root, and refuses when `HOME` is not an
absolute path to an existing directory, when no `gateinto` is next to it, or when
`~/.local/bin/gateinto` is a directory or a symbolic link to one. It writes the new binary to a
temporary file in `~/.local/bin` and renames it over `~/.local/bin/gateinto`. If `uri register`
fails, for example because `~/.config/mimeapps.list` names another desktop file as the
`gateinto://` default or the home directory's path contains a character refused there, the
binary stays installed and `install.sh` exits with an error; fix the cause and run it again.

### Optional user unit

`gateinto-agent.service` runs `~/.local/bin/gateinto agent` as a systemd user service while a
graphical session is running (`graphical-session.target`). `install.sh` does not install or
enable it; to use it, from `gateinto-tarball`:

```sh
mkdir -p ~/.config/systemd/user &&
  cp gateinto-agent.service ~/.config/systemd/user/ &&
  systemctl --user enable --now gateinto-agent
```

Only one agent runs per user: if one started on demand is already running, run `gateinto stop`
first (it ends that agent's sessions and their browsers), or the unit's agent fails, is retried
until the start limit and the unit stays failed until it is started again, for example at the
next login, although `enable --now` reported success.

Desktops that do not start `graphical-session.target` never start the unit; the agent then
starts on demand as without it. Stopping the unit ends the browsers the agent started, as
`gateinto stop` does. The unit carries no credentials and does not set `NoNewPrivileges`, which
browsers would inherit. After an upgrade, `systemctl --user restart gateinto-agent` runs the new
binary. Not yet verified on a real desktop.

To stop using the unit without uninstalling Gateinto:

```sh
systemctl --user disable --now gateinto-agent &&
  rm ~/.config/systemd/user/gateinto-agent.service
```

### Upgrade and reinstall on Linux

To upgrade, download, verify and extract the newer tarball into a new, empty directory as above
and run its `install.sh`. It replaces `~/.local/bin/gateinto` by renaming the new file over it
and registers the handler again for the same path, rewriting the desktop file. The config
file and the linked gateways are kept. `install.sh` does not stop a running agent, which keeps
running the earlier binary: without the unit, run `gateinto stop` (it ends the agent's sessions
and their browsers), and the next `gateinto://` link starts the new binary; with the unit, run
`systemctl --user restart gateinto-agent`. Installing again after `uninstall.sh` works the same
way and finds the kept config file and linked gateways. There is no device identity on Linux to
keep or recreate. Upgrades are not yet verified on a real desktop.

### Uninstall on Linux

Run `uninstall.sh` in the directory the tarball was extracted to, as the user who installed
Gateinto, not as root and not through `sudo`:

```sh
cd gateinto-tarball && ./uninstall.sh
```

| Resource | `uninstall.sh` |
|---|---|
| `~/.local/bin/gateinto` | removed |
| `gateinto.desktop` in `~/.local/share/applications` (or `$XDG_DATA_HOME/applications`) | removed |
| The line `x-scheme-handler/gateinto=gateinto.desktop` in `~/.config/mimeapps.list` (or `$XDG_CONFIG_HOME/mimeapps.list`) | removed; the file, its other lines and a `[Default Applications]` header that `install.sh` added are kept |
| The user unit `~/.config/systemd/user/gateinto-agent.service` and its enablement | disabled and stopped when `systemctl` is on `PATH`, then the unit file is removed; without `systemctl` only the unit file is removed |
| Running agent, its listeners, tunnels and sessions, and the browsers it started | closed (see below) |
| Gateinto browser profiles in `~/.local/state/gateinto/profiles` (or `$XDG_STATE_HOME/gateinto/profiles`) | deleted; the directory itself is kept |
| Device key | none on Linux |
| Config file `~/.config/gateinto/gateinto.toml` (or under `$XDG_CONFIG_HOME`) | **kept** |
| Gateways added from links, `~/.config/gateinto/gateways/*.toml` (or under `$XDG_CONFIG_HOME`) | **kept** |
| `~/.local/bin` and `PATH` | not changed |
| The user's own Chrome, Chromium, Edge and Firefox profiles, other programs' desktop files and `mimeapps.list` entries | never touched |

`uninstall.sh` works in this order and stops at the first failure:

1. It refuses any argument, to run as root, and a `HOME` that is not an absolute path to an
   existing directory.
2. If `~/.local/bin/gateinto` does not exist, it prints that Gateinto is not installed and exits
   successfully without changing anything: the unit file, `gateinto.desktop` and the
   `mimeapps.list` line stay too. To remove them, run `install.sh` from the tarball again and
   then `uninstall.sh`, or remove them by hand: the unit as shown in
   [Optional user unit](#optional-user-unit), the handler files as listed in
   [`uri register` on Linux](#uri-register-and-uri-unregister-on-linux). If
   `~/.local/bin/gateinto` is a symbolic link to a missing file, it exits with an error and asks
   you to remove it by hand.
3. If `~/.config/systemd/user/gateinto-agent.service` is a symbolic link to a missing file, it
   exits with an error without changing anything (see below).
4. If `readlink` is not on `PATH` or cannot read `/proc/<pid>/exe`, for example without
   `/proc`, it exits with an error without changing anything.
5. If `~/.config/systemd/user/gateinto-agent.service` exists and `systemctl` is on `PATH`, it
   runs `systemctl --user disable --now gateinto-agent.service`.
6. It runs `~/.local/bin/gateinto stop`, which stops a running agent that it can reach, with
   its sessions and their browsers, and waits up to 15 seconds for the agent to exit. A failure
   here, such as no agent running, does not stop the uninstall, and its error message is shown
   only if step 7 refuses. When this step stops an agent it prints
   `stopped the agent (process N)`, and step 8 then prints `no agent is running`, because that
   agent is gone.
7. If a process of yours still runs `~/.local/bin/gateinto`, or the earlier binary that
   `install.sh` replaced at that path, it prints the error message of step 6, if there was one,
   and exits with an error before deleting browser profiles, unregistering the handler or
   removing the unit file and the binary (see below). A unit was already disabled and stopped
   in step 5.
8. It runs `~/.local/bin/gateinto stop --remove-stale-profiles`, which deletes the
   Gateinto-marked browser profiles left behind. Only directories that Gateinto created and
   marked are deleted.
9. It runs `~/.local/bin/gateinto uri unregister`.
10. If there is a unit file, it removes it and, when `systemctl` is on `PATH`, runs
    `systemctl --user daemon-reload` (a failure there only prints a warning); then it removes
    `~/.local/bin/gateinto`.

If step 5, 8 or 9 fails, it keeps the binary and exits with an error, so it can be run again
after fixing the cause. A failure in step 9 comes after step 8, so the agent is already
stopped; `uri unregister` fails, for example, when `gateinto.desktop` or the `mimeapps.list`
default was changed to another program, which it leaves for you to remove. At the end it says
that it kept the configuration and the gateways added from links in the `gateinto` directory
under `XDG_CONFIG_HOME` (by default `~/.config/gateinto`).

Run `uninstall.sh` from your own login session. With the unit installed, under `su -`,
`sudo -u` or without a user manager, `systemctl --user disable --now` fails to reach your user
manager (the enablement link may already be gone) and `uninstall.sh` stops. Without the unit,
`gateinto stop` finds the agent only through `$XDG_RUNTIME_DIR/gateinto/agent.sock`, or
`~/.local/state/gateinto/agent.sock` when `XDG_RUNTIME_DIR` is not an absolute path. Where
`XDG_RUNTIME_DIR` differs from the agent's, as under `su -` without a session from
`pam_systemd`, it cannot reach the agent. If that agent runs `~/.local/bin/gateinto`, or the
earlier binary that `install.sh` replaced there, `uninstall.sh` finds its process through
`/proc/<pid>/exe` and refuses as in step 7, with
`a gateinto process is still running from ~/.local/bin/gateinto after "gateinto stop"`; stop
the agent from the session that started it, for example with `gateinto stop` there, and run
`uninstall.sh` again. It refuses the same way while any other `gateinto` command started from
that path still runs. The check compares paths and sees only the processes of the same user in
the same PID namespace. It misses an agent started from another path (a build tree, a copy or a
hard link), an agent started through `~/.local/bin/gateinto` when that is itself a symbolic
link (`install.sh` replaces such a link with a file, so only a manual setup has one), and an
agent in another PID namespace, such as a container. If such an agent is out of reach of
`gateinto stop`, `uninstall.sh` goes on: it deletes the profiles of the agent's open browser
sessions and removes `~/.local/bin/gateinto` while the agent keeps running.

If the unit file is a symbolic link to a missing file, as `systemctl --user link` leaves after
the linked file is deleted, `uninstall.sh` changes nothing and asks you to run
`systemctl --user stop gateinto-agent` if it is running, to remove by hand that link and, if
present, `~/.config/systemd/user/graphical-session.target.wants/gateinto-agent.service`, and to
run it again.

An uninstall removes nothing else; it also keeps the directories that `install.sh` and
`uri register` created, such as `~/.local/bin` and `~/.local/share/applications`. To remove the
configuration too, see [`reset` on Linux](#reset-on-linux).

## Verification

The CI job `msi` on `windows-latest` (once for an x64 MSI with the x64 release build, and once
for an x86 MSI with the i686 debug build under WOW64), and the `msi` jobs of the compatibility
workflow on `windows-2022` and `windows-2025` (weekly and manual runs), build the MSI
and run
[.github/scripts/msi-lifecycle.ps1](../.github/scripts/msi-lifecycle.ps1), which checks the
following with the Microsoft Software Key Storage Provider (the runners have no TPM):

- a silent per-user install writes the exe, the GUI next to it, the **Gateinto** Start Menu
  shortcut pointing at the GUI, the user `PATH` entry, the exact handler command and the
  uninstall entry, starts no `gateinto.exe` or `gateinto-gui.exe` process, writes no
  `Gateinto App` Run value, and creates no device key (`key info` fails until `setup` runs);
- the first `setup` creates a key;
- a silent uninstall with a running agent stops the agent and removes the exe, the GUI, the
  shortcut and the handler,
  while `key info`, run from a copy outside the install folder, still shows the same SPKI; the
  GUI was started before it and `Gateinto App` was set to the installed GUI with a
  StartupApproved entry, and the uninstall closes the GUI and removes both values but keeps an
  unrelated Run value; if the runner shows no GUI window, only the values are checked, with a
  warning;
- after a reinstall with `AUTOSTART=1`, the Run value is exactly
  `"…\gateinto.exe" agent --detach`, the GUI and the shortcut are back, and `setup` reuses the
  key with the same SPKI; the uninstall after the purge below removes the Run value, the GUI and
  the shortcut, and keeps a `Gateinto App` value that points at another copy, its
  StartupApproved entry and the StartupApproved entry of the agent's `Gateinto` value;
- `reset` refuses a wrong prefix and a missing confirmation, deletes the key with the right
  prefix, keeps the handler, and the next `setup` creates a different SPKI;
- the script also checks the config template: the first install creates
  `%APPDATA%\Gateinto\gateinto.toml` with exactly the template's content; the file is then
  edited with its write time set back to its creation time, and a forced repair
  (`msiexec /fa`), a default repair (`msiexec /f`), a same-version major upgrade to a second
  build and back, both uninstalls, the reinstall and another `msiexec /fa` keep the edited
  content. These checks were added after the
  last recorded CI run and have not run on Windows yet. A unit test checks that the template
  parses to the built-in defaults and comments out every setting of `config.example.toml`.

For manual testing, CI runs on a push to `master` and on pull requests, unless they change only
Markdown or `docs/` files other than `README.md` and `docs/quickstart.md`; when the x64
lifecycle check passes, the run keeps the MSI it installed as the `gateinto-msi-x64` artifact for
14 days. It is not a release: it is built
from the CI release build without `-Version`, so it has the `Cargo.toml` version like a
[local build](#releases), and it is not signed.

Not verified: TPM keys, interactive install and uninstall, Windows 10 and 11 client editions (the
runners are Windows Server), a `gateinto://` link clicked in a real browser, opening the GUI from
the Start Menu shortcut, closing the GUI during an interactive uninstall or an upgrade, and
keeping `Gateinto App` across an upgrade between two versions. The checks that close the GUI and
remove or keep `Gateinto App` on uninstall passed in CI for x64 and x86; closing the GUI was
confirmed in the x64 log, the x86 log was not checked for it. See
[verification.md](verification.md).

### Linux

On `ubuntu-latest`, the CI `check` job builds the debug `gateinto`, packs it into a tarball with
[.github/scripts/linux-tarball.sh](../.github/scripts/linux-tarball.sh) and runs
[.github/scripts/linux-install-check.sh](../.github/scripts/linux-install-check.sh) on it. In a
temporary home directory, with `env -i` and only `HOME` and `PATH` set, that script:

- runs `install.sh`;
- checks the user unit with `systemd-analyze --user verify` against the installed binary, with a
  temporary `XDG_RUNTIME_DIR` set for that check only;
- runs `~/.local/bin/gateinto status` and requires exactly the line
  `uri-handler: gateinto: "<home>/.local/bin/gateinto" open -- %u`;
- runs `uninstall.sh` and checks that `~/.local/bin/gateinto` and
  `~/.local/share/applications/gateinto.desktop` are gone.

It does not check that the `mimeapps.list` line is removed, does not install or start the unit,
and starts no agent or browser. The `release-scripts` job runs `shellcheck` on
`packaging/linux/*.sh` and runs
[.github/scripts/release-test.sh](../.github/scripts/release-test.sh), which runs `install.sh`
and `uninstall.sh` against a stub `gateinto` and a stub `systemctl`, with and without the unit,
including failures of each step, a unit that is a symbolic link to a missing file, a process of
the user still running `~/.local/bin/gateinto` (as a copy of `sleep`, also after the stub was
renamed over it) that `gateinto stop` cannot reach, a missing `readlink` or one that cannot
read `/proc` and, where root or passwordless `sudo` is available, the refusal to run as root.
No test runs a real agent that `gateinto stop` cannot reach. The registration code is covered
by unit tests and by `tests/uri_registration_linux.rs`, which registers and unregisters a test
scheme in a temporary home directory and checks the desktop file and the `mimeapps.list`
contents. The `linux` job of the release workflow runs the same install check on the release
tarball on `ubuntu-24.04` before publishing; it has not run yet (see
[verification.md](verification.md)).

Not verified: anything on a real Linux desktop, including install, upgrade and uninstall,
a `gateinto://` link clicked in a real browser, Snap and Flatpak browsers, the unit starting with
the graphical session and stopping its browsers, and `systemctl --user disable --now` against a
real user manager. Linux has no device key, so no TPM or device certificate behaviour exists to
verify.
