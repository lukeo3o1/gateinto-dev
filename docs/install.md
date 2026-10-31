# Installing, uninstalling and resetting Gateinto

This page covers the Windows installer and the commands that manage the device identity across
installs: `gateinto setup`, `gateinto status` and `gateinto reset`. The MSI is built from
[packaging/wix](../packaging/wix/README.md).

No WinGet package exists. `winget install` and `winget uninstall` do not install or remove
Gateinto; [packaging/winget](../packaging/winget/README.md) only holds unsubmitted manifest
templates. To build the MSI yourself, use `packaging/wix/build.ps1` as described in
[packaging/wix](../packaging/wix/README.md#build).

## Releases

The repository is private, so its GitHub Releases are for the owner's own downloads; nothing is
published for anyone else. There are exactly three releases, one per channel, each with a tag of
the same name that points at the commit it was built from:

| Channel | Published | Marked on GitHub |
| --- | --- | --- |
| `alpha` | automatically, after CI passes on a push to `master` and the release workflow's own build and tests pass | prerelease |
| `beta` | by hand: Actions → Release → Run workflow, channel `beta`, and a full commit SHA (recommended), branch or tag (default `master`) | prerelease |
| `latest` | by hand, the same way with channel `latest` | latest release |

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
release channels were added cannot be published.

The release title and notes name the channel, the full commit SHA and the build date, followed
by a notice that the files are not code-signed, that TPM keys, real browsers, physical Windows
machines and Windows 7 are not yet verified on real hardware
([#23](https://github.com/lukeo3o1/gateinto-dev/issues/23)), and, for `alpha` and `beta`, that
the Windows 7 build is experimental and can use only the Microsoft Software Key Storage
Provider.

Each file is attached twice: with the first 12 characters of the commit in its name, and as a
copy without it. The copy keeps the same download URL from one publish to the next:

| File without the commit | `latest` | `alpha`, `beta` |
| --- | --- | --- |
| `gateinto-x86_64-pc-windows-msvc.exe`, Windows 10/11 x64 | yes | yes |
| `gateinto-x86_64-pc-windows-msvc.msi`, the per-user installer below, 64-bit | yes | yes |
| `gateinto-i686-pc-windows-msvc.exe`, 32-bit Windows 10 | yes | yes |
| `gateinto-i686-pc-windows-msvc.msi`, the per-user installer below, 32-bit (x86) | yes | yes |
| `gateinto-i686-win7-windows-msvc-experimental.exe` | no | yes |

Each file has a `.sha256` next to it, one line with the lowercase SHA-256, two spaces and the
file name. The names with the commit are `gateinto-<commit>-<target>.exe` and so on, for
example `gateinto-0123456789ab-x86_64-pc-windows-msvc.exe`. The stable URLs are

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
GUI is not part of the experimental Windows 7 build and has no Windows 7 version. CI
runs it only under WOW64 on 64-bit Windows Server; it has not been tested on a real 32-bit
Windows 10 installation, and it is untested on Windows 7, where that executable does not start.

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
- the uninstall entry under Settings → Apps → Installed apps, written by Windows Installer.

The package creates no other shortcuts. Installing starts neither the GUI nor the agent, and does
not write the GUI's own `Gateinto App` value in the Run key (the GUI's **Start the app at
sign-in** switch); only that switch writes it. A full uninstall removes it (see below). The package does not create a device key or a
config file, and none of its custom actions creates a key: the installer never creates a key as
`SYSTEM` or as an elevated installer account. Windows Installer runs a per-user package as the
installing user.

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
   prints its path and each gateway as `gateway: <name>: <host>:<port> (config)`, then the
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
gateway: office: proxy.example.com:443 (config)
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

## Config file location

Without `--config`, every command reads `%APPDATA%\Gateinto\gateinto.toml` when that file
exists (`$XDG_CONFIG_HOME/gateinto/gateinto.toml`, or `~/.config/gateinto/gateinto.toml`, on
Linux for development). The installed handler and the autostart entry pass no `--config`, so
this is where an installed Gateinto finds its gateways. The installer does not create or remove
this file.

Gateways that the user approved from a `gateinto://` link are kept separately in
the `gateways` folder next to it, one file per gateway (`%APPDATA%\Gateinto\gateways\proxy.corp.example.toml`), also when
`--config` names another file. Gateinto writes only that file, never the config file; on a name
collision the config file wins. `gateinto gateway list` shows every gateway with its source and
`gateinto gateway forget <name>` removes one added from a link. See
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
gateway: office: proxy.example.com:443 (config)
linked-gateways: C:\Users\me\AppData\Roaming\Gateinto\gateways
gateway: corp: proxy.corp.example:443 (linked)
agent: running
session: 2 browser office 127.0.0.1:50123
uri-handler: gateinto: "C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" open -- "%1"
```

`device-key` is `present`, `absent`, `unavailable` (not Windows) or `error: …`. Gateways show
only name, host, port and source (`config` or `linked`); CA files, certificate files, portal
URLs and credentials are not printed. `gateinto gateway list` adds each portal's origin, never
its path or query. Sessions come from the running agent, the same lines as `gateinto session list`.
`uri-handler` is `not registered`, `gateinto: <command>` or `another program: <command>`.

## Uninstall

Use Settings → Apps → Installed apps → Gateinto → Uninstall, or:

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
| Config file(s), including `%APPDATA%\Gateinto\gateinto.toml` | **kept** |
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

Install the MSI again and run `gateinto setup`. It finds the kept key, prints
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

## Development: `gateinto uri register`

`gateinto uri register [--config <file>]` writes the same per-user handler for the
`gateinto.exe` it is run from, and `gateinto uri unregister` removes it. Both are for
development without the MSI. They refuse to change a handler that is not Gateinto's, and
they recognise the MSI's handler as Gateinto's. Registering after installing replaces the MSI's
command until the next uninstall or repair.

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
  prefix, keeps the handler, and the next `setup` creates a different SPKI.

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
