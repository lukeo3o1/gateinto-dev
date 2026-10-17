# Installing, uninstalling and resetting Gateinto

This page covers the Windows installer and the commands that manage the device identity across
installs: `gateinto setup`, `gateinto status` and `gateinto reset`. The MSI is built from
[packaging/wix](../packaging/wix/README.md).

No WinGet package exists. `winget install` and `winget uninstall` do not install or remove
Gateinto. Each release attaches `gateinto-<tag>-x86_64-pc-windows-msvc.msi` and its `.sha256`
next to the zip (see the [quickstart](quickstart.md#from-a-github-release)); the MSI is not inside
the zip. The MSI is x64 only; the 32-bit `i686-pc-windows-msvc` build ships as a zip only. To build it yourself, use `packaging/wix/build.ps1` as described in
[packaging/wix](../packaging/wix/README.md#build).

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

The package creates no shortcuts. It does not create a device key or a config file, and none of
its custom actions creates a key: the installer never creates a key as `SYSTEM` or as an
elevated installer account. Windows Installer runs a per-user package as the installing user.

### Why per-user

The `gateinto://` handler, the device key (a per-user CNG key) and the agent (a per-user named
pipe) all belong to one Windows user. A machine-wide install would need an `HKLM` handler that
competes with per-user ones, and would run its custom actions as `SYSTEM`. A machine service
mode that keeps a device session running with no user logged on is not implemented.

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
   prints its path and each gateway as `gateway: <name>: <host>:<port>`. A config that does not
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
gateway: office: proxy.example.com:443
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

Commands that run with logging (`agent`, `proxy`, `session browser`, `check-upstream`) log at
`info` which default config file they loaded.

`setup` is the only step besides `key init` that creates a key. `key init` refuses the same
service accounts as `setup`. `gateinto agent`,
`gateinto open` (and with it a clicked `gateinto://` link), `proxy` and `check-upstream`
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
gateway: office: proxy.example.com:443
device-session: gateway office, listen 127.0.0.1:18736
agent: running
session: 2 browser office 127.0.0.1:50123
uri-handler: gateinto: "C:\Users\me\AppData\Local\Programs\Gateinto\gateinto.exe" open -- "%1"
```

`device-key` is `present`, `absent`, `unavailable` (not Windows) or `error: …`. Gateways show
only name, host and port; CA files, certificate files, portal URLs and credentials are not
printed. Sessions come from the running agent, the same lines as `gateinto session list`.
`uri-handler` is `not registered`, `gateinto: <command>` or `another program: <command>`.

## Uninstall

Use Settings → Apps → Installed apps → Gateinto → Uninstall, or:

```powershell
msiexec /x gateinto.msi /qn
```

| Resource | Default uninstall |
|---|---|
| `gateinto.exe` | removed |
| Install folder in the user `PATH` | removed |
| `gateinto://` handler (`HKCU\Software\Classes\gateinto`) | removed |
| Logon autostart entry created by the installer | removed |
| Uninstall entry | removed |
| Running agent, its listeners, tunnels and sessions | closed (see below) |
| Gateinto browser profiles in `%LOCALAPPDATA%\Gateinto\profiles` | deleted |
| Device key | **kept** |
| Config file(s), including `%APPDATA%\Gateinto\gateinto.toml` | **kept** |
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
- `--purge-config` also deletes the config file: the one named with `--config`, or
  `%APPDATA%\Gateinto\gateinto.toml`. It must be a regular file that parses as a Gateinto config.
  Only that file is deleted, never a directory.
- When no device key exists, `--purge-config` still deletes the config file. There is no SPKI to
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

The CI job `msi` on `windows-latest`, and the `msi` jobs of the compatibility workflow on
`windows-2022` and `windows-2025`, build the MSI and run
[.github/scripts/msi-lifecycle.ps1](../.github/scripts/msi-lifecycle.ps1), which checks the
following with the Microsoft Software Key Storage Provider (the runners have no TPM):

- a silent per-user install writes the exe, the user `PATH` entry, the exact handler command
  and the uninstall entry, and creates no device key (`key info` fails until `setup` runs);
- the first `setup` creates a key;
- a silent uninstall with a running agent stops the agent and removes the exe and the handler,
  while `key info`, run from a copy outside the install folder, still shows the same SPKI;
- after a reinstall with `AUTOSTART=1`, the Run value is exactly
  `"…\gateinto.exe" agent --detach` and `setup` reuses the key with the same SPKI; the next
  uninstall removes the Run value;
- `reset` refuses a wrong prefix and a missing confirmation, deletes the key with the right
  prefix, keeps the handler, and the next `setup` creates a different SPKI.

Not verified: TPM keys, interactive install and uninstall, Windows 10 and 11 client editions (the
runners are Windows Server), and a `gateinto://` link clicked in a real browser. See
[verification.md](verification.md).
