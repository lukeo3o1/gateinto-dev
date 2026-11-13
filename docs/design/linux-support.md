# Design: Linux support

Status: partly implemented

Steps 1 to 8 and 14 to 17 of the [Implementation plan](#implementation-plan)
are implemented on `feat/linux`; steps 9 to 13 and 18 are not. Names and line
numbers refer to `master` at a0f46b4, the base of `feat/linux`. The behaviour
described for desktops, systemd, browsers, TPMs and gateways is not verified;
what must be checked is listed under [Needs verification](#needs-verification).

## Summary

Gateinto runs on Linux today as a development platform: the proxy, the agent,
IPC, the link store and browser sessions work, but the parts that depend on
Windows facilities are stubs that report "only on Windows". This document
scopes the work that makes Linux a supported desktop platform for the CLI and
the agent:

1. a per-user `gateinto://` handler written as XDG files;
2. `os_user` local proxy authentication based on `/proc`;
3. containment of terminal sessions in a systemd user scope, replacing the
   Windows job object;
4. in-process terminal sessions (`gateinto session terminal` without an
   agent-hosted window);
5. `gateinto status` and `gateinto setup` output that describes Linux;
6. a tarball release with an optional `systemd --user` unit;
7. a device identity backend, which is an open decision.

Each area is delivered as small pull requests into `feat/linux`, test first.
Until the identity decision is made and implemented, Linux runs without a
device client certificate; [Running without a device
certificate](#running-without-a-device-certificate) states what that means
for gateways.

## Goals

- `gateinto://` links open through the desktop's URI handling, with the same
  `register`, `unregister` and registered-command semantics as on Windows,
  touching only entries Gateinto owns.
- `local_auth = "os_user"` accepts a loopback connection only when the client
  socket belongs to a process of the same user, and, for terminal sessions,
  to a process inside the session's containment unit.
- `gateinto session terminal` works on Linux in-process, with every process
  it starts ended when the session ends.
- `gateinto status`, `setup`, install and uninstall say what is and is not
  available on Linux instead of failing with Windows wording.
- Every step is tested on `ubuntu-latest` in CI where the facility exists
  there; the rest is listed as manual.
- The security constraints that hold on Windows hold on Linux unchanged
  ([Security constraints](#security-constraints)).

## Non-goals

- A Linux GUI (tray, dialogs, settings window). Linux is CLI and agent only.
- An agent-hosted terminal window. Decision 15 of
  [terminal-session.md](terminal-session.md) keeps the Linux phase
  in-process; no terminal emulator is launched by the agent.
- Distribution packages (`.deb`, `.rpm`), Flatpak and Snap. Sandboxed
  formats cannot read other processes' `/proc` entries or create user scopes
  ([Area 6](#area-6-packaging)).
- System-wide (root) installation, multi-user registration, or a system
  service.
- macOS and the BSDs. They keep today's stubs; where code becomes
  `cfg(target_os = "linux")` instead of `cfg(unix)`, the other Unix targets
  keep the "not supported on this platform" behaviour.
- Choosing the identity backend in this document. It is presented as an
  open decision.

## What exists today

### Works on Linux

| Area | Where |
| --- | --- |
| IPC directory, `0o700` with an owner check | `src/ipc.rs:795-806` |
| Bind lock, `create_new` with mode `0o600`, stale after 10 s | `src/ipc.rs:811-848` |
| Unix socket listener, mode `0o600`, under `XDG_RUNTIME_DIR` | `src/ipc.rs:865-883` |
| SIGINT and SIGTERM through tokio | `src/main.rs:929-936` |
| Agent started in its own process group (`process_group(0)`) | `src/main.rs:1170-1186` |
| Browser candidates on `PATH` (Chrome, Chromium, Edge) | `src/browser.rs:89-102` |
| Browser profiles under `XDG_STATE_HOME` or `~/.local/state/gateinto` | `src/browser.rs:146-164` (`profiles_root_from`) |
| Browser spawn with `kill_on_drop`; the job argument is ignored | `src/browser.rs:199-219` |
| Private directories `0o700` | `src/browser.rs:257-263` |
| Link store: directory fsync, publish by hard link, `0o600` files | `src/link/store.rs:524-529`, `657-658`, `745-756` |
| Login shell from `getpwuid_r` | `src/terminal.rs:292-329` |
| Default shell: `$SHELL`, then `pw_shell`, then `/bin/sh` | `src/terminal.rs:408-416` |
| `PATH` search that skips relative entries | `src/terminal.rs:479-480` |
| Process exit wait from `/proc/<pid>/stat` | `src/process.rs:52-63` |
| Default configuration `$XDG_CONFIG_HOME/gateinto/gateinto.toml`; relative XDG values ignored | `src/config.rs:25-39` |

### Stubs outside Windows

| Area | Where | Today |
| --- | --- | --- |
| Device keys | `src/identity/mod.rs:14-18`, `30-36` | `SystemStore` is an empty enum; `system_store()` returns `UnsupportedPlatform` ("device keys are only supported on Windows") |
| URI handler | `src/registration.rs:121-134` | `register`, `unregister` and `registered_command` return `Unsupported` |
| Job object | `src/job.rs:25-31` | `Job::new` returns `Unsupported` ("job objects are only available on Windows") |
| `os_user` | `src/proxy/os_user.rs:131-142` | `system()` returns `Unsupported`; a configuration naming it fails to load (test `binding_with_os_user_fails_outside_windows`, `src/proxy/mod.rs:828`) |
| Console terminal | `src/main.rs:820-823` | "terminal sessions are not supported on this platform" |
| Agent terminals | `src/agent.rs:229-231`, `491-495` | `terminals()` is `cfg!(windows)`; agent-hosted requests are refused |
| Browser job and `os_user` | `src/agent.rs:971-985`, `987-992` | no job outside Windows, so browser sessions never use `os_user` |
| Current account check | `src/lifecycle.rs:62-65` | returns `Ok(None)` |
| Handler state in `status` | `src/lifecycle.rs:96-106` | `Unsupported` is shown as "not supported on this platform" |
| `setup` | `src/main.rs:1598-1625` | fails at `system_store()?` |
| `uri` subcommand help | `src/main.rs:76` | "(Windows, development use)" |

### Shared code the Linux work builds on

- `handler_command` and `quotable` (`src/registration.rs:61-80`) build
  `"<exe>" open [--config "<cfg>"] -- "%1"` and refuse paths that are not
  absolute, end with a separator, or contain `"`, `%` or control characters.
- `is_handler_command` (`src/registration.rs:82-106`) already accepts the
  basename `gateinto` as well as `gateinto.exe`.
- `validate_scheme` (`src/registration.rs:108-119`).
- The Windows registration (`src/registration.rs:139-200`): `ensure_ours`
  turns an entry that is not a Gateinto handler into `ForeignHandler`;
  `register` rolls back a key it created when writing fails; `unregister`
  returns `Ok(false)` when there is nothing of ours.
- `os_user::owner` and `lookup` (`src/proxy/os_user.rs:59-92`) match a
  connection-table row whose local end is the client's address and whose
  remote end is the listener, skipping pid 0, behind the `Owners` trait
  (`src/proxy/os_user.rs:32-34`) and the `Denial` values `NotFound`,
  `OtherUser`, `NotInJob`, `Lookup` and `TimedOut`
  (`src/proxy/os_user.rs:8-16`).
- The Windows check sequence (`src/proxy/os_user/windows.rs:59-90`): find the
  pid with retries, open the process, re-read the table to guard against pid
  reuse, compare SIDs, then test job membership.
- The lookup runs in `spawn_blocking` under the handshake deadline
  (`src/proxy/local_auth.rs:84-100`, default 10 s at `src/proxy/mod.rs:73`);
  on timeout the client gets 408 but the blocking task keeps running.
- `SpawnError::{Job, Process}` (`src/job.rs:44-65`).

## Area 1: `gateinto://` handler

### Design

The handler for a scheme `<scheme>` (checked with `validate_scheme`) is two
files under the user's XDG directories, written by Gateinto itself. Every
name below follows the scheme; for the default scheme `<scheme>` is
`gateinto`, and a test scheme such as `gateinto-test-123` gets its own files
and line:

- `$XDG_DATA_HOME/applications/<scheme>.desktop` (default
  `~/.local/share/applications`):

  ```ini
  [Desktop Entry]
  Type=Application
  Name=Gateinto
  Exec="<exe>" open --config "<cfg>" -- %u
  NoDisplay=true
  MimeType=x-scheme-handler/<scheme>;
  X-Gateinto-Handler=1
  ```

  `--config` is present only when a configuration path was given, as on
  Windows.
- `$XDG_CONFIG_HOME/mimeapps.list` (default `~/.config`): the line
  `x-scheme-handler/<scheme>=<scheme>.desktop` in `[Default Applications]`.

The desktop file id `<scheme>.desktop` is an open decision (a reverse-DNS id
is the alternative). The ownership marker and the foreign check below apply
to each scheme's file separately: `<scheme>.desktop` is ours only if it has
`X-Gateinto-Handler=1`, `MimeType=x-scheme-handler/<scheme>;` and an `Exec`
that `is_handler_command` accepts.

A relative `XDG_DATA_HOME` or `XDG_CONFIG_HOME` is ignored as in
`src/config.rs:25-39`, and so is a relative `HOME`. When neither an absolute
XDG value nor an absolute `HOME` gives a directory, `register` and
`unregister` fail with "cannot find the per-user config directory: set HOME
or XDG_CONFIG_HOME to an absolute path" (or the data directory and
`XDG_DATA_HOME`).

**Files, not `xdg-mime`.** `xdg-mime` is an optional shell script from
`xdg-utils`, behaves differently per desktop, rewrites `mimeapps.list` in its
own way, and would itself have to be found as an executable. Writing the two
files directly is deterministic, testable without a desktop, and keeps the
"never resolve executables against the current directory" rule trivially
true because no executable is run.

**Exec quoting.** The Desktop Entry specification requires field codes to be
unquoted and, inside double quotes, `"`, `` ` ``, `$` and `\` to be escaped;
a literal `%` is `%%`. Instead of escaping, Linux refuses these characters:
the path check is `quotable` plus `` ` ``, `$` and `\`. The URI argument is
` -- %u` rather than ` -- "%1"`, so a Linux variant of `handler_command` and
`is_handler_command` is needed; it is a `cfg(target_os = "linux")` constant
and a shared parser, not a second implementation. The executable is
`std::env::current_exe()`, an absolute path, never a name resolved on
`PATH`.

**Semantics, matching Windows.**

- `registered_command(scheme)` returns the `Exec` of the desktop file that is
  the effective default for `x-scheme-handler/<scheme>`, following the
  lookup order of the MIME Applications Associations specification. For
  each `<desktop>` in `XDG_CURRENT_DESKTOP` (colon-separated, lowercased)
  `<dir>/<desktop>-mimeapps.list` comes before `<dir>/mimeapps.list`, and
  the directories are, in order:
  1. `$XDG_CONFIG_HOME`;
  2. each entry of `XDG_CONFIG_DIRS` (default `/etc/xdg`);
  3. `$XDG_DATA_HOME/applications`;
  4. `<dir>/applications` for each entry of `XDG_DATA_DIRS` (default
     `/usr/local/share:/usr/share`).

  A value of `[Default Applications]` is a `;`-separated list of desktop
  ids, tried in order; an id whose desktop file is not installed (not found
  in `$XDG_DATA_HOME/applications` or the data dirs' `applications`) is
  skipped, and when no id of a file is installed the lookup falls through to
  the next file. For `foo.desktop;gateinto.desktop;` the effective handler is
  `foo.desktop` if it is installed and ours only otherwise. `None` when no
  installed default is found. Only regular files of at most 1 MiB are read,
  opened without blocking so a FIFO cannot stall `gateinto status`; any
  other file is treated as missing, and an unreadable desktop file falls
  through to the same id in the later data dirs.

  The lookup is narrower than GIO's:
  - Desktop ids are not mapped to subdirectories (`kde4-foo.desktop` is not
    looked up as `kde4/foo.desktop`); such a default counts as not
    installed.
  - `Hidden=true` is not honoured, so a hidden desktop file still counts as
    installed. The override warning of `register` is given for it all the
    same.
  - A default whose desktop file has no `Exec` (for example
    `DBusActivatable=true`) yields no command, and the override warning is
    given for it.
  - `[Added Associations]` and the `mimeinfo.cache` fallback are not
    consulted, so status can say "not registered" while a desktop picks a
    handler that way.
- `register(scheme, command)` refuses an invalid scheme, and a command that
  `is_handler_command` does not accept with `NotAHandlerCommand`, before any
  file is read, so the error does not name a desktop file that may not
  exist (Windows keeps `ForeignHandler` there).
  It returns `ForeignHandler` when `<scheme>.desktop` exists and is not ours
  (as defined above, with the command of its last `Exec` in the error, or
  none), and `ForeignDefault` (naming the file and the ids) when the
  scheme's values in `[Default Applications]` of `$XDG_CONFIG_HOME/mimeapps.list`
  list any id other than `<scheme>.desktop`. These are the raw ids of every
  line for the key, so a duplicate line and an id with a backslash count,
  and they are taken before the line is edited. A line without ids is
  replaced. Both files are read without following symlinks; a symlink, a
  file that is not regular, one over 1 MiB or one that is not UTF-8 is
  refused with an error that names it and is never rewritten. Otherwise it
  writes the desktop file (always, so its mode is reset to `0o600`), then
  re-reads and re-checks `mimeapps.list` and writes the line if it is not
  there yet. A desktop file it created is removed if the desktop file write
  itself fails or the line is not written; it is removed only while it still
  holds what was written, and a desktop file that existed before (ours, with
  another command) is kept with the new command. When the rename of
  `mimeapps.list` succeeded and only the directory sync after it failed, the
  line is in place: both files are kept and the error says that the change
  was written but could not be flushed to disk. Running `register` again is
  idempotent in every state this leaves.

  After writing, `register` runs the lookup of `registered_command` and
  returns `Ok(Some(Overridden))` unless the effective default is our own
  desktop file in `$XDG_DATA_HOME/applications` and still ours. The signature
  is `Result<Option<Overridden>, RegistrationError>` on every platform;
  Windows always returns `None`. The wording is deliberately "may", because
  the lookup is narrower than GIO's (see above), so the warning can be given
  when a desktop would still use ours:
  - another file in the lookup order sets an installed id: "`<file>` sets
    "`<id>`" as the default for x-scheme-handler/`<scheme>`, so
    `<scheme>`:// links may open that application instead of Gateinto";
  - no installed default is found at all: "no installed default for
    x-scheme-handler/`<scheme>` was found that is the Gateinto desktop file,
    so `<scheme>`:// links may open another application or none".

  The absence of a warning is not a guarantee: other desktops'
  `<desktop>-mimeapps.list` files (only `XDG_CURRENT_DESKTOP` of the
  registering process is read), `[Removed Associations]`, sandboxed browsers
  going through the portal, and desktops that do not follow the
  specification are not considered. `uri register` prints the warning to
  stderr after the success line. `setup` does not register a handler and
  fails on Linux (Area 5), so it prints no override warning; `status` prints
  the same text as `uri-handler-warning` when our desktop file is installed
  (Area 5).
- `unregister(scheme)` reads and checks both files before changing anything.
  It removes our `mimeapps.list` line only when every id on the scheme's
  lines is `<scheme>.desktop` and there is at least one, then our desktop
  file. It returns `ForeignHandler` or `ForeignDefault` if either is foreign,
  `Ok(true)` if it removed anything and `Ok(false)` otherwise, and never
  creates a directory. If the line was removed but the desktop file removal
  fails, running it again removes the desktop file.

`gateinto uri register` and `uri unregister` take a hidden `--scheme`
option, restricted to `gateinto` and `gateinto-test-<name>`, for the
integration test.

**Writes.** Each file is written to a temporary file in the same directory
(`create_new`; mode `0o600` for the desktop file; for `mimeapps.list` the
existing mode is kept, and a newly created one gets `0o644`, since it holds
no secrets), synced, and renamed over the target; the
directory is then synced as in `src/link/store.rs:524-529`. There is no
locking protocol for `mimeapps.list`: a desktop tool writing it at the same
moment can lose its update or ours (the last rename wins). Gateinto re-reads
the file just before writing to keep the window small, and the race is
documented. `mimeapps.list` is parsed as an INI-like file and only the
`x-scheme-handler/<scheme>` key in `[Default Applications]` is added or
removed; every other line, comment and
section is kept byte for byte. The one exception is a
`[Default Applications]` header that `register` added to a list without
one: `unregister` removes only the key line and leaves that header. A `mimeapps.list` or desktop file that is a
symlink or not a regular file is refused rather than followed or replaced.
Every write and removal is anchored at a directory that must contain the
target lexically (the home directory, or the XDG root when it is not under
it). Both anchors are checked before anything is written: an anchor is never
created, and a missing one fails with "directory `<anchor>` does not exist".
The anchor must be a directory owned by the effective uid, which refuses
`sudo gateinto uri register` with a preserved `HOME`. Each level between the
anchor and the target directory is then checked in turn: symlinks are
followed, the resolved directory must be owned by the effective uid, and a
missing level is created with mode `0o700` and checked before the next one,
so nothing is created under a foreign directory. A removal checks the same
levels and never creates any. The checks resolve paths and the later writes
resolve them again, so a process that can write to a checked directory
(normally only the same user, who is trusted; see Security) can still swap a
level in between. A kept mode loses its setuid, setgid and sticky bits.

Known limit: directories are opened `O_RDONLY` to check their owner and to
sync them, so a directory of the user's own without read permission (for
example mode `0o300`) fails with "Permission denied" instead of being used.

### Security

- No executable is run to register. The `Exec` line names an absolute path
  from `current_exe`; paths with characters that the Desktop Entry
  specification would interpret are refused, so a path cannot inject
  arguments, field codes or variables.
- `%u` is passed after `--`, so a link cannot become an option, exactly as on
  Windows. What a link may carry is unchanged: never credentials, CA or TLS
  settings or commands, and a link never starts a terminal.
- Only the scheme's own `mimeapps.list` key and the scheme's own desktop file
  are touched; a foreign handler is reported, not replaced.
- Any process of the same user can rewrite these files; that is the same
  boundary as `HKCU\Software\Classes` on Windows and is stated in the
  security model.

### CI on `ubuntu-latest`

Unit tests run against a temporary directory passed as the XDG roots (the
functions take the roots as parameters; the public wrappers read the
environment):

- quoting: paths with `` ` ``, `$`, `\`, `%`, `"` and control characters are
  refused; built commands are recognised by `is_handler_command`;
- register, re-register (idempotent), unregister, unregister twice
  (`Ok(false)`);
- foreign desktop file, foreign default in `mimeapps.list`, and a
  desktop-specific override, each with the expected result;
- `mimeapps.list` round trip keeps unrelated lines, comments, sections and
  other keys;
- symlinked `mimeapps.list` and a foreign-owned anchor, level or symlinked
  directory are refused (the ownership tests use `/` when not running as
  root, and a directory chowned to `nobody` when running as root);
- rollback when the second write fails (read-only directory);
- relative XDG values are ignored.

An integration test (`tests/uri_registration_linux.rs`) runs `gateinto uri
register --scheme gateinto-test-<n>` with `HOME` and XDG variables pointed at
a temporary directory, checks the two files, and checks `gio mime
x-scheme-handler/gateinto-test-<n>` under `LC_ALL=C` when `/usr/bin/gio` or
`/bin/gio` exists (skipped otherwise; `gio` is never looked up on `PATH`).
GIO treats a desktop file whose `Exec` binary does not exist as invalid, so
the test registers the built `gateinto` binary. It then unregisters and
checks that `gio` reports no default. `gio` is present locally at
`/usr/bin/gio`; whether it is on the runner image still needs verification.

### Manual and unverified

- A link clicked in Firefox, Chrome and Chromium on GNOME and KDE opens
  `gateinto open` with the URI; whether each honours the `mimeapps.list`
  default without `update-desktop-database` having been run.
- Whether `NoDisplay=true` hides the entry from menus but keeps it eligible
  as a scheme handler on each desktop.
- Snap and Flatpak browsers, which go through the desktop portal.

## Area 2: `os_user` owner lookup

### Design

Linux implements `Owners` (`src/proxy/os_user.rs:32-34`) from `/proc`:

1. **Row.** `/proc/net/tcp` and `/proc/net/tcp6` have no pid column, so Linux
   has its own row type, `LinuxRow { local, remote, uid, inode }`, and its own
   matcher. Only the address rule is shared with `owner`
   (`src/proxy/os_user.rs:59-61`): the row's local end is the client's address
   and its remote end is the listener. Addresses are hex; an IPv4 address (and
   each 32-bit word of an IPv6 address) is in host byte order, the port is the
   plain hex port number, and IPv4-mapped IPv6 addresses are matched as IPv4.
   Rows with inode 0 (`TIME_WAIT` and other sockets without a file) are ignored.
   If the matching row's uid differs from the agent's effective uid, return
   `OtherUser` without looking further.
2. **Holder.** Find a process holding `socket:[<inode>]` among the links in
   `/proc/<pid>/fd`. Only processes of the agent's own uid are searched: in
   scope mode (Area 3), the pids listed in the session scope's
   `cgroup.procs` and its descendants; otherwise the pids whose
   `/proc/<pid>/status` has our uid in any of its four `Uid:` fields. A
   process whose fd directory or status cannot be read, or whose status is
   malformed, is skipped and the skip is remembered; one that disappears
   during the scan (`ENOENT`, or `ESRCH` from `pidfd_open`) is ignored.
3. **Liveness.** For the candidate, open a pidfd (`pidfd_open`) before
   reading its fd links, `/proc/<pid>/status` and `/proc/<pid>/cgroup`, then
   `poll` the pidfd with a zero timeout: if it is readable the process has
   exited (or is a zombie, whose fd directory is empty) and the candidate is
   discarded. `pidfd_send_signal(pidfd, 0)` is not used for this, because it
   succeeds on zombies. Finally re-read the table row to confirm the
   connection still has the same inode, as the Windows code re-reads the
   table (`src/proxy/os_user/windows.rs:59-90`).
4. **User.** All four `Uid:` fields of `/proc/<pid>/status` must equal the
   agent's uid, otherwise `OtherUser`.
5. **Membership.** When the check has a containment unit, the process's
   cgroup path must be the scope's path or below it, otherwise `NotInJob`.

The `/proc` parsers are strict and any malformed input is a `Lookup`
denial: a table without its header or with a row of fewer than the twelve
fields the kernel always writes, a `status` without exactly one `Uid:` line
of four decimal fields, a `cgroup` without exactly one `0::/<path>` line. A
second `Uid:` or `0::` line is malformed rather than ignored, so a process
or cgroup name containing a newline cannot add one.

The connection is accepted only when a readable, live holder with our uid
(and, in scope mode, inside the scope) is positively found; the scan stops
at the first. Otherwise it is denied: `OtherUser` if a live holder had
another uid in one of its four fields, else `Lookup` if any process was
skipped as unreadable, `NotFound` if none was. `/proc/net/tcp` is always
read and `/proc/net/tcp6` only for an IPv6 client or an IPv4 client with no
IPv4 row, as on Windows; a table that is needed and cannot be read or
parsed is a `Lookup` denial. `pidfd_open` needs Linux 5.3; on `ENOSYS` the check is a `Lookup`
denial, so `os_user` refuses every connection on older kernels and `status`
says so.

The retries for a row that is not yet visible follow the Windows values
(five reads, 5 ms apart, shared with the Windows code). The handshake
deadline is passed into the check as an `Instant` through `Owners::check`,
and the scan checks it before each process, so the blocking task of
`src/proxy/local_auth.rs:84-100` stops soon after `TimedOut` instead of
running on; a `TimedOut` returned by the check is answered like the outer
timeout (`408`). The row retries do not check it; they take at most 20 ms.
The `/proc` root is a parameter of the Linux `System`, so the selection
logic runs over a fake tree in tests while the pidfds are opened for real
processes.

Reading another process's fd links needs ptrace read access. A non-dumpable
process (setuid programs, processes that called `prctl(PR_SET_DUMPABLE, 0)`,
some browser sandboxes) cannot be read even by its own user, and restricted
containers hide `/proc/net`. If the holder is such a process, or the table
cannot be read, the result is a denial: the check fails closed. `hidepid`
only hides other users' processes, which are never scanned, so it does not
affect the check. A `NETLINK_SOCK_DIAG` query for the row is a later
optimisation, not part of the first version.

### Security

- The uid in the connection table is the socket's creator; the holder check
  and the `status` uid check confirm that a process of our user holds it
  now. The boundary is the user: a socket passed to another user's process
  is refused only if no process of our uid still holds it; while one does,
  the connection is accepted, as on Windows.
- A pidfd does not prevent pid reuse; it detects that the process it was
  opened for has exited. Opening it before reading `/proc/<pid>` and polling
  it afterwards means the data read belongs to the process the pidfd
  refers to, and the row re-read confirms the socket is still the same.
- Acceptance needs a positive finding; an unreadable input is a denial,
  never an acceptance.
- `os_user` remains unavailable in browser sessions on Linux until a
  containment unit exists for browsers (open question); it is never enabled
  on the uid check alone where Windows also requires the job. Until Area 3,
  binding a proxy that asks for `os_user` with a containment unit fails on
  Linux.

### CI on `ubuntu-latest`

- Pure parsers for `/proc/net/tcp{,6}` lines, `status` `Uid:` lines and
  `cgroup` lines, with captured fixtures including IPv6 and mapped
  addresses.
- The selection logic over a fake `/proc` tree in a temporary directory: no
  row, other uid, inode 0, no holder (`NotFound`), an unreadable non-holder
  next to a readable holder (accepted), an unreadable process and no holder
  (`Lookup`), holder of another uid, exited or zombie holder, deadline
  reached.
- An end-to-end test: a listener bound on loopback with `os_user`, a client
  from the test process (accepted), and a client from a child process under
  `sudo -u nobody` on the runner. With `os_user` alone the refusal is 403
  (`LocalAuth::check` returns `Status::Forbidden` when there is no verifier,
  `src/proxy/local_auth.rs:126-141`); 407 is only expected when session
  credentials are also enabled. `OtherUser` appears only in the log, which
  the test checks. The `sudo` part runs only when
  `GATEINTO_TEST_SUDO_NOBODY=1`, which the `ubuntu-latest` job sets on its
  test step, and is required there; the client is a `bash` `/dev/tcp`
  redirection, so the test needs no helper binary readable by `nobody`.
- The existing `binding_with_os_user_fails_outside_windows` becomes
  `..._outside_windows_and_linux`.

### Manual and unverified

- Behaviour in containers, on kernels without `pidfd_open`, and with
  clients that are non-dumpable (Chrome's sandboxed network service is the
  case that matters for a future browser `os_user`).
- Cost per connection on a desktop with many processes; whether scope mode
  keeps it acceptable (Decision 14 of
  [terminal-session.md](terminal-session.md)).

## Area 3: session containment

### Design

Decision 14 of [terminal-session.md](terminal-session.md) chose a systemd
user scope (its option (i)) as the prototype. On Linux `Job` becomes a handle
to a transient scope:

- **Prerequisites, before binding.** `Job::new` checks that cgroup v2 is
  mounted at `/sys/fs/cgroup`, that the user manager is reachable (the user
  bus `$XDG_RUNTIME_DIR/bus` or `$XDG_RUNTIME_DIR/systemd` exists and is
  owned by the uid), that the delegated cgroup
  `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service` exists and
  is owned by the uid, and that `systemd-run` exists at a fixed absolute
  path (`/usr/bin/systemd-run`, then
  `/bin/systemd-run`). It is never looked up on `PATH` and never resolved
  against the current directory. Any failure is `Unsupported` with a message
  naming the missing piece, before the listener is bound, as `Job::new` is
  called today in the Windows `console_terminal`. Where Gateinto's own
  cgroup is in the hierarchy is not checked: a terminal opened over SSH, on
  a VT or from a desktop runs in a `session-<n>.scope` outside
  `user@<uid>.service`, and the scope is still created by the user manager.
  The post-spawn check below is the real guarantee.

  Where this list is silent, the checks fail closed as follows. The uid is
  the effective uid. Every type and owner check is an `lstat` except the
  one for `systemd-run`, so a symbolic link never stands in for a
  directory, socket or file.
  - cgroup v2: `/sys/fs/cgroup/cgroup.controllers` is a regular file, so a
    hybrid layout with the unified hierarchy at `/sys/fs/cgroup/unified` is
    refused.
  - Own cgroup visible: the single `0::` path of `/proc/self/cgroup`
    (parsed as in Area 2) has only plain components after its leading `/`,
    and names a directory under `/sys/fs/cgroup`. A `..` component (a cgroup
    namespace rooted below the process's cgroup), a deleted cgroup
    (`... (deleted)`) and a path that names no directory under
    `/sys/fs/cgroup` are refused. This does not detect a mount from another
    cgroup namespace: a process at the root of its own cgroup namespace sees
    `0::/`, which passes whatever is mounted at `/sys/fs/cgroup` (for
    example after `unshare -C` without a remount). So every
    `/proc/<pid>/cgroup` path that a later step joins to the mount is
    validated the same way (plain components, an existing directory).
  - `XDG_RUNTIME_DIR`: set, absolute, and a directory of the uid with no
    group or other permission bits (the same mode rule `src/ipc.rs` applies
    to its own directory). A relative
    or unset value is refused, never resolved against the current
    directory.
  - User manager: each of `bus` and `systemd` that exists must be the
    right type (a socket, a directory) and belong to the uid, or the check
    fails even if the other one is fine; at least one must exist. Only a
    missing entry is tolerated; any other error refuses.
  - Delegated cgroup: a directory, owned by the uid.
  - `systemd-run`: the fixed candidates are followed through symbolic links
    (merged `/usr` links `/bin` to `/usr/bin`). A missing candidate falls
    through to the next. A candidate that exists but is not a regular file,
    belongs to neither root nor the uid, is writable by group or others, has
    no execute bit, or cannot be inspected refuses at once, without
    falling through to `/bin/systemd-run`. The parent directories are not
    inspected, and step 9 runs `systemd-run` by path, so a window between
    the check and the exec remains; opening the file once and executing
    from that descriptor (`fexecve`) is an option for step 9.
  - The checks run in the order above and the first failure is reported
    with a fixed message; no path, uid or environment value is
    interpolated. The chosen `systemd-run` path is returned by the check
    and is not kept until the spawn of step 9 needs it. Until steps 9 to
    13, nothing on Linux calls `Job::new` (terminals and browser jobs are
    Windows only), so a passing check starts nothing.
- **Spawn.** The shell is started as
  `systemd-run --user --scope --quiet --collect
  --unit=gateinto-terminal-<agent pid>-<start time>-<random> -- <shell>
  <args>`. The shell path is the one already resolved by `src/terminal.rs`
  (absolute, never from the current directory). Spawn then waits, bounded,
  until `/proc/<pid>/cgroup` shows the scope; if it does not, it kills the
  process and returns `SpawnError::Job`.
- **Teardown.** Write `1` to the scope's `cgroup.kill` (Linux 5.14 and
  later) and wait up to 5 s for `populated 0` in `cgroup.events`. If
  `cgroup.kill` is missing (older kernels) or the wait expires, run
  `systemctl --user stop <unit>` (same absolute-path rule) and report what
  is left. The minimum kernel for terminals is therefore 5.3 (for the
  `pidfd_open` of Area 2); on 5.3 to 5.13 teardown always uses the
  `systemctl` fallback.
- **Stale scopes.** At start, the scopes are listed from the cgroup directory
  `user@<uid>.service/app.slice/`, where current systemd versions place
  transient user scopes (needs verification), by the directory name
  `gateinto-terminal-<pid>-<start time>-<random>.scope`; `systemctl --user
  list-units 'gateinto-terminal-*' --plain --no-legend` is the fallback when the
  directory is missing. Those whose owner is gone (pid not running or with
  another start time) are killed and stopped. `PR_SET_PDEATHSIG` on the
  `systemd-run` child is optional and not relied on: it fires when the parent
  thread exits, and tokio's blocking-pool threads exit when idle.
- **Membership** for `os_user` is "cgroup path equals or is below the
  scope", read from `/proc/<pid>/cgroup` with the pidfd liveness check of
  Area 2.

`systemd-run` rather than talking to the user manager over D-Bus with
`zbus`: it adds no dependency and its arguments are fixed. `zbus` is an open
decision if the process cost or the parsing of its failures prove a problem.

**Alternatives rejected as the primary mechanism.** A process group or
session (`setsid`) is left by any child that calls `setsid` itself, and kill
by group misses it. `PR_SET_CHILD_SUBREAPER` keeps orphans as our children
but cannot stop a double-forked daemon from running on, and gives no
membership test for `os_user`. Both remain as defence in depth (the shell is
started in its own process group) but not as the boundary. A cgroup created
by Gateinto itself under a delegated subtree needs the same systemd
delegation and adds code that `systemd-run` already provides.

**Escapes**, documented in the security model: a process of the same user
can ask the user manager to start a unit outside the scope (`systemd-run
--user`, D-Bus activation, `systemctl --user start`); it is then neither
killed at teardown nor accepted by `os_user`. This is the equivalent of the
breakaway gaps of a job object and is accepted for the same reason: the
boundary is the user, the scope is lifetime management.

**Without systemd** (no user manager, cgroup v1, containers, WSL without
systemd) terminals are unavailable with the prerequisite message. A fallback
is an open decision.

### Security

- No executable is resolved from `PATH` or the current directory; the shell
  is the absolute path from the existing resolution.
- Nothing new crosses IPC: as today, IPC never carries a shell, command,
  arguments or environment, and credentials are never placed in the
  environment of the shell or of `systemd-run`.
- The scope is created by the user manager of the same user; it grants no
  privilege.
- Failure to place the shell in the scope ends the spawn; a terminal never
  runs uncontained.

### CI on `ubuntu-latest`

- Unit tests for the unit name, the `systemd-run` argument vector, the
  prerequisite checks against a fake `/sys/fs/cgroup` and `/proc/self/cgroup`,
  and the stale-scope selection. The `/proc` and cgroup roots, the runtime
  directory, the uid and the `systemd-run` candidates are parameters of the
  check, so its tests build fake trees in temporary directories and do not
  depend on the host; one test only requires that the real host either
  passes or fails with one of the fixed messages.
- A dedicated `linux-systemd` job runs `sudo loginctl enable-linger runner`,
  sets `XDG_RUNTIME_DIR=/run/user/$(id -u)` and runs the scope tests with
  `GATEINTO_TEST_SYSTEMD_SCOPE=1`, which makes them required instead of
  skipped: spawn into a scope, a double-forked `sleep` and a `setsid` child
  are both killed at teardown, `populated 0` is reached, a stale scope is
  swept, and `os_user` accepts a client in the scope and refuses one outside
  it. Whether the hosted runner allows a user manager with linger needs
  verification; if it does not, the job is dropped and these tests become
  manual.

### Manual and unverified

- Fedora, Ubuntu, Debian and Arch desktops with a graphical login; a login
  over SSH and on a VT, where Gateinto runs in a `session-<n>.scope`;
  `cgroup.kill` on the oldest supported kernel and the `systemctl` fallback
  on a kernel older than 5.14.
- NixOS, where `systemd-run` is not under `/usr/bin` (open question).
- The cost of `systemd-run` per terminal and of the scope scan per
  connection (Decision 14 asks for this from the prototype).

## Area 4: terminal sessions

### Design

Remove the stub at `src/main.rs:820-823` and use the in-process
`console_terminal` on Linux, with `Job` from Area 3. `src/agent.rs:229-231`
and `src/agent.rs:491-495` stay as they are (Decision 15: no agent-hosted
window on Linux). `handler_state` keeps mapping `Unsupported` to "not
supported on this platform" for other Unix targets.

Signals while the shell runs: Gateinto installs tokio listeners rather than
`SIG_IGN`, because an ignored disposition is inherited across `exec` and the
shell would start with SIGINT ignored, while handlers are reset. SIGINT and
SIGQUIT are drained (the shell, in the foreground of the tty, handles them);
SIGHUP and SIGTERM end the session and tear down the scope. The shell is
started in its own process group; once it runs, Gateinto makes that group
the tty's foreground process group with `tcsetpgrp`, otherwise the shell's
first read from the tty stops it with SIGTTIN. On exit Gateinto restores the
foreground process group to its own with `tcsetpgrp`, blocking SIGTTOU
around both calls.

The shell's environment is built by `terminal_environment` (shared with
Windows, `src/terminal.rs:141` onward); it carries the local proxy address
and never credentials.

### Security

As for Windows terminal sessions: the shell is resolved without the current
directory (`src/terminal.rs:479-480`), links never start terminals, the
listener is loopback-only, and credentials never enter the environment.

### CI on `ubuntu-latest`

The cross-platform tests of `src/terminal.rs` already run on Linux; the
Windows-only ones (for example the `cfg(windows)` test at
`src/terminal.rs:1025`) are reviewed and enabled for Linux where they do not
need a console, and a test covers refusal when `Job::new` fails. With the
`linux-systemd` job: a session started with a script as the shell exits
cleanly, its children are gone, and a client run from the script reaches the
proxy through `os_user`.
The test
`terminal_sessions_are_refused_before_anything_is_bound_outside_windows`
(`src/main.rs:1916-1921`) is limited to non-Linux targets.

### Manual and unverified

Interactive use in GNOME Terminal, Konsole and a plain VT: job control in
the shell, Ctrl-C and Ctrl-\ reaching the foreground job, the shell
getting the foreground at start, the tty restored after exit, and closing
the terminal window (SIGHUP) ending the scope.

## Area 5: lifecycle and status output

### Design

- `gateinto status` on Linux prints the device key as "unavailable: no
  device key backend on Linux; connections are unauthenticated" instead of
  the Windows error text; the handler from `registered_command` with the same
  states as on Windows plus the override warning of Area 1; and terminal
  availability from a read-only form of the Area 3 prerequisite check.
- `gateinto setup` keeps failing on Linux until identity is decided, with a
  message that says so and that `uri register` can be used on its own.
  `setup` and `uri register` warn when run as root.
- `check_current_account` (`src/lifecycle.rs:62-65`) refuses to register a
  handler for a different user than the owner of the XDG directories (the
  ownership rule of Area 1).
- `src/main.rs:76` stops saying "Windows".

As implemented in step 14:

- `status` on Linux prints, after `key-name`:

  ```text
  device-key: unavailable: no device key backend on Linux; connections are unauthenticated
  ```

  then the config, gateways, agent and `uri-handler` lines as before, and
  then:

  ```text
  uri-handler-warning: <the override warning of Area 1>
  terminal-sessions: not supported on Linux yet
  terminal-containment: available
  os-user: not offered by any session on Linux yet; pidfd_open is available
  ```

  `uri-handler-warning` appears only when our desktop file is installed and
  the lookup finds another installed default, or none, for the scheme;
  without our desktop file the `uri-handler` line already says
  `not registered` or `another program: ...`. `terminal-containment` runs the
  prerequisite check of Area 3 (`Host::current`, which only reads) and is
  `available` or `unavailable: <fixed message>`, with the same fixed
  messages as `Job::new`. `available` means only that the prerequisites are
  present; `terminal-sessions` stays `not supported on Linux yet` until
  steps 9 to 13. `os-user` opens and closes a pidfd for Gateinto's own
  process: `ENOSYS` gives "pidfd_open is unavailable (Linux 5.3 or later is
  needed), so os_user would refuse every connection", any other error
  "pidfd_open failed (<error>), so os_user may refuse connections". No
  session offers `os_user` on Linux yet, because it is offered only to
  sessions in a job.
- `setup` on Linux checks the account, loads the config and prints the
  config and gateway lines as on Windows, then fails with "setup is not
  available on Linux yet: it creates the device key, and no device key
  backend for Linux has been decided; run `gateinto uri register` to
  register the gateinto:// handler on its own". It touches no key and
  writes nothing.
- `check_current_account` on Linux first refuses when the anchor of the
  data or the config directory (the home directory, or the XDG root when it
  is not under it) exists and belongs to another uid, with the Area 1
  `ForeignDirectory` error followed by "Gateinto registers its gateinto://
  handler only for the user who owns the per-user directories, so run it as
  that user, not through sudo or su". A missing anchor or an unset `HOME` is
  left to `register`. It then returns, for effective uid 0, "warning:
  running as root, which can bypass every check Gateinto makes and is
  outside its security model; run Gateinto as the user who uses it", which
  `setup` and `uri register` print on stderr. Both run the check before
  they load the config or touch anything else.
  `key init` does not call it on Linux, because it registers nothing and
  fails with "device keys are only supported on Windows".
- The help of `key`, `setup` and `status` says what they do on Linux.

### Security

Status output never prints credentials, `Proxy-Authorization`, or key
material; it reports presence and state only. The Linux lines add no
path, uid or environment value: the containment messages are the fixed
ones of Area 3, and the override warning names only the `mimeapps.list`
file and desktop id that the `uri-handler` line's lookup already reads.

### CI on `ubuntu-latest`

Snapshot tests of `status` output with a temporary XDG tree and with each
terminal prerequisite missing; `setup` returns the Linux message. The
`terminal-containment` line of the binary depends on the host, so the
integration test only requires `available` or one of the fixed messages;
each message is pinned by a unit test over a fake tree.

### Manual and unverified

None beyond Areas 1 and 3.

## Area 6: packaging

### Design

- **Release asset.** `gateinto-<version>-x86_64-unknown-linux-gnu.tar.gz`
  containing `gateinto`, the license files, the optional unit file, a
  `README` and the `install.sh` and `uninstall.sh` scripts. The target is
  `x86_64-unknown-linux-gnu`, not `musl`. `release.yml` gains an
  `ubuntu-latest` build; `.github/scripts/release-test.sh` and
  `.github/scripts/release-assets.sh` learn the new name.
- **Install** (documented in `docs/install.md`): `install.sh` inside the
  tarball, which the user runs after verifying the SHA-256 and extracting
  it. No script is hosted for `curl | sh`. It copies `gateinto` to
  `~/.local/bin` and runs `gateinto uri register`. Optionally copy
  `gateinto-agent.service` to
  `~/.config/systemd/user/` and `systemctl --user enable --now
  gateinto-agent`. Key creation is separate from installation, as on
  Windows: nothing in the package creates or touches a device key.
- **Unit** (`packaging/linux/gateinto-agent.service`).

  ```ini
  [Unit]
  Description=Gateinto agent
  PartOf=graphical-session.target
  After=graphical-session.target

  [Service]
  ExecStart=%h/.local/bin/gateinto agent
  Restart=on-failure

  [Install]
  WantedBy=graphical-session.target
  ```

  No credentials in `Environment=`; the configuration file is read from its
  default location. Hardening options that would hide `/proc` or the user
  cgroup tree (`ProtectProc=`, `PrivateUsers=`) are not used, because Areas
  2 and 3 need them, and `NoNewPrivileges=` is not used (Decision 11).
  - The unit starts and stops with `graphical-session.target` (Decision
    12). Desktops that import `DISPLAY` and `WAYLAND_DISPLAY` into the user
    manager before reaching that target give the agent a display; desktops
    without the target never start the unit, and the agent then starts on
    demand as without the unit.
  - `gateinto agent` runs in the foreground and returns from
    `Agent::serve` on `SIGTERM`, `SIGINT` (`shutdown_signal`,
    `src/main.rs:961`) or a stop request (`src/agent.rs:330-331`), so it
    exits with status 0 (`src/main.rs:1121`, `src/main.rs:589`), checked
    by hand with `kill -TERM` and `gateinto stop` on a debug build.
    `Restart=on-failure` therefore does not restart it after `systemctl
    --user stop` or `gateinto stop`, only after a crash or an error exit.
  - The default `KillMode=control-group` ends the browsers the agent
    started when the unit stops, as `gateinto stop` ends them.
  - Only one agent runs per user. When an agent started on demand is
    already running, the unit's agent fails in `Server::bind` with
    `AlreadyRunning` (`src/ipc.rs:872-874`, `src/main.rs:1105`),
    `Restart=on-failure` retries it until the start limit, and the unit
    ends failed although `systemctl --user enable --now` reported
    success. The documentation says to run `gateinto stop` first, which
    ends the running agent's sessions, or to expect the unit to stay
    failed until it is started again, for example at the next login.
- **Uninstall:** `systemctl --user disable --now gateinto-agent` when the
  unit is installed, then `gateinto stop --remove-stale-profiles` (as the
  MSI does, [install.md](../install.md), section on uninstall), which
  closes sessions, ends their browsers and deletes Gateinto browser
  profiles under `$XDG_STATE_HOME/gateinto` (or
  `~/.local/state/gateinto`); then `gateinto uri unregister`, and remove
  the unit and the binary. The configuration, the link store and any
  device key are kept, as the MSI keeps them; removing them is a separate,
  explicit step.
- XDG autostart (`~/.config/autostart`) is an alternative to the unit for
  desktops without a user manager; it is not shipped in the first version.

As implemented in step 15:

- `.github/scripts/linux-tarball.sh <gateinto> <output .tar.gz>` packages
  one top-level directory named after the output without `.tar.gz`, for
  example `gateinto-0123456789ab-x86_64-unknown-linux-gnu/`, holding
  `gateinto`, `install.sh` and `uninstall.sh` (mode 0755), `README`,
  `LICENSE-APACHE` and `LICENSE-MIT` (mode 0644), and nothing else. The
  project is dual-licensed and has no single `LICENSE`, so both license
  files ship. Step 16 adds the unit file.
- The archive is deterministic: entries sorted by name, owner and group
  0, numeric ids, every mtime `SOURCE_DATE_EPOCH` (0 when unset; the
  release job passes the commit time), GNU format and `gzip -n`. The same
  inputs give the same bytes whatever the umask. Entries are relative to
  the top-level directory, never absolute.
- `release.yml` has a `linux` job on `ubuntu-24.04` (Decision 9):
  `cargo test`, then
  `cargo build --locked --release --target x86_64-unknown-linux-gnu --bin
  gateinto`, the version check, the tarball, its `.sha256` from
  `.github/scripts/write-sha256.sh` (the format of `write-sha256.ps1`), and
  an install and uninstall of the tarball with
  `.github/scripts/linux-install-check.sh`. `publish` needs it to succeed.
  `release-assets.sh` expects
  `gateinto-<commit>-x86_64-unknown-linux-gnu.tar.gz` on every channel and
  adds the fixed-name copy `gateinto-x86_64-unknown-linux-gnu.tar.gz`. The
  release notes say that the tarball and its scripts are not yet verified
  on a real Linux desktop and that Linux has no device key.
- `install.sh` and `uninstall.sh` are POSIX `sh` with `set -eu`, take no
  arguments, and print only fixed messages. Both refuse to run as root
  (euid 0, which includes `sudo`) with a fixed message and change nothing,
  and both refuse a `HOME` that is not an absolute path to an existing
  directory. Neither reads credentials from the environment, resolves
  anything against the working directory, calls `sudo`, or touches the
  configuration, the link store or a device key.
- `install.sh` finds `gateinto` next to itself and refuses, changing
  nothing, when `~/.local/bin/gateinto` is a directory or a symbolic link
  to one, because the rename would move the binary into it. It creates
  `~/.local/bin` with mode 0755 if missing (an existing directory keeps
  its mode), copies the binary to a temporary file in that directory, sets
  mode 0755 and
  renames it over `~/.local/bin/gateinto`, so a running `gateinto` is
  replaced without `ETXTBSY` and no partial file is left. It then runs
  `~/.local/bin/gateinto uri register`, so the handler points at the
  installed path, and warns when `~/.local/bin` is not on `PATH`. If
  registering fails it says so and exits non-zero; the binary stays
  installed and running `install.sh` again retries.
- `uninstall.sh` does nothing when `~/.local/bin/gateinto` does not
  exist and is not a symbolic link. When it is a symbolic link to a
  missing file, it exits non-zero before running anything and asks the
  user to remove the link by hand. Otherwise it runs
  `~/.local/bin/gateinto stop --remove-stale-profiles` (with no agent
  running this prints `no agent is
  running` and still removes stale profiles), then `~/.local/bin/gateinto
  uri unregister`, then removes the binary. If either command fails it
  stops, keeps the binary, so that running it again can retry, and exits
  non-zero. It prints that the configuration and the linked gateways
  were kept. There is no purge.
- `release-test.sh` runs both scripts against a stub `gateinto` in a
  temporary `HOME`, as uid 65534 through `setpriv` when the tests run as
  root, and as root through `sudo -n` (or directly) to check the refusal;
  without root that case is skipped and reported. CI shellchecks
  `packaging/linux/*.sh` and installs and uninstalls a tarball of the
  debug `gateinto` with `linux-install-check.sh`, which refuses a tarball
  without exactly one top-level directory and checks that the
  registered handler runs `~/.local/bin/gateinto` and that uninstall
  removes the binary and the desktop file.

As implemented in step 16:

- The tarball also holds `gateinto-agent.service` (mode 0644), the unit
  above. `install.sh` neither installs nor enables it and still takes no
  arguments; it prints one fixed line saying how: copy
  `gateinto-agent.service` to `~/.config/systemd/user/` and run
  `systemctl --user enable --now gateinto-agent`.
- `uninstall.sh` looks only at
  `~/.config/systemd/user/gateinto-agent.service`, a file or a symbolic
  link to one. When that is a symbolic link to a missing file, as
  `systemctl --user link` leaves after the linked file is deleted, it
  refuses before calling `systemctl` or `gateinto` and removes nothing:
  systemd 255 fails `systemctl --user disable` for such a unit with
  `Failed to disable unit, unit gateinto-agent.service does not exist.`,
  so every rerun would fail the same way. Its fixed message tells the
  user to run `systemctl --user stop gateinto-agent` if it is running,
  to remove by hand that link and, if present,
  `~/.config/systemd/user/graphical-session.target.wants/gateinto-agent.service`,
  and to run `uninstall.sh` again; like the dangling binary, the
  script does not delete links it cannot account for. When the unit is
  there and `systemctl` is found, it runs
  `systemctl --user disable --now gateinto-agent.service` before `gateinto
  stop --remove-stale-profiles`, so the user manager stops the agent and
  does not start it again. If that fails, it stops with a fixed message,
  removes nothing, and running it again retries. After `gateinto uri
  unregister` it removes the unit file, says so, and runs `systemctl
  --user daemon-reload`; a failed reload only prints a fixed warning,
  because the unit is already disabled, stopped and removed and a rerun
  would no longer see it. It removes no other file in
  `~/.config/systemd/user` itself; `systemctl --user disable` removes the
  enablement link. A unit placed only under another `XDG_CONFIG_HOME` is
  not seen. `systemctl --user` needs the user's own manager and bus, so
  with the unit installed, `uninstall.sh` must run in the user's own
  login session: under `su -`, `sudo -u` or in a container without a
  user manager, `disable --now` fails to reach the user manager (the
  enablement link may already be gone, since only the stop needs the
  bus) and the script stops as above.
- `uninstall.sh` finds `systemctl` with `command -v`, through `PATH`, and
  uses the result only when it is an absolute path; a result from an
  empty or relative `PATH` entry, which would resolve against the working
  directory, counts as no `systemctl`. The scripts already take `id`, `rm`
  and the other tools from the user's `PATH`; `systemctl` is not at a
  fixed path on every system (NixOS has it under
  `/run/current-system/sw/bin`), where fixed paths would skip the disable
  silently; and a stub on `PATH` lets `release-test.sh` test the script
  without an override that the environment could also use. Without
  `systemctl` the unit file is removed without `disable` or
  `daemon-reload`; an enablement link left in
  `graphical-session.target.wants` then points to a missing unit.
- `linux-install-check.sh` runs `systemd-analyze --user verify` on the
  `gateinto-agent.service` of the tarball after `install.sh`, with the
  temporary `HOME`, so `%h/.local/bin/gateinto` is the installed binary,
  and a temporary `XDG_RUNTIME_DIR`, without which `systemd-analyze
  --user` fails with `Failed to lookup RuntimeDirectory path`. It needs
  no running user manager or user bus. Before extracting anything it
  stops with a fixed message when `systemd-analyze` is not on `PATH`.
  The check fails when `systemd-analyze` exits
  non-zero, which it does when `ExecStart` is missing or not executable,
  and also when its output names the unit, because unknown keys and
  unparsable values are only warnings with exit status 0. A misspelt
  target in `WantedBy=`, `PartOf=` or `After=` is not detected.
- `release-test.sh` checks the unit's exact text, the tarball entry, the
  line `install.sh` prints, and `uninstall.sh` with the unit as a file
  and as a link that resolves, with a stub `systemctl` on `PATH`, without
  `systemctl`, with `systemctl` only on a relative `PATH` entry, and with
  `disable` or `daemon-reload` failing; and that it refuses a dangling
  linked unit without calling anything or changing the home. The stub
  `systemctl` fails `disable` when the unit does not resolve, as systemd
  255 does. It runs `linux-install-check.sh` without `systemd-analyze` on
  `PATH` and expects the fixed message, and, as the user, on tarballs of
  the stub `gateinto` with the shipped unit, with a misspelt key and with
  a missing `ExecStart` binary, expecting only the first to pass; it
  skips those three when `systemd-analyze` is not installed and says so.

### Security

The tarball gets a SHA-256 file like the Windows assets
(`.github/workflows/release.yml` runs `write-sha256.ps1` for them and
`write-sha256.sh` for the tarball). The checksum proves only that a
download matches the published file; nothing is signed. The installer is
shipped only inside the tarball, so it is covered by the same checksum,
and nothing is piped from the network into a shell. The
unit runs as the user, carries no credentials and does not set
`NoNewPrivileges` (Decision 11). `uninstall.sh` runs `systemctl` only from
an absolute path found on `PATH`, never from the working directory. No
step of install or uninstall replaces, exports or deletes a key.

### CI on `ubuntu-latest`

Build the tarball in `release-scripts`, check its contents, and shellcheck
any new script (done in step 15, together with the install and uninstall
checks described above). `systemd-analyze --user verify` checks that
`ExecStart` exists, so `linux-install-check.sh` verifies the unit after
`install.sh` has put the built binary at `$HOME/.local/bin/gateinto` in its
temporary home. It runs in the Linux `check` job of CI with the debug
build and in the `linux` release job with the release build (step 16).

### Manual and unverified

Install, upgrade and uninstall on a real desktop, including the
`gateinto://` handler that `install.sh` registers opening links in real
browsers; the unit starting with the graphical session, getting
`DISPLAY` or `WAYLAND_DISPLAY`, restarting after a crash, not restarting
after `gateinto stop`, and ending its browsers on stop; the unit failing
when an agent started on demand already runs; `systemctl --user disable
--now` from `uninstall.sh` against a real user manager (only its failure
on a dangling linked unit was reproduced, offline with systemd 255, which
is why `uninstall.sh` refuses that case); and `systemd-analyze --user
verify` on the hosted runners (it was run only locally with systemd
255).

## Area 7: device identity (open decision)

On Windows the device key is non-exportable, kept across upgrades, created
only by `setup`, and purged only explicitly
([security-model.md](../security-model.md)).
Any Linux backend must keep these properties: never write or export a
private key to a file, never silently replace or rotate the identity, and
claim no TPM behaviour that has not been verified.

| Option | Non-exportable | Notes |
| --- | --- | --- |
| TPM 2.0 through `/dev/tpmrm0`, persistent handle (`EvictControl`) | yes, if created in the TPM | `/dev/tpmrm0` is usually group `tss`, so the user needs membership; persistent handles are a small shared space; the key's `authValue` must be stored somewhere, which reintroduces a secret at rest |
| TPM 2.0, key blob wrapped by the TPM and stored on disk | yes in principle | the wrapped blob is a file; whether that conflicts with "never write private keys to files" must be decided explicitly |
| TPM via `tpm2-tss` (`tss-esapi` crate) vs a pure Rust client | same | `tss-esapi` adds a C library dependency; a pure Rust client adds protocol code to maintain |
| PKCS#11 through `p11-kit` (TPM, smart card, YubiKey) | depends on the token | the token decides; the user configures a module |
| Kernel keyring (asymmetric key type) | partly | the keyring can hold an asymmetric private key without read permission and sign with it, but the key material exists in user space before it is loaded, and it does not survive a reboot unless reloaded from somewhere; does not match the Windows guarantee |
| Secret Service | no | the key is readable by the user's processes; does not match the Windows guarantee |
| None | n/a | the current state |

The recommendation for this document is no recommendation: a prototype of
the TPM persistent-handle option, verified on real hardware, is the input to
the decision. Until then Linux runs without a device client certificate.

### Running without a device certificate

`load_client_identity` (`src/identity/client_cert.rs:409-427`) needs the
device key from the system store even for `client_cert_file`, and
`system_store()` fails on Linux, so:

- `client_certificate = "required"` fails to load the configuration
  (`src/identity/client_cert.rs:44-56`);
- `client_certificate = "optional"` (and the default) connects without a
  certificate and logs `unauthenticated_warning`
  (`src/identity/client_cert.rs:254-258`);
- `client_cert_file` and self-signed device certificates do not work either;
- a gateway that requires mTLS rejects the handshake, which the local client
  sees as 502;
- an interactive authentication challenge is ignored when no client
  certificate was sent (`src/proxy/mod.rs:622-633`), so device registration
  through [interactive-auth.md](interactive-auth.md) is impossible from Linux.

`status` and the documentation say this plainly.

## Security constraints

The constraints that hold on Windows hold on Linux without exception:

- TLS verification is never disabled.
- Listeners are loopback-only by default.
- Credentials and `Proxy-Authorization` are never logged.
- Links never carry credentials, CA or TLS settings or commands, and never
  start terminals.
- IPC never carries a shell, command, arguments or environment.
- Credentials are never placed in environment variables, including the
  unit's `Environment=` and the scope's environment.
- The shell and every helper (`systemd-run`, `systemctl`) are never resolved
  against the current directory; the agent's helpers use fixed absolute
  paths, and `uninstall.sh` uses `systemctl` from `PATH` only as an
  absolute path (Area 6).
- No real-gateway, browser, desktop or TPM behaviour is claimed until it has
  been verified.

### Threat-model additions

- **Same user.** Any process of the user can rewrite the XDG handler files,
  start units outside a scope, or read the user's `/proc` entries. The
  boundary is the user, as on Windows.
- **Other users.** `os_user` refuses sockets created by other uids and
  sockets that no live process of our uid holds; the IPC socket and
  directories are `0o600` and `0o700`.
- **`/proc` visibility.** Restrictions (containers, non-dumpable clients,
  kernels without `pidfd_open`) cause denials, never acceptances.
- **Root.** Running as root is warned against; root can bypass every check
  and is outside the model.
- **No device key.** Until Area 7 is decided, the gateway cannot tell a
  Linux device from any other client holding the user's proxy credentials.

## Compatibility

| Feature | Windows | Linux after this plan |
| --- | --- | --- |
| Proxy, agent, IPC, links, browser sessions | yes | yes (today) |
| `gateinto://` handler | registry | XDG files (Area 1) |
| `os_user` in terminal sessions | job + SID | scope + uid (Areas 2, 3) |
| `os_user` in browser sessions | job + SID | no (open question) |
| In-process terminal | yes | yes, with systemd user manager and cgroup v2 (Area 4) |
| Agent-hosted terminal | yes | no (Decision 15) |
| Device key | CNG / TPM | none until Area 7 |
| GUI | yes | no |
| Package | MSI | tarball, optional user unit |
| Other Unix | n/a | unchanged stubs |

## Decisions (proposed)

1. **Order.** Handler, owner lookup, containment, terminals, lifecycle,
   packaging, identity. The owner lookup comes before containment because
   its uid-level check is pure
   `/proc` parsing, testable on `ubuntu-latest` without systemd, and
   containment's membership test builds on it.
2. **Handler files are written directly**, not through `xdg-mime`.
3. **Unsafe path characters are refused, not escaped**, in `Exec`.
4. **Containment is a systemd user scope through `systemd-run`** at a fixed
   path, per Decision 14 of [terminal-session.md](terminal-session.md);
   without it, terminals are unavailable.
5. **`os_user` fails closed** on any unreadable `/proc` input.
6. **No agent-hosted terminal and no GUI on Linux.**
7. **Packaging is a tarball with an optional user unit**; install never
   creates a key and uninstall keeps key and configuration.
8. **Linux runs without a device certificate** until Area 7 is decided.
9. **The release target is `x86_64-unknown-linux-gnu`**, not `musl`,
   built on the fixed `ubuntu-24.04` image so the glibc floor does not
   drift with `ubuntu-latest`. The release build needs glibc 2.38 or
   newer: measured with `objdump -T` and `readelf -V` on a release build
   made locally on Ubuntu 24.04 (glibc 2.39), its newest required version
   is `GLIBC_2.38` (`__isoc23_strtol`, `__isoc23_sscanf`), and the
   `GLIBC_2.39` symbols (`pidfd_spawnp`, `pidfd_getpid`) are weak. It has
   not been run on an older glibc or on other distributions.
10. **An installer script ships only inside the tarball.** The user
    verifies the SHA-256, extracts the tarball and runs `install.sh`
    locally; uninstall is `uninstall.sh` from the same tarball. Nothing is
    hosted for `curl | sh`.
11. **The user unit does not set `NoNewPrivileges=true`.** It would be
    inherited by the browsers the agent starts and disable Chrome's setuid
    sandbox fallback on systems that restrict unprivileged user namespaces
    (for example Ubuntu 24.04 with AppArmor).
12. **The user unit belongs to `graphical-session.target`**
    (`WantedBy=`, `PartOf=`, `After=`), not `default.target`, so the agent
    runs only in a graphical session and after desktops that import the
    display variables before that target have done so. Desktops without
    the target do not start it.

## Implementation plan

Each step is one pull request into `feat/linux`, test first: a failing test,
the minimal code to pass it, then a refactor.

Documentation lands with the step that creates the boundary it describes,
not at the end.

1. **Exec quoting.** Linux `handler_command` and `is_handler_command` with
   ` -- %u` and the extra refused characters.
2. **XDG paths and `mimeapps.list` parser.** Root resolution (relative values
   ignored), parse and edit that keeps unrelated content.
3. **Effective default lookup.** `registered_command` on Linux: the lookup
   order, `;`-separated lists, uninstalled ids falling through.
4. **Atomic file writes** for the desktop file and `mimeapps.list`: temp
   file and rename, modes, symlink and ownership refusal.
5. **`register` and `unregister` on Linux**: per-scheme foreign detection,
   rollback, the override warning and the changed `register` signature (on
   Windows too); the integration test with `gio`; the handler boundary in
   `docs/security-model.md` and `docs/threat-model.md`.
6. **`/proc` parsers.** `net/tcp{,6}` (`LinuxRow`, byte order, inode 0),
   `status` uids, `cgroup`.
7. **Linux `Owners` at uid level** with pidfd liveness, row re-read,
   positive-finding acceptance and the deadline passed into the scan;
   `os_user` loads on Linux; the `sudo -u nobody` end-to-end test (403);
   the `os_user` boundary in `docs/security-model.md`,
   `docs/threat-model.md` and the `os_user` section of
   `docs/compatibility.md`.
8. **Containment prerequisites.** `Job::new` on Linux checks cgroup v2, the
   user manager, the delegated cgroup and `systemd-run`; unit tests against
   fake trees.
9. **Scope spawn** with the `linux-systemd` CI job: `systemd-run` arguments
   and the post-spawn cgroup confirmation.
10. **Scope teardown**: `cgroup.kill`, `populated 0`, the `systemctl` fallback;
    the containment boundary and its escapes in `docs/security-model.md`
    and `docs/threat-model.md`.
11. **Stale-scope sweep.**
12. **Scope membership in `os_user`** (`NotInJob` for clients outside the
    scope).
13. **In-process terminal on Linux.** Remove the stub, signal handling, tty
    foreground handoff and restore; enable the shared tests.
14. **Status and setup output** for Linux; root warning; help text.
15. **Tarball build and release scripts.**
16. **User unit** and `systemd-analyze --user verify` in CI.
17. **Install and uninstall documentation** in `docs/install.md`.
18. **Identity prototype**, after the decision in Area 7; not scheduled by
    this document.

Steps 9 to 13 are gated on the prototype questions of Decision 14 being
answered on real systems; if the answers are negative, steps 1 to 8 and 14
to 17 still ship and terminals stay unavailable on Linux.

## Open decisions

- **Device identity backend** (Area 7): TPM persistent handle, wrapped blob,
  PKCS#11, or none; `tss-esapi` vs pure Rust; where an `authValue` lives;
  group `tss` membership.
- **Desktop file id**: `<scheme>.desktop` (`gateinto.desktop`) or a
  reverse-DNS id.
- **Fallback without systemd** for terminals, or none.
- **`systemd-run` vs `zbus`** for scope management.
- **`systemd-run` location** on NixOS and other layouts without
  `/usr/bin/systemd-run`.
- **`os_user` in browser sessions**: a scope for the browser and whether
  Chrome's non-dumpable processes allow the holder check.

## Needs verification

- Firefox, Chrome and Chromium on GNOME and KDE open `gateinto://` links
  through the `mimeapps.list` default without `update-desktop-database`;
  `NoDisplay=true` keeps the handler eligible.
- `gio` is on the `ubuntu-latest` image.
- How GIO and each desktop treat a `Hidden=true` default, and a default
  without `Exec`, when deciding the override warning.
- The hosted runner allows `loginctl enable-linger` and a user manager with
  a delegated cgroup subtree.
- Transient user scopes are created under `app.slice` on the supported
  systemd versions.
- `systemd-run --user --scope` works when started from a
  `session-<n>.scope` (SSH, VT, desktop session), not only from inside
  `user@<uid>.service`.
- `cgroup.kill` and `populated 0` timing on supported kernels; teardown of
  double-forked and `setsid` children on real desktops; the `systemctl`
  fallback on kernels older than 5.14.
- The holder scan in containers and its cost on a busy desktop.
- tty foreground handoff and restore, and signal behaviour, in real terminal
  emulators.
- The user unit with `graphical-session.target` on GNOME, KDE and other
  desktops: whether they reach that target and import `DISPLAY` and
  `WAYLAND_DISPLAY` before it; Chrome's sandbox when started from the unit
  on systems that restrict unprivileged user namespaces; restart after a
  crash; browsers ended by `KillMode=control-group` on stop; the unit
  failing at the start limit when an on-demand agent already runs;
  `systemctl --user disable --now` from `uninstall.sh` against a real
  user manager.
- Every TPM behaviour named in Area 7.
- The gateway outcomes listed in [Running without a device
  certificate](#running-without-a-device-certificate) against a real gateway.
