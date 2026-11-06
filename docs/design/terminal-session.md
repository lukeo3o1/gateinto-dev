# Design: terminal sessions

Status: design decided; the in-process and agent-hosted variants are
implemented, the GUI entry is not. The decisions are listed in
[Decisions](#decisions). None of the behaviour it expects from shells,
terminals or tools has been tried on a real Windows or Linux system; what
must be checked first is under [Needs verification](#needs-verification).
Names marked *(proposed)* do not exist in the code yet; every other name
refers to code on `master` at the time of writing.

## Summary

A terminal session starts a shell inside a new Windows job object and binds it
to a new session that accepts only `os_user` local authentication, restricted
to that job. The shell gets `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` (and
lowercase variants) set to `http://127.0.0.1:<port>` and a `NO_PROXY` for
loopback. Processes the shell starts inherit both the job and the variables,
so tools that read proxy variables tunnel through the gateway without any
credential.

The first version has two entry points on Windows:

- **In-process:** `gateinto session terminal` runs the session in the CLI
  process and the shell in the console it was run from.
- **Agent-hosted:** `gateinto session terminal --agent` or
  the GUI's "Open terminal" button asks the running agent over IPC; the agent
  opens the shell in a new console window, lists the session in
  `gateinto session list`, and closes it on `gateinto session close` or
  `gateinto stop`.

The first version is Windows-only. Linux is a later phase that starts with
a prototype of option (i), a systemd user scope, verified on real systems; it
is CLI-only (in-process), without an agent-hosted variant. See
[Linux](#linux).

## Goals

- Let command-line tools that honour proxy environment variables (curl, git,
  pip, cargo, Go and .NET programs, ...) use a gateway without the user typing
  or storing a proxy credential.
- Offer the same session from the CLI, in the current console, and from the
  agent, in a new window that the GUI and `gateinto session list` can see and
  close.
- Reuse the existing pieces: `crate::job::Job` (`src/job.rs`), the `os_user`
  owner check with `IsProcessInJob` (`src/proxy/os_user.rs`,
  `src/proxy/os_user/windows.rs`), `LocalAuth::OS_USER`
  (`src/proxy/local_auth.rs`), `SessionManager` (`src/sessions.rs`) and the
  agent's child bookkeeping (`src/agent.rs`).
- Keep every existing rule: loopback-only listener, routes as in
  [session routing](../protocol/launch-uri.md#session-routing), credentials
  never written to disk or logged, links never carry commands, the GUI never
  starts the agent on its own and never writes TOML.

## Non-goals

- Linux in the first version, and macOS at all. On those platforms both entry
  points fail before binding a port: `os_user::system` and `Job::new` already
  return `Unsupported` there. The Linux plan is in [Linux](#linux).
- An agent-hosted terminal on Linux (no portable "new console window"; see
  [Linux](#linux)).
- Changing system proxy settings (WinINet, WinHTTP, PAC, registry). Programs
  that use WinINet or WinHTTP proxy settings instead of environment variables
  are not covered.
- Covering processes outside the job: services, scheduled tasks, COM servers,
  daemons that were already running, elevated processes started through UAC.
- Plain-HTTP (absolute-form) proxying in the first version; see
  [Plain HTTP](#plain-http-absolute-form-requests).
- Isolation from malicious code of the same user (unchanged non-guarantee of
  `os_user`).
- Choosing a shell, command, argument or environment variable from a link, an
  IPC request or the GUI.

## What exists today

- `gateinto session browser` (`browser_session` in `src/main.rs`) runs a
  session in the CLI process itself, with `LocalAuth::SESSION_CREDENTIALS`,
  the `gateway` route and no job. It starts no browser.
- Agent launches (`Agent::start` in `src/agent.rs`) create a job
  (`browser_job`), start the browser in it with `Job::spawn`, and bind a
  session with `browser_local_auth(true)`, i.e. `os_user` plus
  `session_credentials`. If the job cannot be created or used, the browser
  starts without one and the session falls back to `session_credentials`
  only. On other platforms `browser_job` returns `None`, so browser sessions
  there offer `session_credentials` only.
- The agent keeps each started browser in `Inner::browsers`, a
  `BTreeMap<SessionId, Browser>` holding a close sender and the task of
  `watch`. `watch` waits for the browser to exit or for the close signal,
  then stops the job (`release` or `kill`), closes the session, removes the
  profile and the map entry. `Agent::close` and `Agent::close_all` (used by
  `Request::Stop`) send the close signal and await the task. `Agent::list`
  returns one `SessionInfo` line per session, with the browser name joined in.
- Agent limits (`AgentLimits`): `launches` (5) per `launch_window` (60 s)
  through `LaunchLimiter`, `max_browser_sessions` (4) through
  `check_capacity`, which counts only `Inner::browsers`.
- IPC (`src/ipc.rs`): one request line of at most `MAX_REQUEST_BYTES` (8192)
  per connection. `Request` has `Launch`, `Approve`, `Deny`, `List`, `Close`,
  `Credentials`, `Stop`, `Log` and `Config`. A `launch` line is parsed by
  splitting on spaces, accepting keys only in a fixed order, and then checking
  that `Request::to_string` reproduces the line exactly. On Windows the named
  pipe rejects remote clients and has an owner check; on Unix the socket is in
  a private directory owned by the user and set to mode `0600`.
- The agent is started by `spawn_agent` (`src/main.rs`) with
  `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP` on Windows, and with its own
  process group on Unix; it has no console and null standard handles. Its
  current directory is the one it was started from.
- The agent reads `[browser] executable` from the configuration file once, at
  start, into `AgentOptions::browser`. `ConfigFile` has
  `deny_unknown_fields`.
- The GUI talks to the agent only over IPC. `gui/src/worker.rs` maps
  `Command::Launch(GatewayName)` to a `launch` request; `Command::Start`
  starts the agent and is sent only by the explicit Start agent button. The
  gateways page offers a launch only while `AgentState::Running`
  (`gui/src/gateways.rs`, test `only_a_running_agent_can_start_a_browser`).
  In demo mode `gui/src/demo.rs` answers requests (`answer`) and maps
  commands to refusal texts (`refusal`). `gui/src/sessions.rs` maps
  `SessionKind::Browser` and `SessionKind::Unknown` to rows.
- `Job::new` (`src/job.rs`) creates an unnamed, non-inheritable job with
  only `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Neither
  `JOB_OBJECT_LIMIT_BREAKAWAY_OK` nor `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`
  is set, so `CREATE_BREAKAWAY_FROM_JOB` is refused for processes in it.
  `Job::spawn` uses `PROC_THREAD_ATTRIBUTE_JOB_LIST`, falling back to
  `CREATE_SUSPENDED` plus `AssignProcessToJobObject`. It passes a null
  environment (the child inherits Gateinto's), a null current directory, no
  inherited handles and no console flags.
- `Process::kill` and `Drop for Process` terminate the job and wait up to 5
  seconds for `JobObjectBasicAccountingInformation` to report no active
  process.
- With `LocalAuth::OS_USER` alone, a connection the owner check denies gets
  `403 Forbidden` with `Connection: close` (`Authenticator::check`), or `408`
  when the owner lookup does not finish before the handshake deadline
  (`Shared::handle` in `src/proxy/mod.rs`).
- Non-`CONNECT` requests: `parse_connect_request` (`src/http.rs`) first
  requires a well-formed `HTTP/1.1` request line; anything else, for example
  an `HTTP/1.0` absolute-form request, is `ParseError::Malformed` and gets
  `400`. A well-formed `HTTP/1.1` head with any other method is
  `ParseError::MethodNotAllowed` and gets `405 Method Not Allowed` with
  `Allow: CONNECT`. Absolute-form requests such as
  `GET http://example.com/ HTTP/1.1` are therefore refused locally and never
  reach DNS, routing or the gateway.
- Link and IPC launch auth is `LaunchAuth::SessionCredentials` only
  (`src/uri.rs`); the URI parser refuses unknown fields.
- `SessionKind` (`ipc-types/src/lib.rs`) has only `Browser`; unknown values
  deserialize as `Unknown`. `SessionInfo` has no `deny_unknown_fields`, so
  older readers ignore new optional fields.

## Design

### Two variants

**Decision: both variants ship in the first version, on Windows.**

| | In-process | Agent-hosted |
| --- | --- | --- |
| Started by | `gateinto session terminal` | `gateinto session terminal --agent`, GUI button |
| Session lives in | the CLI process | the agent |
| Console | the CLI's | a new one (`CREATE_NEW_CONSOLE`) |
| Shell | `--shell` > `[terminal] shell` > default | `[terminal] shell` > default |
| `session list`, `close`, `stop` | not visible, not affected | listed, closable, closed by `stop` |
| Agent needed | no | yes, already running |
| Ends when | the shell exits or the CLI ends | the shell exits, the session is closed, or the agent ends |

Both use the same job settings, local authentication, environment, routes and
plain-HTTP behaviour. Shared code lives in a `terminal` module
with pure helpers (`terminal_environment`, `resolve_shell`, `terminal_route`)
and one spawn function used by both variants.

`SessionKind::Terminal => "terminal"` is added to `ipc-types`;
older clients already read it as `Unknown`.

### In-process variant

`gateinto session terminal` creates the job, binds the session with that job
as `proxy::Config::os_user_job` (it must exist before `SessionManager::start`,
as in `Agent::start`), and then starts the shell in the job, in the console it
was run from; the shell replaces the interactive prompt until it exits. No
agent is needed.

The lifetime is the shell's, and teardown is guaranteed by
`KILL_ON_JOB_CLOSE` even if `gateinto.exe` is killed, because Gateinto never
duplicates or passes on the job handle. A process of the same user that
duplicates it from Gateinto keeps the job, and every process in it, alive
after Gateinto ends; this is part of the same-user non-boundary in
[Security](#security). Like `session browser`, the session is not shown
by `gateinto session list`, cannot be closed by `gateinto session close` and
is not stopped by `gateinto stop`.

### CLI shape

```text
gateinto session terminal [--config PATH] [--gateway NAME] [upstream options]
                          [--route saved|gateway|mixed] [--shell PATH] [-- ARGS...]
gateinto session terminal --agent --gateway NAME [--route saved|gateway|mixed]
```

- Gateway selection and upstream options: the same `UpstreamArgs` and
  `--gateway` as `BrowserSessionArgs` (config-file gateways only).
- `--route`: `saved` (default), `gateway` or `mixed`; see
  [Routes](#routes).
- `--shell`: executable to start, overriding the
  [shell preference](#shell-selection). A value containing a path separator
  (`\` or `/`) or a drive is a path, resolved against the current directory
  when relative. A drive-relative value (a drive prefix without a root, for
  example `C:tools\sh.exe`) is refused: `Path::join` with a drive prefix
  discards the base, and Windows resolves it against the process's per-drive
  current directory. A root-relative value (a root without a drive, for
  example `\tools\sh.exe`) is refused too: Windows resolves it against the
  current drive. A bare name (no separator) is searched in the
  directories of `PATH` only, never in the current directory, trying the name
  as given and then with each extension of `PATHEXT`. The result must be an
  existing file.
  `ARGS` after `--` are passed to it, quoted by the existing `command_line`
  (`src/job.rs`), which already refuses quotes in the executable path and NUL
  characters. `ARGS` require `--shell`; without it the arguments come from
  `[terminal] args`.
- `--agent`: send a [`terminal` request](#ipc) to the running agent instead of
  running in-process, print the agent's answer and return. It requires
  `--gateway` and refuses `--shell`, `ARGS`, `--config` and upstream options,
  because the request carries none of them; the agent uses its own
  configuration. If no agent runs, the command fails with the usual "no agent
  is running" error (`RequestError::NotRunning`); it never starts one.
- In-process, before starting the shell it prints, on standard output:
  `session`, `kind: terminal`, `gateway`, `listen`, `route`, `auth: os_user`,
  and `replaced: <names>` with the names (not values) of proxy variables it
  replaced. On standard error it prints notices: that `http://` URLs are
  refused ([Plain HTTP](#plain-http-absolute-form-requests)), and, when the
  route is `mixed`, the direct-connection warning ([Routes](#routes)). It
  prints no credential because there is none.
- In-process exit code: the shell's exit code, a 32-bit Windows value passed
  through unchanged with `std::process::exit` (an `ExitCode` built from a `u8`
  would truncate it). Gateinto's own errors before the shell starts use its
  usual exit codes; a shell can return the same values, so the exit code alone
  does not tell a Gateinto error from a shell result, but Gateinto's errors
  are always printed on standard error. `std::process::exit` skips
  destructors, so it is called only after the job has been terminated (and
  found empty or the 5-second wait has ended) and the session has been closed.
  With `--agent` the exit code is Gateinto's own, as for other agent requests.

New code: `SessionCommand::Terminal(TerminalSessionArgs)` in
`src/main.rs`.

### Shell selection

**Decision: `--shell` flag > `[terminal] shell` in the configuration file >
platform default.** The flag exists only in the in-process variant.

```toml
[terminal]
shell = "pwsh.exe"
args = ["-NoLogo"]
```

`TerminalSection { shell: Option<PathBuf>, args: Vec<String> }`
in `src/config.rs`, `deny_unknown_fields` like the other sections. `args` are
passed like `ARGS` and are used only together with `shell`; both keys ship
in the first version. The platform default is `%ComSpec%` on Windows; for the
later Linux phase it is `$SHELL`, then `pw_shell` from
`getpwuid_r(getuid())`, then `/bin/sh`.

Resolution of `shell`, never against the current directory:

- an absolute path is used as is;
- a relative path with a separator (`\` or `/`), for example
  `tools\sh.exe`, is resolved against the directory of the configuration
  file, like other relative paths in it;
- a drive-relative value (a drive prefix without a root, for example
  `C:tools\sh.exe`) is refused, as for `--shell`: joining it would discard
  the configuration file's directory and depend on a per-drive current
  directory;
- a root-relative value (a root without a drive, for example
  `\tools\sh.exe`) is refused, as for `--shell`: joining it would discard
  the configuration file's directory and depend on the current drive;
- a bare name (no separator), for example `pwsh.exe`, is searched in the
  directories of `PATH`, trying the name as given and then with each
  extension of `PATHEXT` on Windows, as for `--shell`.

The result must be an existing file. This differs from `[browser]
executable`, which `ConfigFile` loading joins with the configuration file's
directory unconditionally (`base.join` in `src/config.rs`). `shell` must not
go through that join, or `pwsh.exe` would become `<config dir>\pwsh.exe`; the
join is applied only to values with a separator.

Options considered:

| Option | Assessment |
| --- | --- |
| `[terminal] shell` key, edited by the user | **Recommended.** Same model as `[browser] executable`: a user-owned file read by the CLI on each run and by the agent at start. Not settable from links, IPC or the GUI. |
| Linux `$SHELL`, then `pw_shell` | Recommended as the default for the later Linux phase. Both are the user's own choice; `$SHELL` comes from the environment the agent or CLI was started with. |
| Windows `%ComSpec%` | Recommended as the Windows default; normally `cmd.exe`. Comes from Gateinto's environment, like `PATH`. |
| `pwsh.exe` found on `PATH` | Not as a default: the default shell would change silently when PowerShell 7 is installed or removed, without the user choosing it. A user who wants it writes `shell = "pwsh.exe"`; that is the user's explicit choice, and its `PATH` search works like that of any bare name (in the agent, with the agent's start-time `PATH`). |
| Windows Terminal's default profile | Not worth it: `settings.json` lives in a package directory with a changing schema, profiles hold full command lines (not an executable) that would have to run verbatim, and dynamic profiles (WSL, Azure Cloud Shell) do not map to a local executable in a job. |

Security: the preference must come only from places the user owns and an
attacker on the other side of a trust boundary cannot set. A link is
attacker-controlled; an IPC request can come from any process of the user,
including a link handler started by a browser; the GUI never writes TOML. So
the `terminal` IPC request has no shell, argument or environment field, the
URI has none, and the GUI has no shell setting. A process that can write the
configuration file already runs as the user and could start any program
itself, so the file is not a new boundary. The agent reads the key once at
start, like `[browser] executable`; changing it needs an agent restart.

Compatibility: `ConfigFile` rejects unknown keys, so an older Gateinto fails
to load a configuration file that has a `[terminal]` section. The release
notes must say so.

### IPC

**Decision: one new request, `terminal`, without any shell, command,
argument or environment field.**

```text
terminal <gateway> route=<saved|gateway|mixed>
```

(`Request::Terminal(TerminalRequest { gateway: GatewayName, route:
Option<Route> })`, `None` meaning `saved`)

- `<gateway>` is required and must parse as a `GatewayName`; it names a gateway
  in the agent's configuration file. Gateways approved from links are refused
  ([Decisions](#decisions), 4). There is no gateway address, URL or
  portal field, so a `terminal` request can never add a gateway and never
  needs a confirmation; `Approve` and `Deny` are not involved.
- `route=` is always present, so the line has one spelling and no default to
  get wrong. The GUI sends `route=saved`.
- Parsing follows `launch`: split on single spaces, exact word count, then
  check that `Request::to_string` reproduces the line; anything else is
  `invalid terminal request`. Any extra word, including `shell=`, `command=`,
  `args=` or `env=`, makes the line invalid.
- Answer lines: `session: <id>`, `gateway: <name>`, `listen: <addr>`,
  `route: <route>`, `auth: os_user`, `shell: <file name>`, then the
  `warned` lines (`Known::error_lines`) as for `launch`, and the mixed-route
  warning when the route is `mixed`. No credential lines.
- An older agent answers `invalid request`; the CLI and GUI show "the agent is
  too old for terminal sessions; restart it".
- On platforms without terminal sessions the agent answers an error saying so,
  after the rate limit and before resolving the gateway.
- `SessionInfo` gains `shell: Option<String>`, the shell's file
  name (for example `pwsh.exe`), serialized only when present. `session list`
  and `session_table` (`src/session_table.rs`) show `kind: terminal`;
  `session credentials <id>` answers "session <id> has no credentials", the
  existing text.

### Agent-hosted variant

`Agent::handle` maps `Request::Terminal` to `Agent::terminal`:

1. Take a slot from the shared `LaunchLimiter` (browser and terminal
   requests share one budget, so a local process cannot open windows faster
   than browsers). Then ask the launcher whether terminals are supported
   (`Launcher::terminals() -> bool`; `System` answers `cfg!(windows)`, test
   launchers answer what the test needs) and answer
   the unsupported error if not. Then check a separate capacity,
   `AgentLimits::max_terminal_sessions` (default 4), against the
   number of terminals.
2. Resolve the gateway, the route ([Routes](#routes)) and the shell
   ([Shell selection](#shell-selection)). Only configuration-file gateways
   are accepted, in both variants, matching `gateinto session browser`: a
   name that is not in the file's gateways is refused, the check
   `ConfigProfiles::browser_session` already makes as `configured`
   (`src/main.rs`), and the plan is built from the file alone, without
   `ConfigFile::with_linked`. A gateway approved from a link is refused even
   though the agent knows it.
3. Create a job with `Job::new`. On failure, answer an error and start
   nothing; there is no fallback.
4. Start a session with `kind: SessionKind::Terminal`, `LocalAuth::OS_USER`,
   `os_user_job: Some(job)` and listen `127.0.0.1:0`.
5. Build the environment from the agent's own environment
   ([Environment](#environment)) and spawn the shell in the job through
   `spawn_blocking`, with `CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT`,
   current directory `%USERPROFILE%` (the agent's own current directory is
   wherever it was started from), and a window title `Gateinto: <gateway>`
   in `STARTUPINFOW::lpTitle` (the shell may change it). Not
   `CREATE_NEW_PROCESS_GROUP`. Ctrl-C in the new console needs more; see
   [Ctrl-C in the agent-hosted console](#ctrl-c-in-the-agent-hosted-console).
   On `SpawnError::Job` or any other spawn error, close the session and
   answer an error.
6. Register the terminal and spawn its watch task, then answer.

Bookkeeping: a second map, `Inner::terminals`, holds each terminal's shell
name, close sender and task next to `Inner::browsers`. Each kind has its
own capacity check; `list` joins the browser name or the shell name; `close`
and `close_all` handle both kinds the same way.

Watch task: like `watch`, without a profile directory. It selects on the
shell's exit and the close signal. On exit it terminates the job (ending
background processes the shell left) and waits up to 5 seconds; on the close
signal it calls `Process::kill`. Then it closes the session and removes the
entry. It logs the shell's exit code at `info`.

Lifetime:

- **Shell exits** (the user types `exit` or closes the window): the job is
  terminated, the session closed, the entry removed. Closing a console
  window sends `CTRL_CLOSE_EVENT` to the processes on that console only; the
  agent is not attached to it.
- **`gateinto session close <id>`** or the GUI's close button: the job is
  killed, so the window closes with the shell and everything started from it,
  including unsaved work in editors.
- **`gateinto stop`**: `Request::Stop` runs `close_all`, which closes
  terminals like browsers. `gateinto stop` and the GUI's Stop button say how
  many terminal sessions are closed: the agent's stop answer has a
  `terminals-closed: <n>` line, which `gateinto stop` prints as "closed <n>
  terminal sessions" when it is not 0; the GUI's count is not implemented
  yet. The GUI asks for
  confirmation first while terminals are open ([GUI](#gui)); `gateinto stop`
  and `gateinto session close` do not ask.
- **Agent ends** (killed, crash, logoff): the job handles close with the
  process and `KILL_ON_JOB_CLOSE` ends every shell. The handles are
  non-inheritable and Gateinto never duplicates or passes them on. A process
  of the same user that duplicates a handle from the agent keeps that job and
  its shell alive; this is the same-user non-boundary in
  [Security](#security).
- **Console events in the agent.** It depends on how the agent was started:
  - started through `spawn_agent` (`gateinto agent --detach`, which is also
    what the GUI's autostart writes as the `HKCU` `Run` value
    `AGENT_RUN_VALUE`, see `gui/src/settings.rs` and `gui/src/win/run.rs`):
    the agent has no console (`DETACHED_PROCESS`) and is in a new process
    group, so no console event reaches it, and closing or pressing Ctrl-C in
    a terminal window affects only that console;
  - started in the foreground (`gateinto agent` typed in a console): the
    agent has that console and is not in a new process group, so Ctrl-C
    there stops the agent through `shutdown_signal`, which ends every
    terminal. The terminals have their own consoles, so Ctrl-C in a terminal
    does not reach the agent.

  In neither case does the agent need the in-process variant's Ctrl-C
  listeners.
- Whether the console host and, on Windows 11, a Windows Terminal window
  chosen as the default terminal application close when the job is killed,
  and whether the console host itself runs inside the job, needs
  verification. Proposed fallback if a window outlives the job or the
  console host runs outside it: the agent forces the classic console host
  (conhost) for terminal windows. How to force it for one process without
  changing the user's default terminal setting needs verification too.

Environment source (decided): the agent's environment is the one it was
started with (by the GUI, the autostart `Run` value or a CLI). Variables the
user changed later, such as `PATH`, are not seen until the agent restarts.
Rebuilding the user's environment with `CreateEnvironmentBlock` would avoid
that but needs a user token and differs from the in-process variant, so it
is not done.

#### Ctrl-C in the agent-hosted console

Needs verification. `spawn_agent` (`src/main.rs`) starts the agent with
`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`. The `CreateProcess`
documentation says that with `CREATE_NEW_PROCESS_GROUP` Ctrl-C is disabled
for the processes in the new group, and the `SetConsoleCtrlHandler`
documentation says that the "ignore Ctrl-C" attribute is inherited by child
processes. A shell the detached agent starts may therefore ignore Ctrl-C,
even in its own console and its own group: Ctrl-C would not stop `ping -t`.
A foreground `gateinto agent` is not in a new group, so the problem would
not appear there.

Proposed fix *(needs verification)*: the agent calls
`SetConsoleCtrlHandler(NULL, FALSE)` once at start, before it can spawn any
terminal, so that children inherit normal Ctrl-C processing. To verify: that
the call succeeds in a process without a console, and that it really clears
the inherited attribute for children. In a foreground agent the attribute is
normally not set, unless inherited from its parent, so the call normally
changes nothing there. If the call fails, the agent logs
a warning and terminal windows work without Ctrl-C; that is a usability
defect, not a security one, but it blocks shipping the agent-hosted variant.

Alternatives checked: no documented `CreateProcess` flag, `STARTUPINFO`
field or `PROC_THREAD_ATTRIBUTE_*` resets the attribute for one child as far
as the documentation shows; the attribute lives in undocumented process
parameters, which Gateinto must not write. Dropping
`CREATE_NEW_PROCESS_GROUP` from `spawn_agent` may also work, since a
detached agent has no console to receive events anyway, but it changes
existing behaviour. Decision: if verification shows that the reset does not
restore Ctrl-C for the agent's children, `spawn_agent` drops
`CREATE_NEW_PROCESS_GROUP` and keeps `DETACHED_PROCESS`; that this restores
Ctrl-C needs verification too.

### GUI

The gateways page shows an "Open terminal" action *(proposed)* next to the
browser launch, under the same condition as `page(..).launch`: only while the
last poll found the agent running (`AgentState::Running`). It is hidden while
the agent is stopped or unreachable, and pressing it never sends
`Command::Start`; the explicit Start agent button stays the only way to start
the agent.

- `Command::Terminal(GatewayName)` *(proposed)* in `gui/src/worker.rs` maps
  to `Request::Terminal` with `route: None` (`route=saved`) in
  `Command::request`. In `serve_with` it follows `Command::Launch`: the
  `launch` flag becomes `matches!(command, Command::Launch(_) |
  Command::Terminal(_))`, so a refused or finished terminal request also
  increases `launched`, which `Launches::settle` (`gui/src/gateways.rs`) uses
  to clear the row's pending state; it is checked with `refuse` first (demo
  mode); and it joins `Command::Close | Command::Stop | Command::Launch` in
  the arm that falls through to `run`, so its error becomes a note. The row
  has one pending action at a time, shared by the browser and terminal
  buttons.
- New strings in `gui/src/i18n.rs`, in English and Chinese *(proposed
  `Text` variants)*: the "Open terminal" action, the "Terminal" session
  title fallback, the "agent too old" note, the demo refusal, and the two
  confirmations (closing a terminal; stopping the agent with terminals
  open) with their buttons.
- `gui/src/sessions.rs` maps `SessionKind::Terminal` to a terminal row whose
  title is the shell name; its close button sends the existing
  `Command::Close`. There is no credentials button, because the session has
  none.
- **Confirmation (decided).** Closing a terminal row always asks first,
  because it kills the shell, everything started from it and unsaved work.
  The Stop button asks first when the last session list contains at least
  one terminal, naming how many; with none it stops at once, as today.
  Cancelling sends nothing. The dialog follows the existing remove-gateway
  confirmation in `gui/src/board/dialog.rs` (`Zone::ConfirmRemove`).
  Closing a browser row does not ask. The CLI's `gateinto stop` and
  `gateinto session close` never ask.
- The GUI has no shell setting and shows no TOML editor; its own settings
  stay in the registry. `[terminal]` is edited only by the user.
- Demo mode: `demo::answer` answers `Request::Terminal` with an empty `ok`
  like `Launch`, `demo::refusal` maps `Command::Terminal` to `NOT_STARTED`,
  and the sample sessions include one terminal so the row can be seen.

### Links

**`gateinto://` links never start terminal sessions.** No field selects a
session kind, shell, command, argument or environment variable, and none will
be added. The link handler builds only `Request::Launch`; nothing converts a
`LaunchRequest` into a `Request::Terminal`.

- Links are attacker-controlled
  ([security model](../security-model.md#launch-uris-and-the-agent)): any web
  page, e-mail or document can open one. A browser session runs web content in
  a fresh profile; a terminal runs whatever the user, or text pasted from that
  page, types into it, with gateway access.
- A command field would make the agent a remote command launcher. Even
  without one, a page that opens a shell window, already connected to the
  gateway, can ask the user to paste a command into it.
- A terminal is always a deliberate local action; there is no workflow that
  needs it from a link.

The URI parser already refuses unknown fields; tests pin that `kind`,
`shell`, `command` and `args` are refused.

### Local authentication

- **`os_user` only, always with the job.** The session uses
  `LocalAuth::OS_USER` with `os_user_job: Some(job)`. If the job cannot be
  created or the shell cannot be put in it (`SpawnError::Job`), nothing is
  started. There is no fallback, unlike browser launches, because the
  fallback would be `session_credentials`.
- **No `session_credentials` (decided exception).** Terminal sessions are an
  accepted exception to the rule that every session accepts
  `session_credentials`. They offer none, so there is nothing to show, store
  or leak, and a process outside the job is denied (`403` and close, or `408`
  when the owner lookup times out) instead of getting a `Basic` challenge.
- **Never in environment variables.** Credentials must not be put into proxy
  URLs (`http://user:pass@127.0.0.1:<port>`): every child inherits the
  environment, any process of the same user can read it, crash dumps and
  diagnostics capture it, and many tools print the proxy URL in verbose
  output, error messages or logs.
- **Documentation change required.** With the implementation, update the
  [security
  model](../security-model.md#local-proxy-authentication-session_credentials),
  which says that every session accepts `session_credentials` and that no
  setting removes them, to name the terminal exception; the [`os_user`
  section](../security-model.md#local-proxy-authentication-os_user), which
  says `os_user` is offered by browser sessions next to
  `session_credentials` and that "`session_credentials` is always offered
  too" (the "Clear fallback" guarantee); the threat model's trust boundary;
  and `docs/verification.md`.
- Small wording changes: `Denial::NotInJob` says "outside the session's
  browser" and `Drop for Process` says "the browser's job"; both become
  neutral ("the session's job").

### Environment

The shell's environment is the starting process's environment (the CLI's or
the agent's) with these changes (`terminal_environment(inherited,
listen) -> (vars, replaced)`):

| Name | Value |
| --- | --- |
| `HTTPS_PROXY`, `https_proxy` | `http://127.0.0.1:<port>` |
| `HTTP_PROXY`, `http_proxy` | `http://127.0.0.1:<port>` |
| `ALL_PROXY`, `all_proxy` | `http://127.0.0.1:<port>` |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` |

- The scheme is `http://` because the client speaks plain HTTP `CONNECT` to the
  local listener; the tunnelled TLS is end to end. The address is the session's
  actual `local_addr()`, always IPv4 loopback.
- **Existing values are replaced, never merged.** Every inherited variable
  whose name matches one of the four names case-insensitively (for example
  `Https_Proxy`) is removed first, on every platform. Keeping a user's proxy
  would send traffic around the tunnel. The replaced names are printed; their
  values are not, because proxy URLs often contain credentials.
- **Both spellings (decided).** Both the uppercase and the lowercase name are
  written, with identical values. Windows treats environment names
  case-insensitively, but MSYS2 and Cygwin programs (Git Bash) import the
  block case-sensitively and some only read the lowercase names; on Linux
  names are case-sensitive and tools differ (curl, for example, reads only
  lowercase `http_proxy`), so both are needed there. Risks on Windows that
  still need verification:
  - .NET Framework's `ProcessStartInfo.EnvironmentVariables` builds a
    case-insensitive dictionary and throws "Item has already been added" on
    names that differ only in case (the known `Path`/`PATH` problem), which
    can break Windows PowerShell 5.1 `Start-Process`, MSBuild and other .NET
    Framework programs that start processes from the shell;
  - `set HTTPS_PROXY=` in cmd may clear only one of the two entries, leaving
    the other in effect;
  - which entry Windows APIs return for a duplicated name.

  If verification confirms one of them as a real breakage, the manual
  checklist result goes to `docs/verification.md` and the decision is
  revisited.
- **`NO_PROXY`.** Loopback only, so tools reaching local development servers
  do not tunnel them; under the `gateway` route such a request would otherwise
  reach the gateway's own loopback. Inherited `NO_PROXY` entries are dropped,
  since they would let named hosts bypass the tunnel. CIDR forms such as
  `127.0.0.0/8` are not understood by every tool and are left out.
- No other variable is set or removed. `GATEINTO_INSTANCE` is inherited, so
  `gateinto` commands in the terminal talk to the same agent instance.
  Tool-specific settings (`npm_config_https_proxy`, git `http.proxy`,
  `pip.ini`, `.curlrc`) are not touched and may take precedence.
- The parent process's environment is not modified; the block is passed only
  to the new process.

On Windows `Job::spawn` needs an environment, console flags and a current
directory (`Job::spawn_with(executable, args, SpawnOptions {
environment, new_console, current_dir, title })`), passing
`CREATE_UNICODE_ENVIRONMENT` and a block built by a pure, cross-platform
`environment_block`:

- `NAME=value\0` each, terminated by an extra NUL.
- Sorted by name with an ordinal, case-insensitive comparison that folds to
  uppercase (as `CompareStringOrdinal` with `bIgnoreCase` and Rust std's
  Windows `EnvKey` do), not by folding to lowercase: under uppercase folding
  `_` (0x5F) sorts after letters, so `NODE_ENV` comes before `NO_PROXY`.
- Names must be non-empty and contain no NUL and no `=` after the first
  character; values contain no NUL. A leading `=` is allowed: the inherited
  environment contains hidden entries such as `=C:=C:\work` (per-drive current
  directories) and `=ExitCode=...`, which `std::env::vars_os` returns with the
  leading `=`. They are passed through unchanged so the shell keeps its
  per-drive directories in the in-process variant. The agent-hosted variant
  drops every inherited entry whose name starts with `=` (`=<drive>:` per-drive
  directories, `=ExitCode`, `=ExitCodeAscii` and any other): they describe the
  agent's own process state and its shell starts in `%USERPROFILE%`. That cmd
  sets them again when the user changes drives or directories needs
  verification.

On Linux the list is passed to `execve` as is; no sorting or hidden entries.

### Job object and lifetime

- **Job settings.** Same as today for both variants: unnamed,
  non-inheritable handle, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no breakaway
  flags, so breakaway is refused. No CPU, memory or process-count limits.
- **Console, in-process.** No `CREATE_NEW_CONSOLE`: the shell attaches to the
  CLI's console, which is what `Job::spawn` does now. Whether the shell gets
  usable console standard handles while `bInheritHandles` is false needs
  verification, also when Gateinto's own standard handles are redirected.
  When Gateinto is started from mintty (Git Bash's default window) or another
  pipe-based host, it may have no console to share, and the shell would then
  get Windows' default for a console program without one; what happens there
  needs verification, and the command may have to refuse to start, require
  `winpty`, or suggest `--agent`.
- **Console, agent-hosted.** `CREATE_NEW_CONSOLE`; see
  [Agent-hosted variant](#agent-hosted-variant).
- **Console control events, in-process.** Ctrl-C and Ctrl-Break are delivered
  to every process on the console. Tokio's Windows handler reports an event
  as handled only while a receiver for it exists; with none, Windows runs the
  default handler, which calls `ExitProcess`, closing the job and killing the
  shell. `shutdown_signal` (`src/main.rs`) must not be reused: it returns
  after the first event and drops its listeners. Instead the terminal command
  creates `tokio::signal::windows::ctrl_c()` and `ctrl_break()` listeners
  *before* spawning the shell and keeps both alive, draining them in a loop,
  until the shell has exited and the job is torn down. `ctrl_close`,
  `ctrl_logoff` and `ctrl_shutdown` remain shutdown events and end the
  session. The implementation creates all five listeners before it creates
  the job and starts the session, so Ctrl-C and Ctrl-Break are ignored by
  Gateinto from then until the shell has exited and the command exits.
  Gateinto must not call `SetConsoleCtrlHandler(NULL, TRUE)`, whose ignore
  flag the shell would inherit, and must not start the shell with
  `CREATE_NEW_PROCESS_GROUP`, which disables Ctrl-C in the new process.
- **Shell exits.** Gateinto terminates the job, which also ends background
  processes the shell left (build daemons, `start /b` jobs), waits up to 5
  seconds as `Process::kill` does and closes the session. In-process, it
  then exits with the shell's code. This matches browser sessions.
- **Gateinto ends** (console closed, process killed, crash): the job handle
  closes and `KILL_ON_JOB_CLOSE` ends every process in the job; the listener
  closes with the process. For the in-process variant "Gateinto" is the CLI;
  for the agent-hosted variant it is the agent.
- **The agent stops:** ends agent-hosted terminals (see above); no effect on
  in-process ones.
- **Nested sessions.** A terminal session started inside another one creates
  a nested job (Windows 8 and later) and its own session; its variables
  replace the outer ones. An agent-hosted terminal requested from inside a
  terminal is started by the agent, outside the first job. Nothing special is
  planned.

### Routes

The route is resolved like a link's, with the CLI flag or the request's
`route=` in the link's place. The route of a new terminal session is, in this
order:

1. `--route gateway|mixed` or `route=gateway|mixed`, for that session only;
2. otherwise (`saved`, the default) the gateway's saved route
   (`GatewaySection::route()`);
3. otherwise `mixed`.

So `mixed` is the default and `gateway` ("All" in the GUI) is opt-in.

Overriding a saved `gateway` route with `mixed` needs no prompt. A link
cannot produce a `terminal` request or the CLI flag, and any process that can
send the request (any process of the user can reach the agent's pipe or
socket) could just as well run `gateinto session terminal --route mixed`
itself, so a prompt would protect nothing. Whenever the route is `mixed`, the
in-process CLI prints the same direct-connection warning the link approval
shows, on standard error, before starting the shell; the agent returns it as
an answer line, which the CLI prints and the GUI shows as a note. This
differs from `gateinto session browser`, which always uses `gateway`; the
difference is deliberate and documented.

### Plain HTTP (absolute-form requests)

Today a well-formed `HTTP/1.1` request with any method other than `CONNECT`
gets `405` with `Allow: CONNECT`, and a request line with another version
(for example `HTTP/1.0`) gets `400`. With `HTTP_PROXY` set, a tool fetching
an `http://` URL sends an absolute-form request and fails with `405` (or
`400` for `HTTP/1.0`); with it unset, the same request would go directly to
the target, around the gateway.

**Decision for the first version:** set `HTTP_PROXY` anyway and keep these
refusals, so plain HTTP fails closed instead of silently bypassing the
tunnel. A notice on standard error says that `http://` URLs are refused.
Forwarding absolute-form requests (for example by opening a `CONNECT` to
`host:80` and relaying one rewritten request per connection) would add
request parsing, framing and smuggling risks to the proxy core; it is not
planned for the first version.

## Linux

Linux is not in the first version, which is Windows-only. The later Linux
phase starts with a prototype of option (i), verified on real systems, and is
CLI-only, without an agent-hosted variant. The analysis below is kept for
that phase. Today `Job::new` and `os_user::system` return
`Unsupported` there, `browser_job` returns `None`, and browser sessions offer
`session_credentials` only. A terminal session needs a replacement for "this
connection comes from a process in the session's job" that an unprivileged
user can set up. Nothing below has been tried; every point needs
verification.

### Options

**(i) cgroup v2 through a systemd user scope.** The CLI starts the shell in a
transient scope of the user's systemd manager, either with
`systemd-run --user --scope --unit=gateinto-terminal-<id>` or with the D-Bus
call `StartTransientUnit` on `org.freedesktop.systemd1` with the shell's PID
in `PIDs`. With the D-Bus call, the shell is forked, held on a pipe until
the scope's job has finished (the `JobRemoved` signal), and only then allowed
to `exec`, so no grandchild starts outside the scope. The owner check for a
TCP connection then is:

1. find the socket inode of the accepted connection in `/proc/net/tcp` (the
   line whose local and remote addresses are the peer's and the listener's),
   or with `NETLINK_SOCK_DIAG`;
2. read the scope's `cgroup.procs` and look for `socket:[<inode>]` among the
   links in `/proc/<pid>/fd` of only those PIDs (the inverse of a full
   `/proc/*/fd` scan, which costs time proportional to every process's open
   files);
3. accept when one is found, otherwise `403`, as on Windows.

- *Cost:* one `/proc/net/tcp` read (proportional to the number of TCP
  sockets in the network namespace) and one `readlink` per open file of the
  processes in the scope, per connection. Probably acceptable for a terminal;
  needs measurement on a machine with many sockets and a large build in the
  scope.
- *Races:* the client may close its socket or exit before the scan, which
  denies the connection (fails closed). A process that inherited or received
  the socket (`SCM_RIGHTS`) counts as long as one holder is in the scope.
- *PID reuse:* a PID read from `cgroup.procs` may exit and be reused by a
  process outside the scope before its `fd` directory is read. Opening a
  `pidfd` for each PID and checking `/proc/<pid>/cgroup` again after the scan
  closes that window; needs verification.
- *`hidepid`:* `/proc` mounted with `hidepid=1` or `2` hides other users'
  processes only; the user's own processes and `/proc/net/tcp` stay readable.
  Hardened setups that also restrict `/proc/net` need verification.
- *Non-dumpable processes:* reading the links in `/proc/<pid>/fd` needs
  ptrace read access. A process of the same user that is not dumpable (it
  called `prctl(PR_SET_DUMPABLE, 0)`, or changed credentials, as some agents,
  sandboxes and setuid-derived helpers do) refuses it. The check then cannot
  find the socket and denies the connection: it fails closed, but a
  legitimate tool in the scope is denied. Which common tools are affected
  needs verification.
- *Teardown:* stopping the scope (`StopUnit`) kills every process in it.
  Writing `1` to the scope's `cgroup.kill` (Linux 5.14 and later) kills every
  process in the cgroup, including ones forking at that moment, without
  systemd; it is the closest equivalent of terminating a job and is proposed
  for session close and the stale-scope sweep, with `StopUnit` afterwards so
  systemd removes the unit. There is no `KILL_ON_JOB_CLOSE`: if Gateinto is
  killed, the scope keeps running with a dead proxy port. `PR_SET_PDEATHSIG`
  on the shell covers only the shell; Gateinto would also sweep stale
  `gateinto-terminal-*.scope` units at start. Whether a scope can be bound to
  Gateinto's own lifetime needs verification.
- *Requirements:* a running systemd user manager, the unified cgroup v2
  hierarchy and a D-Bus client or `systemd-run`. Missing in many containers,
  WSL without systemd, and distributions without systemd.
- *Escape:* moving a process between cgroups needs write access to
  `cgroup.procs` of the common ancestor of the source and the destination
  cgroup. The subtree under `user@<uid>.service` is delegated to the user;
  `user-<uid>.slice` above it and the login sessions' `session-<n>.scope`
  are owned by root. So:
  - a process in the terminal's scope can move itself to another cgroup
    inside `user@<uid>.service` (unlike a Windows job, which refuses
    breakaway); it then loses gateway access and also escapes teardown;
  - a process already under `user@<uid>.service` (on systemd desktops most
    applications run in `app-*.scope` there) can move itself into the
    terminal's scope, which matches the Windows non-boundary that same-user
    code can join a job;
  - a process in a login session's `session-<n>.scope` (for example an SSH
    login, or a desktop that does not use the user manager for applications)
    cannot move itself into the terminal's scope, because the common
    ancestor is root-owned. Needs verification on common distributions.

**(ii) `SO_PEERCRED`.** Gives the peer's PID, UID and GID, but only on Unix
domain sockets. The local proxy is TCP; most tools cannot use a Unix socket
as an HTTP proxy (curl can only for SOCKS), so this does not apply unless the
listener changes, which would defeat the purpose.

**(iii) UID only.** The owning UID of a TCP socket is in `/proc/net/tcp` and
cheap to read. It accepts every process of the same user, including browsers,
background daemons and other sessions, so it is weaker than the job check
and, against same-user programs that do not target Gateinto, weaker than
`session_credentials`. Not acceptable as the terminal session's only check.

**(iv) Network namespace.** An unprivileged user and network namespace
(`unshare --user --net`) could leave the shell with nothing but a path to the
proxy. It needs unprivileged user namespaces, which some distributions
disable or restrict (sysctls, AppArmor), changes how UIDs and file ownership
appear in the shell, needs a way to bring the proxy into the namespace, and
breaks the `mixed` route's direct connections by design. Too heavy for this
feature.

**(v) Process ancestry.** Walk `PPid` in `/proc/<pid>/status` from the
socket's owner up to the shell. PIDs can be reused during the walk; a double
fork or `setsid` reparents a process to `init` or to the nearest subreaper
and breaks the chain. Making Gateinto a subreaper (`PR_SET_CHILD_SUBREAPER`)
keeps orphans under it, but processes started through `systemd-run`, D-Bus
activation or an already running server are never descendants, and nothing
kills the tree if Gateinto is killed. A cgroup is inherited by every
descendant regardless of reparenting and can only be left by an explicit
write to `cgroup.procs`.

### Recommendation

- A later, CLI-only (in-process) Linux phase using option (i): a systemd user
  scope with the cgroup-based owner check, `LocalAuth::OS_USER` only, and no
  fallback. When the user manager or cgroup v2 is missing, the command fails
  with a message naming the requirement, as `SpawnError::Job` does on
  Windows. Not UID only, not ancestry.
- A prototype first, to measure the check's cost and to verify the
  fork-hold-move-exec sequence, the PID-reuse guard and stale-scope cleanup.
- No agent-hosted variant on Linux. There is no portable way to open a new
  console window: it needs a terminal emulator, and many (GNOME Terminal,
  Konsole, kitty in single-instance mode) are servers that start the shell
  from their own, already running process, outside any scope Gateinto
  creates, and without a reliable way to wait for that shell. The agent
  answers `terminal` requests with "terminal sessions from the agent are not
  supported on this platform", and the GUI is Windows-only today. A
  user-configured emulator command (for example `xterm -e`, which runs the
  shell as its own child) is not part of the Linux phase either.

### Environment on Linux

Names are case-sensitive, so writing both spellings is required, not just
harmless: tools read `https_proxy` or `HTTPS_PROXY` and differ between them
(curl ignores uppercase `HTTP_PROXY`). Two names that differ only in case are
distinct variables, so the Windows duplicate-name risks do not exist there.
Inherited variants are still removed case-insensitively so one rule holds on
every platform; tools ignore mixed-case names anyway. `NO_PROXY` handling is
the same as on Windows.

## Security

- **Every process in the job is trusted.** Anything the user runs in the
  terminal, including package install scripts, build plugins and downloaded
  binaries, can open tunnels through the gateway with the device's client
  certificate, without a credential. This is a wider exposure than a browser
  session, whose processes run web content in a sandbox. Users should open a
  terminal session only for work that needs the gateway.
- **Same non-boundaries as browser sessions.** Code of the same user can join
  the job (duplicate the job handle from Gateinto, or create a process with
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` set to the shell), or inject into a
  process in the job.
- **The `terminal` IPC request.** Any process of the user can connect to the
  agent's pipe or socket, as for `launch`. It can make the agent open a
  terminal window for a known gateway, which is no more than that process
  could do by running `gateinto session terminal` itself. It cannot choose
  the shell, arguments, environment or current directory, cannot add a
  gateway, and is limited by the launch rate limit and
  `max_terminal_sessions`. The resulting window is visible to the user and
  listed in `session list` and the GUI.
- **The shell preference is user-owned.** It comes only from the `--shell`
  flag or the configuration file, never from IPC, links or the GUI.
- **Processes outside the job are not covered.** Services, scheduled tasks,
  COM and WMI-launched processes, programs that hand a request to an
  already-running instance (for example opening a URL in the existing
  browser), daemons started before the session, elevated processes started
  through UAC, and WSL 2 or container workloads run outside the job. If they
  use the port they are denied (`403`, or `408` on an owner lookup
  timeout); if they never see the variables they use their usual network
  path.
- **Loopback only.** The listener is `127.0.0.1:0`, as for every session.
- **Environment contains no secret**, only the port. It is readable by any
  process of the same user, which is acceptable.
- **Port reuse after the session.** When the session ends its port is free.
  A process outside the job that copied the variables could later send
  traffic to whatever binds that port. Processes in the job are terminated,
  so this needs a process that escaped the job.
- **Logging (decided).** The in-process variant logs to the shared console,
  at `warn` and above only, while the shell runs (for example the first
  `os_user` denial); it writes no log file. The agent logs to its logbook as
  for browsers. Neither logs environment values other than the listen
  address.
- **Linux (later phase, not in the first version).** A process in the scope
  can leave it and escape teardown; a killed Gateinto leaves the scope running
  until the sweep. Both are weaker than the Windows job; the prototype must
  measure them and the phase must document them.

Threat-model additions *(to be made with the implementation)*:

| Threat | Mitigation |
| --- | --- |
| A program of the same user outside the terminal's job uses its port. | Owner check with `IsProcessInJob`; denied with `403` and close, or `408` on an owner lookup timeout; no `session_credentials` to fall back to or steal. |
| Code run inside the terminal (a malicious dependency) reaches gateway-protected hosts. | None; every process in the job is trusted. Residual risk, documented. |
| A web page starts a terminal or a command through a link. | No link field selects a terminal, shell or command; unknown fields are refused; the link handler never builds a `terminal` request. |
| A local process asks the agent for a terminal with its own command. | The `terminal` request has no shell, command, argument or environment field; the shell comes from the user's configuration file. |
| A local process floods the user with terminal windows. | Shared launch rate limit and `max_terminal_sessions`. |
| A local proxy credential leaks through the environment or logs. | Terminal sessions have no credential; proxy URLs carry none. |
| Plain-HTTP traffic bypasses the gateway. | `HTTP_PROXY` points to the session, which refuses absolute-form `HTTP/1.1` requests with `405` and other versions with `400`. |
| Background processes outlive the session with a stale proxy port. | Shell exit, session close, `gateinto stop`, and the end of the CLI or agent terminate the job. |

## Compatibility

Nothing here has been verified. "Expected" means the tool is documented or
widely known to read proxy environment variables; each row still needs a
manual check.

| Category | Expected behaviour | Status |
| --- | --- | --- |
| `curl.exe` (Windows built-in), Git for Windows over HTTPS | Uses `https_proxy`/`HTTPS_PROXY` | Expected, needs verification |
| Git Bash / MSYS2 programs | Read lowercase names from the imported environment | Needs verification |
| Python (`pip`, `requests`, `urllib`) | Uses proxy variables | Expected, needs verification |
| Go programs | `ProxyFromEnvironment`; never proxies `localhost` | Expected, needs verification |
| .NET (PowerShell 7 `Invoke-WebRequest`, `dotnet`, Git Credential Manager) | `HttpClient.DefaultProxy` reads the variables before system settings | Expected, needs verification |
| .NET Framework programs that start processes (Windows PowerShell 5.1 `Start-Process`, MSBuild) | May fail on names that differ only in case | Needs verification |
| cmd `set HTTPS_PROXY=` | May clear only one spelling | Needs verification |
| Rust (`cargo`, `reqwest`-based tools) | Use proxy variables | Expected, needs verification |
| `npm` | Reads `HTTPS_PROXY`; `npm_config_*` and `.npmrc` take precedence | Expected, needs verification |
| Node.js `fetch`/`https` in user code | Ignores the variables unless opted in | Not covered by default |
| Java | Ignores the variables (uses system properties) | Not covered |
| Windows PowerShell 5.1, `winget`, BITS, Windows Update, browsers started from the shell | Use WinINet/WinHTTP or system settings | Not covered |
| `ssh`, `git` over SSH, raw TCP tools | No HTTP proxy | Not covered |
| `http://` URLs in any tool | `405` from the session (`400` for `HTTP/1.0`) | Fails closed by design |
| WSL, Docker, elevated (`runas`) children | Outside the job | Not covered; denied (`403`, or `408` on lookup timeout) if they use the port |
| Agent-hosted window in conhost | New console window, closes with the job | Expected, needs verification |
| Agent-hosted window with Windows Terminal as default terminal (Windows 11) | Opens as a Windows Terminal tab or window; closing behaviour on job kill unknown | Needs verification |
| Configuration file with `[terminal]` read by an older Gateinto | Refused (unknown section) | Expected, by `deny_unknown_fields` |
| Older agent receiving `terminal` | `invalid request`; CLI and GUI ask for an agent restart | Expected, needs verification |
| Linux (later phase, not in the first version): systemd user scope, cgroup v2 | Owner check by cgroup | Needs a prototype |
| Linux without a systemd user manager (containers, some WSL setups), later phase | Command refuses to start | Expected by design |

## Test plan

TDD order: each item starts as a failing test.

**Unit tests (all platforms, `cargo test`):**

- `terminal_environment`: sets each proxy name in both spellings, once each,
  to the listen URL and the loopback `NO_PROXY`; removes case variants of
  inherited names; reports replaced names without values; keeps unrelated
  variables, including `GATEINTO_INSTANCE`; formats the address from
  `local_addr()`.
- `environment_block`: separators and final double NUL; ordinal uppercase
  case-insensitive sorting, including `NODE_ENV` before `NO_PROXY`; hidden
  entries with a leading `=` (`=C:=C:\work`, `=ExitCode=00000000`) passed
  through unchanged; refusal of empty names, NUL, and `=` after the first
  character of a name.
- Agent-hosted environment: every inherited entry with a leading `=`
  (`=C:=C:\work`, `=D:=D:\`, `=ExitCode=00000000`, `=ExitCodeAscii=`) is
  dropped, while the in-process environment keeps them.
- Terminal local auth is exactly `LocalAuth::OS_USER`; a missing job is an
  error, never a fallback to `session_credentials`.
- Route resolution: flag or `route=`, then saved route, then `mixed`;
  `--route` accepts only `saved`, `gateway`, `mixed`; mixed produces the
  warning.
- Shell selection: `--shell` over `[terminal] shell` over the platform
  default; `args` used only with `shell`; on Windows `%ComSpec%`; the Linux
  default (`$SHELL`, then `pw_shell`, then `/bin/sh`, with injected lookups)
  is tested with the Linux phase.
  `[terminal]` with an unknown key is refused.
- `[terminal] shell` resolution: a bare `pwsh.exe` is searched on `PATH`
  with `PATHEXT` and is not joined with the configuration file's directory;
  `tools\sh.exe` is resolved against the configuration file's directory, not
  the current directory; a drive-relative `C:tools\sh.exe` and a
  root-relative `\tools\sh.exe` are refused; an absolute path is kept; a
  missing file is an error. `[browser] executable` keeps its current join.
- CLI parsing of `session terminal` with `--shell` and arguments after `--`;
  shell resolution searches `PATH` with `PATHEXT` for bare names but not the
  current directory, and resolves a relative path with a separator (for
  example `.\tools\sh.exe`) against the current directory; a drive-relative
  `C:tools\sh.exe` and a root-relative `\tools\sh.exe` are refused.
  `--agent` refuses `--shell`, `ARGS`, `--config` and upstream options, and
  requires `--gateway`.
- IPC: `terminal <gateway> route=<saved|gateway|mixed>` round-trips for every
  route; missing `route=`, an unknown route, an extra word (`shell=...`,
  `command=...`, `args=...`, `env=...`), a second space, an invalid gateway
  name and keys in another order are refused; a line of `MAX_REQUEST_BYTES`
  is still refused cleanly.
- Exit code: a shell code above 255 (for example `0xC000013A`) is passed
  through unchanged.
- On non-Windows the in-process command fails with an unsupported error
  before binding (`cfg(not(windows))` test).
- Console events: Ctrl-C and Ctrl-Break do not end the in-process session;
  close, logoff and shutdown do (mapping tested as a pure function). The
  Ctrl-C and Ctrl-Break listeners exist before the shell is spawned and stay
  alive until teardown (tested through the terminal's event loop with fake
  event sources): a second and a third Ctrl-C do not end the session either.
- Links: `kind`, `shell`, `command` and `args` fields are refused; no
  `LaunchRequest` converts into `Request::Terminal`.
- `SessionKind::Terminal` and `SessionInfo::shell` round-trip; an older
  client reads `unknown` and ignores `shell`; `session_table` shows a terminal
  row.
- `Denial::NotInJob` text no longer mentions a browser.

**Agent tests (all platforms, fake `Launcher` as in the existing
`JobFailsOnce` test in `src/agent.rs`).** They run everywhere because the
platform check goes through the `Launcher::terminals()` seam, not
`cfg!`; the fake answers `true` unless a test says otherwise:

- a launcher answering `false` makes the agent answer the unsupported error
  after the rate limit and before any gateway lookup (the fake `Profiles`
  records no call);
- `System::terminals()` is `cfg!(windows)` (one assertion per platform);
- a `terminal` request starts a session of kind `terminal` with
  `LocalAuth::OS_USER` and the job, and the launcher sees the resolved shell,
  `new_console`, `%USERPROFILE%` and the environment;
- a job that cannot be created, or `SpawnError::Job`, closes the session,
  answers an error and leaves no session, with no retry;
- the launch rate limit is shared with `launch`, and `max_terminal_sessions`
  is counted separately from `max_browser_sessions`;
- `list` shows the terminal with its shell name; `credentials <id>` answers
  that it has none;
- `close <id>` kills the fake process and closes the session; a fake shell
  exit closes it too; `stop` closes terminals and browsers;
- an unknown gateway is refused without a confirmation token, and so is a
  linked gateway that is not in the configuration file.

**GUI tests (`gui`, existing patterns):**

- the "Open terminal" action is offered only with `AgentState::Running`,
  never with `Stopped` or `Unreachable`, like
  `only_a_running_agent_can_start_a_browser`;
- `Command::Terminal` maps to `terminal <gateway> route=saved` and never to
  `Command::Start`; a failure becomes a note;
- demo mode answers it without changes and the sample sessions include a
  terminal row;
- the sessions page shows a terminal row with the shell name and no
  credentials button;
- closing a terminal row opens the confirmation and sends `Command::Close`
  only after it is confirmed; cancelling sends nothing; closing a browser
  row sends `Command::Close` without asking;
- Stop with a terminal in the last session list opens the confirmation and
  sends `Command::Stop` only after it is confirmed; Stop without terminals
  sends it at once;
- both confirmations exist in English and Chinese.

**Windows CI integration (`windows-latest`, proposed
`tests/terminal_windows.rs`)** against the existing upstream fixture, with a
probe binary like `tests/fake_browser.rs` run as `--shell` or as
`[terminal] shell`:

- the probe reads `HTTPS_PROXY`, sends `CONNECT` and gets `200` through the
  fixture;
- a grandchild started by the probe is accepted;
- a process outside the job gets `403` and close, and the fixture sees no
  connection;
- the probe sees exactly the expected variables, inherited proxy variables
  replaced, and no `@` in any proxy URL;
- `CREATE_BREAKAWAY_FROM_JOB` from the probe fails;
- an absolute-form `HTTP/1.1` `GET` gets `405` with `Allow: CONNECT`, and an
  `HTTP/1.0` one gets `400`;
- Ctrl-C does not end the in-process session (needs verification that this
  setup works on `windows-latest`): `GenerateConsoleCtrlEvent(CTRL_C_EVENT,
  0)` can only target process group 0, every process on the caller's
  console, so a test helper starts `gateinto session terminal` with
  `CREATE_NEW_CONSOLE`, attaches to that console with `AttachConsole`,
  ignores Ctrl-C itself, sends the event three times, and then checks that
  Gateinto, the shell and the session's listener are still alive and that the
  probe saw each event;
- shell exit with a lingering grandchild: job empty within 5 seconds, port
  closed, exit code propagated;
- killing `gateinto.exe` ends the shell and its children;
- a forced job failure (test hook) starts nothing;
- agent-hosted: a test agent started with `GATEINTO_INSTANCE` receives
  `terminal`, the probe runs in its own console (`GetConsoleWindow` differs
  from the test's), `session list` shows it, `session close` ends the probe
  and its grandchild, `stop` does the same, and killing the agent ends them;
- agent-hosted Ctrl-C (needs verification that this setup works on
  `windows-latest`): the test starts the agent through `spawn_agent`
  (`--detach`, so with `CREATE_NEW_PROCESS_GROUP`), requests a terminal whose
  shell is the probe, attaches to the probe's console with `AttachConsole`,
  ignores Ctrl-C itself, sends `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`,
  and checks that the probe's handler saw the event; the same test without
  the agent's `SetConsoleCtrlHandler(NULL, FALSE)` call (test hook) shows
  whether the inherited attribute exists at all;
- `trace` logs contain no environment value other than the listen address.

**Manual checklist (Windows 10 and 11, results go to
`docs/verification.md`):**

- [ ] cmd, PowerShell 7, Windows PowerShell 5.1 and Git Bash as the shell, in
      conhost and in Windows Terminal, for both variants.
- [ ] Ctrl-C, pressed several times, stops a running `ping -t` but not the
      session; closing the window ends the shell, its children and the
      listener.
- [ ] In an agent-hosted window, Ctrl-C stops `ping -t`, both with an agent
      started by `gateinto agent --detach` (or the GUI or autostart) and with
      a foreground `gateinto agent`; Ctrl-C in the foreground agent's console
      stops the agent and closes its terminal windows.
- [ ] `curl.exe https://...`, `git clone https://...`, `pip install`,
      `npm install`, `dotnet restore`, `cargo fetch`, PowerShell 7
      `Invoke-WebRequest` go through the gateway (visible in tunnel logs).
- [ ] Windows PowerShell 5.1 `Invoke-WebRequest` and `winget` do not.
- [ ] Windows PowerShell 5.1 `Start-Process`, MSBuild and cmd
      `set HTTPS_PROXY=` with both spellings present.
- [ ] Inherited proxy variables are replaced and the parent shell is unchanged
      after exit.
- [ ] An elevated child (`runas`) and a WSL process are denied if they use the
      port.
- [ ] `mixed` and `gateway` routes, and the mixed warning in the CLI and GUI.
- [ ] Nested terminal session.
- [ ] GUI: the button is absent while the agent is stopped and present once it
      runs; the window title; close from the GUI and from
      `gateinto session close`; `gateinto stop`; Windows 11 with Windows
      Terminal as the default terminal application.
- [ ] GUI: closing a terminal row and pressing Stop with a terminal open both
      ask first, and cancelling leaves the terminal running;
      `gateinto stop` and `gateinto session close` close it without asking.

## Decisions

Numbered in the order the questions were raised during design. Where the
earlier proposal was not explicit, the conservative option is chosen and
marked as such.

1. **Leftovers are terminated.** On shell exit the job is terminated, ending
   background processes the shell left, then Gateinto waits up to 5 seconds;
   it does not wait for the job to empty on its own.
2. **`NO_PROXY` is replaced.** Its final value is
   `localhost,127.0.0.1,::1`, written as both `NO_PROXY` and `no_proxy`.
   Inherited entries are dropped, not merged; no CIDR form such as
   `127.0.0.0/8` and no bracketed `[::1]` is added.
3. **Plain HTTP fails closed.** The `405` (other methods over `HTTP/1.1`)
   and `400` (other versions) refusals stay; absolute-form forwarding is not
   planned for the first version.
4. **Configuration-file gateways only**, in both variants. A gateway
   approved from a link is refused, even by the agent that knows it; the
   agent test for that refusal stays.
5. **In-process logging** goes to the shared console at `warn` and above
   while the shell runs, with no log file; the agent logs to its logbook.
   Neither logs environment values other than the listen address
   (conservative: the proposal did not name a level filter or rule out a
   file).
6. **No `GATEINTO_SESSION` marker.** No variable other than the proxy names
   is set (conservative: the proposal only asked the question). Nested
   sessions need no detection, and a prompt can test `HTTPS_PROXY`.
7. **`--agent`** is the flag that selects the agent-hosted variant of
   `gateinto session terminal`.
8. **Confirmation in the GUI only.** The GUI asks before closing a terminal
   session and before Stop while terminal sessions are open. `gateinto stop`
   and `gateinto session close` do not ask.
9. **Agent-hosted environment** is the agent's start-time environment;
   `CreateEnvironmentBlock` is not used.
10. **Agent-hosted current directory** is `%USERPROFILE%`; there is no
    `[terminal] directory` key.
11. **Limits:** `max_terminal_sessions` = 4, counted separately from
    browsers, and the launch rate limit is shared by `launch` and
    `terminal`.
12. **Windows Terminal as default terminal** needs verification (below).
    Proposed fallback: the agent forces conhost for terminal windows.
13. **`[terminal] args` is kept** next to `shell` and is used only together
    with `shell`.
14. **Linux is not in the first version**, which is Windows-only. The later
    phase starts with a prototype of option (i), a systemd user scope with
    the cgroup-based owner check, verified on real systems; whether its
    escape and stale-scope weaknesses and its per-connection cost are
    acceptable is decided from that prototype.
15. **No agent-hosted variant on Linux.** The Linux phase is CLI-only
    (in-process); no terminal emulator is launched by the agent.
16. **Ctrl-C in agent-hosted windows:** the agent calls
    `SetConsoleCtrlHandler(NULL, FALSE)` at start. If verification shows the
    reset does not restore Ctrl-C for its children, `CREATE_NEW_PROCESS_GROUP`
    is dropped from `spawn_agent` (needs verification too).

### Needs verification

These are not open design questions; each has a decided answer or fallback
above and must be checked on real systems before it ships. Results go to
`docs/verification.md`.

- With Windows Terminal as the default terminal application (Windows 11):
  whether a job kill closes the tab or window, whether the console host runs
  in the job, and, if the conhost fallback is needed, how to force conhost
  for one process.
- `SetConsoleCtrlHandler(NULL, FALSE)` in a process without a console:
  whether it succeeds and clears the inherited "ignore Ctrl-C" attribute for
  children; if not, whether dropping `CREATE_NEW_PROCESS_GROUP` from
  `spawn_agent` restores Ctrl-C.
- Both spellings on Windows: .NET Framework programs that start processes
  (Windows PowerShell 5.1 `Start-Process`, MSBuild), cmd `set HTTPS_PROXY=`,
  and which entry Windows APIs return for a duplicated name.
- Whether cmd sets the hidden `=<drive>:` entries again in an agent-hosted
  window.
- In-process, on `CTRL_CLOSE_EVENT` (and logoff or shutdown) Windows may end
  the process before the job is terminated and the session closed; the job
  handle then closes with the process and `KILL_ON_JOB_CLOSE` still ends the
  shell.
- In-process console handles while `bInheritHandles` is false, also with
  redirected standard handles; behaviour when started from mintty or another
  pipe-based host.
- The Windows CI setups for Ctrl-C (in-process and agent-hosted) on
  `windows-latest`.
- Every row of the [compatibility table](#compatibility).
- For the Linux phase, in the prototype: the fork-hold-move-exec sequence,
  the PID-reuse guard, the owner check's per-connection cost, stale-scope
  cleanup, and escape from the scope.
