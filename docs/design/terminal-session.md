# Design: terminal sessions

Status: proposal. Nothing in this document is implemented, and none of the
behaviour it expects from shells or tools has been tried on a real Windows
terminal. Names marked *(proposed)* do not exist in the code yet; every other
name refers to code on `master` at the time of writing.

## Summary

`gateinto session terminal` starts a shell inside a new Windows job object and
binds it to a new session that accepts only `os_user` local authentication,
restricted to that job. The shell gets `HTTPS_PROXY`, `HTTP_PROXY`,
`ALL_PROXY` (and lowercase variants) set to `http://127.0.0.1:<port>` and a
`NO_PROXY` for loopback. Processes the shell starts inherit both the job and
the variables, so tools that read proxy variables tunnel through the gateway
without any credential.

## Goals

- Let command-line tools that honour proxy environment variables (curl, git,
  pip, cargo, Go and .NET programs, ...) use a gateway without the user typing
  or storing a proxy credential.
- Reuse the existing pieces: `crate::job::Job` (`src/job.rs`), the `os_user`
  owner check with `IsProcessInJob` (`src/proxy/os_user.rs`,
  `src/proxy/os_user/windows.rs`), `LocalAuth::OS_USER`
  (`src/proxy/local_auth.rs`) and `SessionManager` (`src/sessions.rs`).
- Keep every existing rule: loopback-only listener, routes as in
  [session routing](../protocol/launch-uri.md#session-routing), credentials
  never written to disk or logged, links never carry commands, the GUI never
  starts the agent on its own and never writes TOML.

## Non-goals

- Platforms other than Windows. Elsewhere the command fails before binding a
  port: `os_user::system` and `Job::new` already return `Unsupported` there.
- Changing system proxy settings (WinINet, WinHTTP, PAC, registry). Programs
  that use WinINet or WinHTTP proxy settings instead of environment variables
  are not covered.
- Covering processes outside the job: services, scheduled tasks, COM servers,
  daemons that were already running, elevated processes started through UAC.
- Plain-HTTP (absolute-form) proxying in the first version; see
  [Plain HTTP](#plain-http-absolute-form-requests).
- Isolation from malicious code of the same user (unchanged non-guarantee of
  `os_user`).

## What exists today

- `gateinto session browser` (`browser_session` in `src/main.rs`) runs a
  session in the CLI process itself, with `LocalAuth::SESSION_CREDENTIALS`,
  the `gateway` route and no job. It starts no browser.
- Agent launches (`Agent::start` in `src/agent.rs`) create a job
  (`browser_job`), start the browser in it with `Job::spawn`, and bind a
  session with `browser_local_auth(true)`, i.e. `os_user` plus
  `session_credentials`. If the job cannot be created or used, the browser
  starts without one and the session falls back to `session_credentials`
  only.
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
  `403 Forbidden` with `Connection: close` (`Authenticator::check`).
- Non-`CONNECT` requests: `parse_connect_request` (`src/http.rs`) returns
  `ParseError::MethodNotAllowed` for any other method, and the session answers
  `405 Method Not Allowed` with `Allow: CONNECT`. Absolute-form requests such
  as `GET http://example.com/ HTTP/1.1` are therefore refused locally and
  never reach DNS, routing or the gateway.
- Link and IPC launch auth is `LaunchAuth::SessionCredentials` only
  (`src/uri.rs`); the URI parser refuses unknown fields.
- `SessionKind` (`ipc-types/src/lib.rs`) has only `Browser`; unknown values
  deserialize as `Unknown`.

## Design decisions

### Where the session runs

**Decision: in the CLI process, like `gateinto session browser`.**
`gateinto session terminal` binds the session, creates the job and starts the
shell in the console it was run from; the shell replaces the interactive
prompt until it exits. No agent is needed and no IPC request is added.

Reasons: the shell needs a console, and the CLI already has the user's
console; the agent is detached and has none. The lifetime is obvious (the
shell's), and teardown is guaranteed by `KILL_ON_JOB_CLOSE` even if
`gateinto.exe` is killed, because the job handle lives only in that process.

Consequences: the session is not shown by `gateinto session list`, cannot be
closed by `gateinto session close` and is not stopped by `gateinto stop`,
exactly like `session browser` today. An agent-hosted variant is an
[open question](#open-questions).

### CLI shape

```text
gateinto session terminal [--config PATH] [--gateway NAME] [upstream options]
                          [--route saved|gateway|mixed] [--shell PATH] [-- ARGS...]
```

- Gateway selection and upstream options: the same `UpstreamArgs` and
  `--gateway` as `BrowserSessionArgs` (config-file gateways only).
- `--route`: `saved` (default), `gateway` or `mixed`; see
  [Routes](#routes).
- `--shell`: executable to start, default `%ComSpec%`. A bare name is
  searched in `PATH` only, never in the current directory; the result must be
  an existing file. `ARGS` after `--` are passed to it, quoted by the existing
  `command_line` (`src/job.rs`), which already refuses quotes in the executable
  path and NUL characters.
- Before starting the shell it prints, on standard output: `session`, `kind:
  terminal`, `gateway`, `listen`, `route`, `auth: os_user`, and the names (not
  values) of proxy variables it replaced. It prints no credential because there
  is none.
- Exit code: the shell's exit code; Gateinto's own errors use its usual exit
  codes.

New code *(proposed)*: `SessionCommand::Terminal(TerminalSessionArgs)` in
`src/main.rs`, a `terminal` module with pure helpers
(`terminal_environment`, `resolve_shell`, `terminal_route`), and
`SessionKind::Terminal => "terminal"` in `ipc-types` for log spans and a
future agent-hosted variant (older clients already map it to `Unknown`).

### IPC

No change in the first version. If an agent-hosted variant is chosen later,
its request must carry no executable, argument or environment: only gateway
and route, like `launch`. The agent would use `%ComSpec%` or a shell set by
the user in the configuration file.

### GUI

No entry point in the first version: the GUI only talks to the agent over IPC,
and the in-process session has no IPC. With an agent-hosted variant the GUI
could offer "Open terminal" on a gateway only while its last poll found an
agent; it would never start the agent for it (the explicit Start agent button
stays the only way), and would never write the configuration file.

### Links

**`gateinto://` links never start terminal sessions.** No field selects a
session kind, shell, command, argument or environment variable, and none will
be added.

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
  created or the shell cannot be put in it (`SpawnError::Job`), the command
  fails and starts nothing. There is no fallback, unlike browser launches,
  because the fallback would be `session_credentials`.
- **No `session_credentials`.** The session offers none, so there is nothing to
  show, store or leak, and a process outside the job gets `403` and close
  instead of a `Basic` challenge.
- **Never in environment variables.** Credentials must not be put into proxy
  URLs (`http://user:pass@127.0.0.1:<port>`): every child inherits the
  environment, any process of the same user can read it, crash dumps and
  diagnostics capture it, and many tools print the proxy URL in verbose
  output, error messages or logs.
- **Documentation change required.** The [security
  model](../security-model.md#local-proxy-authentication-session_credentials)
  says that every session accepts `session_credentials` and that no setting
  removes them. Terminal sessions are the exception; that text, the threat
  model's trust boundary and `docs/verification.md` must be updated with the
  implementation.
- Small wording changes: `Denial::NotInJob` says "outside the session's
  browser" and `Drop for Process` says "the browser's job"; both become
  neutral ("the session's job").

### Environment

The shell's environment is Gateinto's environment with these changes
*(proposed `terminal_environment(inherited, listen) -> (vars, replaced)`)*:

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
  `Https_Proxy`) is removed first. Keeping a user's proxy would send traffic
  around the tunnel. The replaced names are printed; their values are not,
  because proxy URLs often contain credentials.
- **Both spellings.** Windows treats environment names case-insensitively, but
  MSYS2 and Cygwin programs (Git Bash) import the block case-sensitively and
  some only read the lowercase names. The block therefore contains both
  spellings with identical values. Whether Windows APIs and each runtime handle
  the duplicate names as expected needs verification.
- **`NO_PROXY`.** Loopback only, so tools reaching local development servers
  do not tunnel them; under the `gateway` route such a request would otherwise
  reach the gateway's own loopback. Inherited `NO_PROXY` entries are dropped,
  since they would let named hosts bypass the tunnel. CIDR forms such as
  `127.0.0.0/8` are not understood by every tool and are left out.
- No other variable is set or removed. Tool-specific settings
  (`npm_config_https_proxy`, git `http.proxy`, `pip.ini`, `.curlrc`) are not
  touched and may take precedence.
- The parent process's environment is not modified; the block is passed only
  to `CreateProcessW`.

`Job::spawn` needs an environment parameter *(proposed `Job::spawn_with`
taking an environment, or an options struct)*, passing
`CREATE_UNICODE_ENVIRONMENT` and a block built by a pure, cross-platform
`environment_block` *(proposed)*: entries sorted case-insensitively,
`NAME=value\0` each, terminated by an extra NUL, refusing names that are empty
or contain `=` or NUL and values that contain NUL.

### Job object and lifetime

- **Job settings.** Same as today: unnamed, non-inheritable handle,
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no breakaway flags, so breakaway is
  refused. No CPU, memory or process-count limits.
- **Console.** No `CREATE_NEW_CONSOLE`: the shell attaches to the CLI's
  console, which is what `Job::spawn` does now. Whether the shell gets usable
  console standard handles while `bInheritHandles` is false needs
  verification, also when Gateinto's own standard handles are redirected.
- **Console control events.** Ctrl-C and Ctrl-Break are delivered to every
  process on the console. While the shell runs, Gateinto must handle them
  without ending the session (the tokio listeners already used by
  `shutdown_signal` mark them handled; the terminal command simply does not
  treat them as shutdown). It must not call `SetConsoleCtrlHandler(NULL,
  TRUE)`, whose ignore flag the shell would inherit. Close, logoff and
  shutdown events end the session.
- **Shell exits.** Gateinto terminates the job, which also ends background
  processes the shell left (build daemons, `start /b` jobs), waits up to 5
  seconds as `Process::kill` does, closes the session and exits with the
  shell's code. This matches browser sessions.
- **Gateinto ends** (console closed, process killed, crash): the job handle
  closes and `KILL_ON_JOB_CLOSE` ends every process in the job; the listener
  closes with the process.
- **The agent stops:** no effect; the session does not belong to the agent.
- **Nested sessions.** A `gateinto session terminal` run inside another one
  creates a nested job (Windows 8 and later) and its own session; its variables
  replace the outer ones. Nothing special is planned.

### Routes

The route is resolved like a link's, with the CLI flag in the link's place:

1. `--route gateway` or `--route mixed`, for this session only;
2. otherwise the gateway's saved route (`GatewaySection::route()`, `mixed`
   when unset);
3. so `mixed` is the default and `gateway` ("All" in the GUI) is opt-in.

`--route mixed` for a gateway saved as `gateway` needs no prompt: the flag is
typed by the user, not supplied by a link. Whenever the route is `mixed`, the
CLI prints the same direct-connection warning the link approval shows. This
differs from `gateinto session browser`, which always uses `gateway`; the
difference is deliberate and documented.

### Plain HTTP (absolute-form requests)

Today any non-`CONNECT` request gets `405` with `Allow: CONNECT`. With
`HTTP_PROXY` set, a tool fetching an `http://` URL sends an absolute-form
request and fails with `405`; with it unset, the same request would go
directly to the target, around the gateway.

**Decision for the first version:** set `HTTP_PROXY` anyway and keep the
`405`, so plain HTTP fails closed instead of silently bypassing the tunnel.
The startup output says that `http://` URLs are refused. Forwarding
absolute-form requests (for example by opening a `CONNECT` to `host:80` and
relaying one rewritten request per connection) would add request parsing,
framing and smuggling risks to the proxy core; it is an open question.

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
- **Processes outside the job are not covered.** Services, scheduled tasks,
  COM and WMI-launched processes, programs that hand a request to an
  already-running instance (for example opening a URL in the existing
  browser), daemons started before the session, elevated processes started
  through UAC, and WSL 2 or container workloads run outside the job. If they
  use the port they get `403`; if they never see the variables they use their
  usual network path.
- **Loopback only.** The listener is `127.0.0.1:0`, as for every session.
- **Environment contains no secret**, only the port. It is readable by any
  process of the same user, which is acceptable.
- **Port reuse after the session.** When the session ends its port is free.
  A process outside the job that copied the variables could later send
  traffic to whatever binds that port. Processes in the job are terminated,
  so this needs a process that escaped the job.
- **Logging.** Gateinto logs to the shared console at `warn` while the shell
  runs (for example the first `os_user` denial). It never logs environment
  values other than the listen address.

Threat-model additions *(to be made with the implementation)*:

| Threat | Mitigation |
| --- | --- |
| A program of the same user outside the terminal's job uses its port. | Owner check with `IsProcessInJob`; `403` and close; no `session_credentials` to fall back to or steal. |
| Code run inside the terminal (a malicious dependency) reaches gateway-protected hosts. | None; every process in the job is trusted. Residual risk, documented. |
| A web page starts a terminal or a command through a link. | No link field selects a terminal, shell or command; unknown fields are refused. |
| A local proxy credential leaks through the environment or logs. | Terminal sessions have no credential; proxy URLs carry none. |
| Plain-HTTP traffic bypasses the gateway. | `HTTP_PROXY` points to the session, which refuses absolute-form requests with `405`. |
| Background processes outlive the session with a stale proxy port. | Shell exit, session end or Gateinto exit terminate the job. |

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
| Rust (`cargo`, `reqwest`-based tools) | Use proxy variables | Expected, needs verification |
| `npm` | Reads `HTTPS_PROXY`; `npm_config_*` and `.npmrc` take precedence | Expected, needs verification |
| Node.js `fetch`/`https` in user code | Ignores the variables unless opted in | Not covered by default |
| Java | Ignores the variables (uses system properties) | Not covered |
| Windows PowerShell 5.1, `winget`, BITS, Windows Update, browsers started from the shell | Use WinINet/WinHTTP or system settings | Not covered |
| `ssh`, `git` over SSH, raw TCP tools | No HTTP proxy | Not covered |
| `http://` URLs in any tool | `405` from the session | Fails closed by design |
| WSL, Docker, elevated (`runas`) children | Outside the job | Not covered; `403` if they use the port |

## Test plan

TDD order: each item starts as a failing test.

**Unit tests (all platforms, `cargo test`):**

- `terminal_environment`: sets the eight names to the listen URL and the
  loopback `NO_PROXY`; removes case variants of inherited names; reports
  replaced names without values; keeps unrelated variables; formats the
  address from `local_addr()`.
- `environment_block`: sorting, separators, final double NUL, refusal of `=`,
  NUL and empty names.
- Terminal local auth is exactly `LocalAuth::OS_USER`; a missing job is an
  error, never a fallback to `session_credentials`.
- Route resolution: flag, then saved route, then `mixed`; `--route` accepts
  only `saved`, `gateway`, `mixed`; mixed prints the warning.
- CLI parsing of `session terminal` with `--shell` and arguments after `--`;
  shell resolution searches `PATH` but not the current directory.
- On non-Windows the command fails with an unsupported error before binding.
- Console events: Ctrl-C and Ctrl-Break do not end the session; close, logoff
  and shutdown do (mapping tested as a pure function).
- Links: `kind`, `shell`, `command` and `args` fields are refused.
- `SessionKind::Terminal` round-trips; an older client reads `unknown`.
- `Denial::NotInJob` text no longer mentions a browser.

**Windows CI integration (`windows-latest`, proposed
`tests/terminal_windows.rs`)** against the existing upstream fixture, with a
probe binary like `tests/fake_browser.rs` run as `--shell`:

- the probe reads `HTTPS_PROXY`, sends `CONNECT` and gets `200` through the
  fixture;
- a grandchild started by the probe is accepted;
- a process outside the job gets `403` and close, and the fixture sees no
  connection;
- the probe sees exactly the expected variables, inherited proxy variables
  replaced, and no `@` in any proxy URL;
- `CREATE_BREAKAWAY_FROM_JOB` from the probe fails;
- an absolute-form `GET` gets `405` with `Allow: CONNECT`;
- shell exit with a lingering grandchild: job empty within 5 seconds, port
  closed, exit code propagated;
- killing `gateinto.exe` ends the shell and its children;
- a forced job failure (test hook) starts nothing;
- `trace` logs contain no environment value other than the listen address.

**Manual checklist (Windows 10 and 11, results go to
`docs/verification.md`):**

- [ ] cmd, PowerShell 7, Windows PowerShell 5.1 and Git Bash as `--shell`, in
      conhost and in Windows Terminal.
- [ ] Ctrl-C stops a running `ping -t` but not the session; closing the
      window ends the shell, its children and the listener.
- [ ] `curl.exe https://...`, `git clone https://...`, `pip install`,
      `npm install`, `dotnet restore`, `cargo fetch`, PowerShell 7
      `Invoke-WebRequest` go through the gateway (visible in tunnel logs).
- [ ] Windows PowerShell 5.1 `Invoke-WebRequest` and `winget` do not.
- [ ] Inherited proxy variables are replaced and the parent shell is unchanged
      after exit.
- [ ] An elevated child (`runas`) and a WSL process are denied if they use the
      port.
- [ ] `mixed` and `gateway` routes, and the mixed warning.
- [ ] Nested terminal session.

## Open questions

1. In-process only, or also an agent-hosted variant (new console window,
   listed by `session list`, closable, GUI button, IPC request without any
   command field)?
2. On shell exit, terminate leftover background processes (proposed) or wait
   until the job is empty?
3. `NO_PROXY`: replace (proposed) or merge with the user's value; add
   `127.0.0.0/8` or `[::1]`?
4. Write both spellings of each variable (proposed), or only one?
5. Keep `405` for plain HTTP (proposed), or implement absolute-form
   forwarding later?
6. Config-file gateways only (as `session browser`), or also gateways approved
   from links?
7. Log to the shared console while the shell runs, or only to a file or the
   agent's logbook?
8. Default shell: `%ComSpec%` (proposed) or PowerShell 7 when installed?
9. Set a non-secret `GATEINTO_SESSION=<id>` marker so prompts and nested
   sessions can detect the session?
10. Is dropping `session_credentials` for this kind acceptable as an exception
    to the "every session accepts `session_credentials`" rule?
