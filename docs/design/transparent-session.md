# Design: transparent sessions on Windows

Status: design decided; steps 1 and 2 of the [Implementation
plan](#implementation-plan) are implemented (`Job::set_dscp_tag` in
`src/job.rs`, the packet core in `src/divert.rs` and `src/divert/`), and so is
step 3, the `divert` helper: its platform-independent part (the pipe
protocol, the engine loop, the helper sequence and the firewall command
lines) and its Windows bindings (`src/divert/windows.rs`, the hidden
`gateinto divert` subcommand). Step 4 is implemented as parts of their own:
adoption into a session's proxy (`Proxy::adopter`), the attribution
(`os_user::original`, `Attribution`), the listener socket
(`transparent::listener`), the engine state with the registry and the
session marks (`transparent::state`) and the listener's dispatch loop
(`transparent::serve`). Step 5 is implemented: the agent side of the
helper (`transparent::helper`: starting it through `ShellExecuteExW`, the
liveness pipe server, its status line and noticing when it stops), the
availability check (`transparent::availability`), and the agent wiring: the
IPC mode word, `SessionInfo::transparent`, and transparent browser and
terminal sessions in the agent in the [order of
operations](#order-of-operations), over an engine seam (`src/agent/engine.rs`)
and `Launcher::tag`, the configuration (`[transparent] dscp`), the IPC
`transparent` request, the `status` lines, the `session list` marking and
the CLI flags (`gateinto session terminal --agent --transparent`, `gateinto
open --transparent`), and the GUI's mode choice, its marking of transparent
sessions and its engine row in Settings. Step 6a, packaging, is implemented:
the optional MSI feature with the pinned WinDivert files and their license,
which the release workflow downloads and checks; no MSI with it has been
built or installed yet.
`Job::set_dscp_tag`, the helper's Windows bindings, the Windows attribution
and listener socket, the agent side of the helper, the agent's Windows
engine, the availability probes on Windows and the GUI's window code, and
their tests have only been type-checked from Linux until Windows CI runs them; the helper has
never opened a WinDivert handle and `ShellExecuteExW` has never been
called. The design rests on premises that have
not been verified: the evidence is two experiments on GitHub-hosted Windows
Server images ([Evidence](#evidence)), and nothing has been tried on a
client edition of Windows, unelevated, over IPv6, or next to a VPN or
antivirus product. Those premises are listed under [Needs
verification](#needs-verification). Names marked *(proposed)* do not exist in
the code yet; every other name refers to the code at the time of writing.

## Summary

A transparent session routes every outbound IPv4 TCP connection of the
processes in a session's job object through the session's proxy, and so
along its gateway route, without depending on the application honouring
proxy settings; every other packet they send (UDP and QUIC, ICMP, and all
IPv6) is dropped, not relayed. The session keeps its proxy settings
(`--proxy-server` for a browser, the proxy variables for a terminal);
transparent routing catches every IPv4 TCP connection that ignores them.
The agent tags the session's job with a DSCP value through
`SetInformationJobObject(JobObjectNetRateControlInformation)`; Windows then
marks every IPv4 and IPv6 packet those processes send, from the first SYN
on. A separate elevated helper, `gateinto divert`, holds one
WinDivert handle that reflects tagged TCP packets to a listener of the agent
and drops every other tagged packet. For each connection the agent accepts
there, it finds the original connection in the system TCP tables, checks
that its owner is in the job of a live transparent session, and hands the
connection to that session's proxy, which opens `CONNECT <ip>:<port>`
through the gateway as for any other tunnel. Connections to the session's
own loopback proxy are outside the filter and work as today.

```text
 process in the session's job ignoring the proxy settings, DSCP tag N
   |  SYN  L:p -> R:port, DSCP N
   v
 gateinto divert (elevated, WinDivert NETWORK layer)
   |  rewrite: R:p -> L:T, DSCP 0, checksums; inject inbound
   v
 agent: transparent listener 0.0.0.0:T accepts a connection from R:p
   |  TCP tables: row L:p -> R:port, owner in the job of session S (else close)
   v
 session S's proxy: route (gateway/mixed), tunnel limit, pool, counters
   |  CONNECT R:port through the gateway (or direct on `mixed`)
   v
 gateway
 agent replies L:T -> R:p are rewritten by the helper to R:port -> L:p
```

Transparent sessions are opt-in, per session, for browser and terminal
sessions started by the agent. Proxy-mode sessions stay the default and do
not change.

## Goals

- Route the TCP traffic of applications that ignore proxy settings (Java,
  Node.js `fetch`, `ssh`, Windows PowerShell 5.1, `winget`, game launchers,
  ...) when they run inside a session's job, without depending on the
  application honouring proxy settings.
- Keep proxy mode for everything that honours the settings: those programs
  still send host names to the gateway and resolve nothing locally.
- Keep the session model: one session per job, with its gateway, route,
  tunnel limit, upstream pool, counters and lifetime; tunnels end when the
  session closes.
- Fail closed: a transparent session that cannot be fully set up does not
  start, and a session whose engine stops is closed.
- Keep the device key, the configuration and every credential in the
  unelevated agent. The elevated part rewrites packet headers only.
- Leave Gateinto unchanged on machines without WinDivert, without
  administrator rights, or on unsupported platforms.

## Non-goals

- Routing processes outside a session's job, or the whole machine. There is
  no system-wide transparent mode.
- IPv6 translation, UDP or QUIC relaying, DNS through the gateway, and
  host names from TLS ClientHello SNI in the first version
  ([Limits of the first version](#limits-of-the-first-version)).
- A Windows service or a machine-wide install. The MSI stays per-user
  ([install.md](../install.md#why-per-user)).
- Linux, macOS and Windows on ARM64. WinDivert has no ARM64 build; Linux
  would need a different mechanism (for example a cgroup-based nftables
  mark) and its own design.
- In-process transparent sessions (`gateinto session terminal` without
  `--agent`, `gateinto session browser`).
- Transparent sessions from `gateinto://` links.
- Making the client machine an enforcement boundary
  ([security model](../security-model.md#routing-scope)).

## What exists today

- `Job::new` (`src/job.rs`) creates an unnamed, non-inheritable job with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` through `SetInformationJobObject` with
  `JobObjectExtendedLimitInformation`. `Job::active_processes` reads job
  information with `QueryInformationJobObject`. `Job::handle` is
  `pub(crate)`. On Linux `Job::new` checks the systemd user scope
  prerequisites (`src/job/linux.rs`); elsewhere it returns `Unsupported`.
- `Job::set_dscp_tag(Dscp)` (`src/job.rs`, Windows only) sets
  `JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`
  with the tag and `MaxBandwidth = 0` through
  `JobObjectNetRateControlInformation`, reads it back with
  `QueryInformationJobObject`, and fails when either flag or the tag
  differs. Type-checked from Linux only.
- `crate::divert` (`src/divert.rs`, platform-independent, unit-tested on
  every platform):
  - `Dscp` (1 to 63, `Dscp::DEFAULT` 43, `InvalidDscp` otherwise) and
    `divert::filter(NonZeroU16, Dscp)`, which writes the filter text below;
  - `Engine::new(listener_port: NonZeroU16, capacity, idle_timeout)`,
    `Engine::process(packet, Direction, now) -> Verdict` (`InjectInbound` or
    `Drop`) and `Engine::counters() -> Counters` (`src/divert/engine.rs`);
  - the flow table with `LINGER` (120 s), `DEFAULT_IDLE_TIMEOUT`
    (2 h 4 min) and a full-table sweep at most once per `SWEEP_INTERVAL`
    (1 s) (`src/divert/flows.rs`);
  - parsing, `reflect`, `restore` and full checksum recomputation
    (`src/divert/packet.rs`);
  - `divert::fuzzing` (with `--cfg fuzzing`), a checker over
    `Engine::process` for a fuzz target;
  - `DEFAULT_CAPACITY` (16384 flows);
  - the [liveness pipe](#liveness-pipe) protocol (`divert::protocol`):
    `Event` (`Ready`, `Failed(ErrorCode)`, `Counters(Snapshot)`) and its
    line encoding, and `StatusReader`, the agent-side reader, fuzzed by the
    target `divert-status`;
  - the engine loop (`divert::pump::run`) over the `DivertPort` and
    `Liveness` seams, with `REPORT_INTERVAL` (10 s), `GRACE_PERIOD` (5 s) and
    `PACKET_BUFFER_BYTES` (65575);
  - the helper's argument types (`PipeName`, `ListenerPort`), exit codes and
    sequence (`divert::helper::run` over the `Platform` seam), and
    `sha256_matches`;
  - the `netsh` command lines (`divert::firewall`);
  - the pinned WinDivert release (`helper::DRIVER_VERSION` 2.2, the file
    digests in `src/divert/windivert.rs`) and the `WINDIVERT_ADDRESS`
    layout (`windivert::Address`), compiled on Windows and in tests; the
    packaging manifest `packaging/wix/windivert.txt` is checked against
    those digests by the unit tests in `src/divert/windivert/packaging.rs`
    (see [WinDivert distribution](#windivert-distribution));
  - the Windows implementation of the seams (`src/divert/windows.rs`) and
    the hidden subcommand `gateinto divert` (`src/main.rs`), Windows only.

  The agent starts the helper through its agent side, described below.
- `windows-sys` 0.61.2 with `Win32_System_JobObjects`, enabled in
  `Cargo.toml`, defines the net rate control types; `Win32_System_IO`,
  `Win32_System_Pipes` and `Win32_System_SystemInformation` were added for
  the helper, and `Win32_UI_Shell` (`ShellExecuteExW`) for its agent side.
- `os_user` (`src/proxy/os_user.rs`): `Row { local, remote, pid }`, `owner`
  (the row whose local end is the client's address and whose remote end is
  the listener, pid not 0, addresses compared canonically), and `lookup`
  over `families(peer)`: an IPv4 peer searches the IPv4 table and then the
  IPv6 table, where a dual-stack socket carrying IPv4 appears with
  IPv4-mapped addresses. The Windows backend
  (`src/proxy/os_user/windows.rs`) reads `GetExtendedTcpTable` with
  `TCP_TABLE_OWNER_PID_CONNECTIONS` (`rows`, `table`), retries
  `LOOKUP_ATTEMPTS` (5) times `LOOKUP_DELAY` (5 ms) apart, opens the process
  with `PROCESS_QUERY_LIMITED_INFORMATION`, reads the table again while the
  handle is held (pid reuse), compares the token's SID with `EqualSid` and,
  when the session has a job, calls `IsProcessInJob`.
  `Authenticator::os_user` (`src/proxy/local_auth.rs`) runs the lookup in
  `spawn_blocking` under the connection's deadline.
- `Proxy::bind` (`src/proxy/mod.rs`) refuses a listen address that is not
  loopback (`Error::NonLoopbackListen`) and a tunnel limit above
  `MAX_TUNNELS`. `Proxy::run_until` owns the listener; per accepted
  connection it takes a permit of `Shared::tunnels` (`Limits::max_tunnels`,
  default 64) or answers `503` through the `rejects` semaphore, and spawns
  the connection into a `JoinSet` that `connections.shutdown()` aborts when
  the session closes. `Shared::handle` runs the `os_user` lookup, reads a
  `CONNECT` head, checks local authentication, opens the upstream with
  `Shared::open_upstream` under `handshake_timeout` (default 10 s), writes
  `HTTP/1.1 200 Connection Established`, and relays. On
  `UpstreamError::Challenge` it stores the verification offer
  (`Verifications::offer`). `Proxy::adopter` returns an `Adopter` through
  which a stream accepted elsewhere is adopted without a `CONNECT` head
  ([Adoption](#adoption-into-the-sessions-proxy)); `proxy::reset` closes a
  stream with zero linger.
- `Shared::open_upstream` calls `routing::attempt` (`src/proxy/routing.rs`):
  on `Route::Gateway` it returns at once; on `Route::Mixed` it resolves the
  target and the gateway, connects directly unless an address matches a
  gateway address, and otherwise falls back to `pool.open`. `Authority`
  (`src/http.rs`) has `Host::Ipv4` and `Host::Ipv6` variants and converts
  from a `SocketAddr` (`From<SocketAddr>`, an IP literal);
  `connect_request` writes `CONNECT {target}` with the literal.
- The step 4 parts, which the agent uses (the listener socket, the
  attribution and the dispatch loop on Windows only):
  - `os_user::original`, `one_session`, `all_rows`, `confirmed` and `retry`
    (`src/proxy/os_user.rs`) and the Windows lookup `Attribution`
    (`src/proxy/os_user/windows.rs`), described under [Transparent listener
    and attribution](#transparent-listener-and-attribution); `Row` carries
    the connection's TCP state (`TcpState`: `Established`, `CloseWait` or
    `Other`, from `dwState`), which only the listener-row rule reads;
    `Denial::kind` names a denial without its details;
  - `transparent::listener` (`src/transparent/listener.rs`,
    `src/transparent/listener/windows.rs`): `choose` over the `Bind` seam,
    `PORT_ATTEMPTS` (64), and on Windows `reserve` and `Reserved::listen`;
  - `transparent::state` (`src/transparent/state.rs`): `State<K, J>`, the
    engine state with the generation counter and the registry of
    transparent sessions under one `std::sync::Mutex`, `Phase`, `Begin`,
    `Starter`, `Joiner`, `Refusal`, the session mark `Mark` with its
    `Launch` guard and `Closing`, and the `Terminate` seam over a job,
    implemented by `Job` (`Job::terminate`: `TerminateJobObject` on
    Windows, an `Unsupported` error elsewhere, where no transparent session
    exists); see [Engine state and session
    registration](#engine-state-and-session-registration);
  - `transparent::serve` (`src/transparent/serve.rs`): `serve`, the
    accept and dispatch loop of one generation's listener over the
    `Attribute` seam, which `Attribution` implements on Windows, and
    `MAX_ATTRIBUTIONS` (64).
- `SessionManager::start` (`src/sessions.rs`) binds the `Proxy` with
  `Proxy::bind_sharing`, takes its `Adopter` (`Session::adopter`) and moves
  it into a task running `run_until` with a close signal; `Session` keeps no
  handle to the proxy's `Shared`.
- Browser sessions (`Agent::start`, `src/agent.rs`): `Launcher::job` returns
  `browser_job()`, which on failure logs a warning and returns `None`; on
  `SpawnError::Job` the agent closes the session and starts a proxy-mode
  browser without a job, with `session_credentials` only; a transparent one
  fails instead. The browser gets `--proxy-server=http://<listen>` from
  `browser::browser_args`, in both modes.
- Terminal sessions (`Agent::terminal`): `terminal::terminal_job` turns a job
  failure into an error with no fallback; `terminal::terminal_proxy` sets
  `LocalAuth::OS_USER` with the job; `terminal::terminal_environment` sets
  the proxy variables to the session's loopback listener, in both modes.
- The agent is unelevated and per-user, started by `spawn_agent`
  (`src/main.rs`) or the `HKCU` `Run` value. The MSI installs
  `%LOCALAPPDATA%\Programs\Gateinto\gateinto.exe`, a directory the user can
  write. `lifecycle::windows::elevated` reads `TokenElevation`;
  `check_account` adds `ELEVATED_NOTE` when `setup` runs elevated.
  `transparent::helper::Windows` starts the elevated helper (below) when the
  agent starts its engine for a transparent session.
- `ConfigFile` (`src/config.rs`) has `deny_unknown_fields` and the sections
  `gateways`, `device_key`, `limits`, `browser`, `terminal` and
  `transparent`.
- IPC (`src/ipc.rs`): `Request::Launch(LaunchRequest, Mode)` carries
  `uri::LaunchRequest`, the type the `gateinto://` parser produces, and the
  mode apart from it; `Request::Terminal` carries `TerminalRequest { gateway,
  route, mode }`. `Mode` is `Proxy` (the default) or `Transparent`, whose
  word `mode=transparent` ends the line ([CLI, IPC, GUI and
  status](#cli-ipc-gui-and-status)). `SessionInfo` (`ipc-types`) uses
  `serde(default)` without `deny_unknown_fields` and has `transparent`,
  serialized only when true.
- `gateinto status` (`status` in `src/main.rs`) prints Linux-only lines from
  `lifecycle::current_linux_status`, and on every platform the
  `transparent-sessions` line and, from a running agent, the
  `transparent-engine` line ([CLI, IPC, GUI and
  status](#cli-ipc-gui-and-status)).
- The test upstream fixture (`tests/fixture/`, `UpstreamProxy`) records
  every request head (`requests()`); `Behavior::Tunnel` connects to the
  `CONNECT` target itself.
- `.github/scripts/win7-imports.txt` lists every DLL import allowed in the
  experimental Windows 7 build of `gateinto.exe`; the agent side of the
  helper added `shell32.dll ShellExecuteExW`, `kernel32.dll GetProcessId`
  and `kernel32.dll GetNamedPipeClientProcessId`, all on Windows 7.
- The step 5 parts so far:
  - `transparent::helper` (`src/transparent/helper.rs`, platform-independent
    and unit-tested on every platform with a fake platform and paused time):
    `Supervisor::new(platform)` and `Supervisor::start(ListenerPort, Dscp)`
    over the `Platform` (`create_pipe`, `launch`), `Pipe` (`connect`,
    `client_pid`, `AsyncRead`) and `Process` (`id`, `wait`) seams, which
    returns `Running` or a `StartError`; `Running::stopped`, which completes
    once with `Stopped` (`Closed`, `Protocol` or `Exited`); `Exit` (the exit
    code, if it could be read); `PREVIOUS_HELPER_TIMEOUT` (25 s),
    `START_TIMEOUT` (60 s) and `DRAIN_TIMEOUT` (1 s); see [Order of
    operations](#order-of-operations) and [Liveness pipe](#liveness-pipe).
    The Windows implementation (`src/transparent/helper/windows.rs`):
    `Windows` (the platform), `Server` (the pipe server) and `Elevated`
    (the helper's process handle);
  - `transparent::availability` (`src/transparent/availability.rs`, with
    the Windows probes in `src/transparent/availability/windows.rs`):
    `available()`, `Availability` (`available` or `unavailable: <reason>`),
    `Reason`, and the cache of the last verified files (`Stamp`,
    `Verified`); see [CLI, IPC, GUI and status](#cli-ipc-gui-and-status);
  - `job::parameters`, the command-line quoting of `src/job.rs` for a
    parameter string without the executable;
  - the agent wiring (`src/agent.rs`, `src/agent/engine.rs`):
    `AgentOptions::dscp` (`main` passes `Dscp::DEFAULT` until the
    configuration sets it), `LaunchLimiter::would_allow`, `Launcher::tag`,
    the engine seam `Engine` (`available`, `start`) with `Started` (the
    helper's `stopped` future and a `Listener` that runs the dispatch loop),
    implemented on Windows by `Divert` over one `Supervisor<helper::Windows>`
    and elsewhere by an unavailable engine; the agent's registry
    (`Inner::registry`, `State<SessionId, Job>`), `Agent::ensure_engine`,
    `Agent::watch_engine`, `Agent::register`, `launched` and
    `Agent::transparent_engine` (`EngineStatus`: the phase and the last
    helper error); see [Order of operations](#order-of-operations);
  - the status (`src/ipc.rs`, `src/agent.rs`, `src/main.rs`,
    `src/session_table.rs`): the IPC `transparent` request with
    `TransparentStatus` and `ipc::transparent_status`, the agent's answer,
    the `transparent-sessions` and `transparent-engine` lines of
    `gateinto status`, and the ` (transparent)` marking of the `PROGRAM`
    cell in `session list` and the session table of `status`; see [CLI,
    IPC, GUI and status](#cli-ipc-gui-and-status).

## Evidence

Two experiments in `experiments/job-dscp` and `experiments/job-dscp-route`
on branch `claude/dreamy-cerf-2f0b4c` (not merged), run on GitHub-hosted
`windows-2022` (build 20348) and `windows-2025` (build 26100), elevated,
IPv4 only, one external destination, with WinDivert 2.2.2. The counts below
are recorded in the description of pull request #117 (head 933e2e0); the
experiment READMEs describe the cases and verdict rules but not the counts,
and the CI logs and artifacts expire. Small samples; evidence, not
guarantees.

- **Experiment 1** (capture only): a job with
  `JobObjectNetRateControlInformation`
  (`JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`)
  marks every outbound packet of its processes, a grandchild included, from
  the first SYN or UDP datagram on, as seen at WinDivert's NETWORK layer;
  processes outside the job are not marked.
- **Experiment 2** (reflect engine `route.cpp`, a bridge listener and
  Gateinto's `Proxy` with `Route::Gateway`), identical verdicts on both
  images:
  - `https-external` and `load`, with jobs tagged DSCP 10 and 20 and the
    "any non-zero" filter (`ip.TOS >= 4`): tagged sessions routed through
    the gateway 6 of 6 and, with a 30-way burst, 40 of 40; the NIC capture
    saw no pure SYN from a tagged local port and no segment from the bridge
    port; untagged attempts went direct;
  - `shared-dscp`, exact-match filter on DSCP 43: two sessions sharing the
    code point were attributed to the right session 12 of 12 by an owner
    lookup at accept time (`GetExtendedTcpTable` and `IsProcessInJob`). The
    bridge took the original destination from the engine's translation map
    and never depended on that lookup;
  - `qos-policy`, exact-match filter: a QoS-policy mark (DSCP 46) outside the
    job was ignored, and inside a DSCP 43 job the job tag won over the
    policy;
  - `udp-containment`, exact-match filter with containment: tagged UDP was
    contained (0 datagrams on the wire) while TCP still routed;
  - send errors, orphans, SYN retransmits and key collisions were all 0.
- **Overhead** in that setup: about +65 to +75 ms p50 sequential and +110 to
  +130 ms p50 in a 30-way burst, on top of about 410 to 450 ms direct. It
  included a helper process per connection for the owner lookup and a Python
  bridge with an authenticated `CONNECT` to a loopback proxy, so it is
  expected to be an upper bound, not a product measurement. Throughput was
  not measured.

Not covered by either: client SKUs (Windows 10 and 11), an unelevated
process setting the tag (runners are elevated), IPv6 (no IPv6 route on the
runners), domain-joined machines, VPN, antivirus and other WFP products,
nested jobs, browsers, an application-set DSCP inside a tagged job, and the
original destination taken from the TCP tables.

## Design

### Platform and scope

**Decision: Windows 10 1607 / Windows Server 2016 or later, x86 and x64;
opt-in per agent-hosted browser or terminal session.**

- `JobObjectNetRateControlInformation` needs Windows 10 1607. The agent
  checks the build at runtime; on older systems, including the experimental
  Windows 7 build, transparent sessions are unavailable and `status` says so.
- WinDivert ships x86 and x64 builds only. Gateinto has no ARM64 build; the
  x64 build under ARM64 emulation cannot load an x64 driver.
- The i686 build under WOW64 needs the x86 `WinDivert.dll` with the 64-bit
  driver; see [Needs verification](#needs-verification).
- Only session kinds that already own a job: agent browser sessions
  (`Agent::start`) and agent terminal sessions (`Agent::terminal`).
  A transparent browser session has no job fallback: if `browser_job()`
  returns `None` or the spawn fails with `SpawnError::Job`, the session
  fails instead of restarting with `session_credentials` and no job.

### The mark

**Decision: one DSCP code point shared by all transparent sessions, default
43, configurable 1 to 63.**

- 43 is `101011`, in pool 2 (`xxxx11`, experimental or local use) of RFC
  2474, so it matches no standard per-hop behaviour.
- The value comes from the configuration file only:

  ```toml
  [transparent]
  dscp = 43
  ```

  `TransparentSection { dscp: Option<Dscp> }` in `src/config.rs`, with
  `deny_unknown_fields`; `Dscp` accepts 1 to 63 and defaults to
  `Dscp::DEFAULT` (43). The dotted key `transparent.dscp` and an inline
  table work too. A value out of range or of the wrong type, an unknown key
  and a `transparent` that is not a table (an array included) are refused.
  The error starts with toml's "TOML parse error at line N, column M" and
  an excerpt of the file; its message line starts with `[transparent]` and
  names the key at fault, for example "[transparent] dscp: invalid value:
  integer `64`, expected an integer between 1 and 63", also for an integer
  outside the i64 range up to 128 bits (a larger one gets toml's "integer
  number overflowed"), or "[transparent] invalid type: sequence, expected a
  table". An older Gateinto refuses a file with `[transparent]` (unknown
  section). The agent reads it once at start, like `[browser] executable`,
  into `AgentOptions::dscp`.
- Setting: `Job::set_dscp_tag(Dscp)` with read-back. The session does not
  start when the call fails or the read-back lacks either flag or reports
  another tag; the failure is reported with its Win32 error code, never
  ignored.
- Nested jobs (unverified): net rate control is expected to be allowed on
  only one job in a nested hierarchy, so the call would fail when the agent,
  or the process that starts the session, already runs in a job that holds
  it. That failure ends the request like any other.
- Own-job check *(proposed)*, best effort: the agent refuses transparent
  sessions when its own process carries a net rate control tag, because its
  own upstream connections would then be tagged, reflected to its own
  listener and loop. `QueryInformationJobObject` with a null handle sees only
  the job the process is immediately in, so a tag on an outer job is missed;
  the check is a diagnostic, not a guarantee.
- The job tag is expected to replace any DSCP the application sets; only a
  QoS policy was tested against it (experiment 2: the job tag won over a
  DSCP 46 policy).

### Engine state and session registration

**Decision: one engine state and a per-session open/closing mark, each under
a lock, so that no process starts in a job after the engine stopped.**

- The agent keeps one engine state under a lock (`transparent::state::State`,
  the agent's `Inner::registry`, a `State<SessionId, Job>` for the agent's
  lifetime): `stopped`, `starting(g)` or `running(g)`
  (`Phase`). The same `std::sync::Mutex` guards the generation counter and
  the registry of transparent sessions, so that registering only under
  `running(g)` is one atomic step. The generation `g` is a counter incremented
  under the engine lock each time a start sets `starting`; it identifies
  one start and the one helper that start launches. Every transition below
  is checked and made under the engine lock.
- **A start** moves `starting(g)` to `running(g)` on `ready`, or back to
  `stopped` on failure, only if the state is still `starting(g)` with its
  own generation. Otherwise it changes nothing, closes its own listener and
  helper, and its request fails. Requests that wait for a start receive the
  outcome of the generation they joined, never that of a later one.
- **The pipe-break handler** belongs to one helper and carries that
  helper's generation `g`. It acts only if the state is `starting(g)` or
  `running(g)`: it sets `stopped`, takes a snapshot of the transparent
  sessions registered under `g`, closes them as below, and closes that
  helper's listener. In any other state it changes nothing.
- **Registration** of a transparent session succeeds only when the state is
  `running(g)` at the moment of registration, and the registry entry records
  that current `g` (which may be newer than the generation the request saw
  in step 1; the new helper then covers the session); the handler's
  snapshot is exactly the entries recorded with its generation. A session
  registering after the handler ran finds `stopped` (or a newer
  generation's `starting`), is closed, and no process is launched.
- **Why a late or repeated break changes nothing.** The state leaves
  generation `g` in only two ways: the handler of `g`, which under the same
  lock sets `stopped` and snapshots every session registered under
  `running(g)`, or a failed start of `g`, which leaves `starting(g)` before
  any session could register. After either, no session can register under
  `g` again, because the state never returns to an old generation. So when
  a break from an older helper arrives late, or the same helper's pipe break
  and process exit both arrive, every session of that generation has
  already been snapshotted and closed, and the newer generation is left
  alone.
- Sequence this rules out: start A receives `ready`; helper A dies and its
  handler sets `stopped`; request B sets `starting(g+1)` and waits on helper
  A's process handle; start A then finds `starting(g+1)`, not its own
  `starting(g)`, changes nothing and fails. Neither A's hand-over nor A's
  failure path can make B's start `running` or clear it.
- Each transparent session has an `open` or `closing` mark (`Mark`)
  under its own lock. Every launch into the session's job holds that lock
  while it spawns and refuses when the mark is `closing`. The pipe-break
  handler takes the same lock, sets `closing`, and then terminates the job.
  So a spawn either finishes before the terminate, and the terminate kills
  its process, or sees `closing` and refuses.
- **In the code** (`src/transparent/state.rs`):
  - `State::begin` returns `Begin::Start(Starter)` from `stopped` (after
    incrementing the generation and setting `starting(g)`),
    `Begin::Join(Joiner)` from `starting(g)` and `Begin::Running(g)` from
    `running(g)`. `Starter::finish(result)` is the hand-over or the failure
    path of start `g`: it moves `starting(g)` to `running(g)` on `Ok`, or to
    `stopped` on `Err`, only from its own `starting(g)`; otherwise it
    changes nothing and returns an error (a successful start then fails
    with "the transparent engine stopped while it was starting"). Every
    joiner of `g` receives exactly that result through `Joiner::outcome`,
    a `tokio::sync::watch` channel of its own generation. A `Starter`
    dropped without `finish`, for example because its request was
    cancelled, finishes as a failure ("abandoned"), so neither the state
    nor its joiners wait forever. It first passes that error to the hook
    set with `Starter::on_abandon`, through which the agent records it as
    the engine's last error before the phase becomes `stopped`.
  - `State::stop(g)` is the pipe-break handler. Under the state lock it
    checks `starting(g)` or `running(g)`, sets `stopped` and removes the
    registry entries recorded with `g`; after releasing it, it takes each
    entry's mark, sets `closing`, terminates the job through the
    `Terminate` seam (a failure, or a panic caught per entry, is logged as a
    warning and the other jobs are still terminated) and releases the mark.
    It returns the keys of all those sessions, which the caller then closes
    through the existing close paths; in any other state it returns none. It
    blocks on each mark while a launch holds it, so the agent calls it off
    the async runtime (`spawn_blocking`).
  - `State::register(key, job, adopter)` succeeds only under `running(g)`
    and returns the session's `Mark`; otherwise it refuses with
    `Refusal::NotRunning`, and a key already registered is refused with
    `Refusal::Registered`, so an entry is never replaced. `State::unregister`
    drops the entry when the session closes. `State::jobs(g)` is the
    snapshot of the keys and jobs registered under generation `g` for
    attribution, taken under the lock and released before the lookup.
    `State::adopt(g, key, stream, target)` looks up the session registered
    under `g` and calls `Adopter::adopt` (`try_send`, which never waits)
    under the same lock, so a `stop` or `unregister` cannot fall between
    the lookup and the send: once either has taken the entry, every later
    adopt hands the stream back. A stream adopted before them is in the
    session's adoption channel, which the session's close resets.
  - `Mark::launch` returns a `Launch` guard, held while the process is
    spawned (inside the `spawn_blocking` closure that spawns it), or
    `Closing`.
- **Lock order.** A terminal launch (`Agent::terminal`) takes `launching`
  (`Inner::launching`), then `Inner::terminals`, which it holds through job
  creation, the tag, `SessionManager::start`, the registration and the
  spawn, then `Inner::sessions` for the start and the registration; the
  comment above its `terminals` lock states "launching, terminals,
  sessions, engine state, session mark". A browser launch takes
  `launching` (in `Agent::launch` in proxy mode, in
  `Agent::launch_transparent` for a transparent one) and holds
  `Inner::sessions` in `Agent::start` across `SessionManager::start`, the
  registration and the spawn. Both register (`Agent::register`, the
  engine lock) while holding `sessions`, and take the session's mark
  (`launched`) inside the `spawn_blocking` closure that spawns the process.
  `Agent::close` and `Agent::close_all` take
  `Inner::browsers` or `Inner::terminals`, release it, and then take
  `Inner::sessions` (`close_all` unregisters its sessions while holding
  it). The new locks are innermost: launching, terminals, sessions, engine
  state, session mark.
- **Lock scope of the handler.** It holds the engine lock only to check
  its generation, set `stopped` and take the snapshot, and each session's
  mark only to set `closing` and terminate that job. It releases both
  before it closes the sessions through the existing close paths, which
  take `Inner::browsers` or `Inner::terminals` and then `Inner::sessions`.
  It never waits for a lock of the existing order while holding a new one,
  so a launch that holds `terminals` or `sessions` while waiting for the
  engine lock cannot deadlock with it. In the agent (`Agent::watch_engine`,
  then `Agent::close_stopped`) it runs `State::stop` in `spawn_blocking`,
  then ends that generation's listener, then takes and releases
  `launching` before it closes the sessions through `Agent::close`: a
  launch that registered before the stop adds its session to `browsers` or
  `terminals` only when it ends, and a close before that would only close
  the session and miss its process. It holds no other lock while it waits
  for `launching`, and a launch holding `launching` waits for nothing the
  handler holds. If the blocking task does not finish (a `JoinError`, from
  a panic `State::stop` does not catch or from the runtime shutting down),
  `stop` may already have set `stopped` and taken the entries, but their
  keys are lost. The handler then fails closed: it closes every session
  flagged transparent in `browsers` and `terminals`, which can include
  sessions of a newer generation, and leaves proxy-mode sessions alone.

### Order of operations

**Decision: helper ready, then listener, then job tag, then registration,
then processes.**

For a transparent session request the agent:

0. Runs read-only pre-checks, which can refuse the request without side
   effects, so that a request that would fail anyway raises no UAC prompt.
   The authoritative checks under `launching` (and, for terminals, under
   `terminals`) stay as they are and run again.
   The pre-checks are the start of `Agent::launch_transparent`, before
   `Agent::ensure_engine`, for browsers and
   `Agent::check_transparent_terminal` for terminals.
   - **Rate limit.** `Agent::allow_launch` locks `Inner::launches`, a
     `std::sync::Mutex` around `LaunchLimiter`, and calls
     `LaunchLimiter::allow`, which drops entries older than `launch_window`
     and, when fewer than `launches` remain, records the request and returns
     true. `Agent::launch`, `Agent::launch_transparent` and `Agent::terminal`
     call it right after taking `launching`. `allow` consumes a slot, so the
     pre-check calls `Agent::would_allow_launch`, which uses the read-only
     `LaunchLimiter::would_allow` under the same mutex: it drops expired
     entries but records nothing, and `allow` is `would_allow` followed by
     the record. Both answer the same rate-limit error.
   - **Platform.** Terminals: `Launcher::terminals()`, as `Agent::terminal`
     asks it. Both kinds: `Engine::available` (`Agent::check_transparent`,
     in `spawn_blocking`, since the Windows probe hashes the WinDivert
     files); `unavailable: <reason>` refuses with "transparent sessions are
     unavailable: <reason>". Outside Windows the engine is always
     unavailable ("transparent sessions need Windows").
   - **Capacity.** Browsers: `Agent::check_capacity` compares
     `Inner::browsers` with `AgentLimits::max_browser_sessions`. Terminals:
     `Agent::check_terminal_capacity` compares the count of `Inner::terminals`
     with `max_terminal_sessions`; the pre-check takes `terminals` only to
     read the count, `Agent::terminal` checks again while holding it.
   - **Gateway.** Terminals: `Agent::terminal_plan`, the same call
     `Agent::terminal` makes: `Profiles::terminal_session(&gateway)`, which
     refuses a gateway that is not in the configuration file. As for the
     browser plan below, it runs in `spawn_blocking`, and the pre-check
     discards it and `Agent::terminal` builds it again, under `launching`
     and `terminals`, because the CA file, the client certificate and the
     shell executable can change while the request waits for the helper.
     Browsers: `Agent::known` and `link::resolve` with
     `Decision::Defer` (`transparent_launch`), which reads only.
     `Agent::known` runs `Profiles::known()` in `spawn_blocking`, as every
     path of the agent does, since the linked gateways are files under
     `%APPDATA%`, which can be redirected to a network share. A result
     other than `Resolution::Launch`, that is a request that would need a
     gateway confirmation, is refused for a transparent session ("a
     transparent session is not started for a request that needs a gateway
     confirmation; ..."), because the transparent mode is never set by a
     link. Such a request never becomes the pending confirmation.
   - **Session plan.** Browsers: `Agent::browser_plan` for the gateway the
     request resolved to, the same call `Agent::start` makes:
     `Profiles::browser_session`, which refuses settings that do not
     resolve, and `browser::find_browser`, which refuses a configured
     browser that is not a file or a system without a browser. It runs in
     `spawn_blocking`, since building the proxy configuration reads the CA
     file and can sign with the device key. The pre-check discards the plan
     and `Agent::start` builds it again under `launching`: while the request
     waits for the helper, another process can forget a linked gateway and
     `Agent::approve` can link the name again with another address, and the
     CA file, the client certificate and the browser executable can change.
     Terminals: an absolute `USERPROFILE` in `Launcher::environment`
     (`home_dir`), the shell's working directory, refused with "the agent
     has no absolute USERPROFILE to start the shell in; nothing was
     started".

   The pre-checks guarantee no UAC prompt only for the requests they refuse.
   Several concurrent requests can pass them, share one prompt, and still be
   refused under `launching` (rate limit, capacity) or later.
1. Ensures the helper runs, before the request takes `launching`,
   `terminals` or `sessions`, so waiting for the UAC answer never blocks
   other launches or closes. The engine lock is not held while waiting: a
   request that finds `stopped` increments the generation, sets
   `starting(g)` under the lock and performs the start; a request that finds
   `starting(g)` waits for the outcome of generation `g`, so one start
   raises one UAC prompt; a request that finds `running(g)` continues.
   Before starting a new helper the agent waits on the previous helper's
   process handle, which may still be ending, bounded by
   `PREVIOUS_HELPER_TIMEOUT` (25 s, above the helper's worst-case end of
   about 20 s: the 5 s grace period, the 5 s shutdown watchdog and up to
   10 s for the final `netsh`), and fails with "the previous transparent
   engine has not ended" if the old helper does not end. The previous
   helper is the last one launched, also by a start that failed after the
   launch; the agent keeps one `Supervisor` for its lifetime (in the
   Windows engine `Divert`), so this holds across generations. A helper of
   an earlier agent run is not known to the new agent; the new helper then
   answers `error another-helper` ("another transparent engine is running
   or still ending on this machine; try again in a few seconds"). In the
   agent this step is `Agent::ensure_engine` over
   the `Engine` seam (`src/agent/engine.rs`); steps 2 and 3 are
   `Supervisor::start` (`src/transparent/helper.rs`). The start:
   1. reserves the listener port T (`transparent::listener::reserve`): it
      binds a socket to `0.0.0.0:0` with `SO_EXCLUSIVEADDRUSE`, without
      listening. If the system hands out a port below 49152 (a customised
      dynamic range), it closes that socket and binds explicit ports in
      49152 to 65535 instead: up to 64 independent random draws
      (`PORT_ATTEMPTS`), skipping a port that is in use (`AddrInUse`) or
      excluded (`PermissionDenied`, as for a reserved port range) and
      stopping at any other error. `SO_EXCLUSIVEADDRUSE` keeps every other
      socket off port T, which matters because the engine treats any
      captured packet with source port T as a listener reply;
   2. creates the [liveness pipe](#liveness-pipe) with a name from 16 bytes
      of `SystemRandom` and starts the [helper](#the-divert-helper) with
      `divert --pipe <name> --agent-pid <pid> --port T --dscp N` through
      `ShellExecuteExW`; a declined prompt (`ERROR_CANCELLED`, 1223) fails
      with "the administrator approval for the transparent engine was
      declined";
   3. waits for the helper to connect and for its first line at most 60 s
      (`START_TIMEOUT`), measured from `ShellExecuteExW` returning, so time
      spent on the UAC prompt is not counted (whether the call blocks until
      the prompt is answered needs verification). It checks the client's
      pid before it reads anything. If the helper process ends first, it
      drains the pipe for at most 1 s (`DRAIN_TIMEOUT`) and reports an
      `error` line found there, otherwise the exit code. `ready` returns a
      `Running` handle; anything else fails the start and closes the pipe;
   4. on `ready`, starts listening on T and, under the engine lock, moves
      the state from `starting(g)` to `running(g)` only if it is still
      `starting(g)` with its own generation; otherwise its helper has
      stopped meanwhile, it closes its listener and the request fails. On
      any failure before that it sets `stopped`, again only from its own
      `starting(g)`. Listening only after the helper has added the
      firewall rule avoids Windows Firewall's "allow this app" prompt for
      `gateinto.exe`, which would create a rule for every port if the user
      accepted it (needs verification).

   In the agent, the Windows engine creates the `Attribution`, reserves the
   port, runs `Supervisor::start` and listens; any failure there is
   answered with its message and recorded for `status`, and
   `Starter::finish(Err(message))` hands it to every joiner. Then
   `Agent::ensure_engine` looks once, biased, at the running handle's
   `stopped` future: a helper whose pipe already broke fails the start with
   its own message. This look is only a fast path: on the real overlapped
   pipe a break is rarely observed that early and the poll mostly returns
   pending, so the stop-watcher is the real guard. Otherwise it spawns the
   stop-watcher on the handle (`Agent::watch_engine`), which from then on
   drains the counter lines and runs the handler of `g` whenever the helper
   stops, and calls `Starter::finish(Ok(()))`. That can fail only if the
   watcher has already stopped `g`; the listener is then dropped and the
   request fails, and the watcher needs no release from the start, since it
   has already ended that generation. On
   success it spawns that generation's `serve` with a shutdown future that
   ends when the watcher drops its sender. No lock is held while it waits,
   and a request that joined receives the same outcome.
2. Creates the job, sets and reads back the tag: under `launching` (and
   `terminals`) the authoritative checks run again, then `Launcher::job` or
   `Launcher::terminal_job`, then `Agent::tag` (`Launcher::tag`, on Windows
   `Job::set_dscp_tag`, in `spawn_blocking`) with `AgentOptions::dscp`. A
   transparent browser without a job fails ("a transparent browser session
   needs a job object, which could not be created; nothing was started");
   a tag that cannot be set fails with "setting the DSCP tag N on the job
   of the session failed: <error>; nothing was started".
3. Starts the session (`SessionManager::start`, with the proxy settings of
   proxy mode) and registers its job and adoption channel
   (`Session::adopter`) with the transparent listener under the engine lock
   (`Agent::register`, `State::register`), only if the state is
   `running(g)` then, recording that `g`. A refusal closes the session and
   answers "the transparent engine is not running; nothing was started".
4. Starts the browser or shell in the job under the session's mark: the
   `spawn_blocking` closure holds `Mark::launch` while it spawns
   (`launched`), and a closing mark fails the spawn ("the transparent
   session is closing"). A failed spawn unregisters and closes the session;
   a transparent browser whose spawn fails with `SpawnError::Job` is not
   started again without a job.

Any failure closes what was opened and answers an error. Every close path
(`Agent::close`, `Agent::close_all`, a session that ends by itself, the
stop-watcher) unregisters the session (`State::unregister`). There is no
silent downgrade to a proxy-mode session: the user asked for transparent
routing, and a proxy-mode session would send everything that ignores the
proxy settings directly. Messages name the cause: the helper's `error` code,
the helper's exit code when it ended without a line, a timeout, the tag that
could not be set, a system too old.

### The divert helper

**Decision: a separate elevated process, `gateinto divert`, a hidden
subcommand of the same executable, started on demand through UAC.**

The MSI is per-user, the agent runs unelevated, and there is no machine
service, so opening a WinDivert handle (which needs administrator rights and
loads a kernel driver) needs an elevated process. The agent starts it with
`ShellExecuteExW`, verb `runas`, the absolute path of its own executable
(`std::env::current_exe`), the arguments quoted by `job::parameters`,
`SW_HIDE`, `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
SEE_MASK_FLAG_NO_UI`, and keeps the returned process handle
(`transparent::helper::Elevated`, pid from `GetProcessId`).
`SEE_MASK_NOASYNC` because the call runs on a thread of Tokio's blocking pool
(`spawn_blocking`), which may end soon after the call returns, and the flag
is meant for such callers: the call completes before it returns.
`SEE_MASK_FLAG_NO_UI` keeps the shell from showing an error dialog of its
own, for example when the executable cannot be started, since the agent
answers the error itself; the UAC consent prompt is not error UI and is
expected to still appear (see [Needs verification](#needs-verification)).
The agent does not call `CoInitializeEx`: no shell extension is involved in
running an executable with `runas`, and it would add `ole32.dll` to the
imports (see [Needs verification](#needs-verification)). The process is
waited for on a thread of its own, as `job::Process` does
(`WaitForSingleObject`, then `GetExitCodeProcess`), so it holds no
blocking-pool thread for the life of the helper and does not delay the
runtime's shutdown.

- **Arguments:** `divert --port T --dscp N --pipe <name> --agent-pid <pid>`.
  The subcommand takes each as a raw `Option<OsString>`, accepts values that
  start with `-`, and passes a missing or non-UTF-8 value on as empty, so
  clap refuses nothing that the helper should report. It reads no
  configuration, opens no device key, sets up no logging, touches no IPC,
  and replaces the panic hook with one that prints nothing. `main`
  dispatches it before it builds the Tokio runtime, so the helper starts no
  runtime worker threads. They come from
  the unelevated agent, so the helper validates
  them: the pipe name must match the fixed Gateinto pattern, N must be 1 to
  63, T must be in 49152 to 65535. An invalid pipe name cannot be reported
  on the pipe, because nothing is reported before the pipe is connected; the
  helper then ends with an exit code only. An invalid DSCP or port is
  refused with `error invalid-arguments`. With an arbitrary port the helper
  could be used to black-hole a service port: inbound packets to T are
  dropped, and the service's replies from T are dropped as unknown replies.
  No secret is passed. The helper reads no configuration file, opens no
  device key, never connects to the agent's IPC endpoint and never calls
  `check_current_account`.
- **Steps, in this order:**
  1. validate the pipe name and connect to the pipe; nothing is reported
     before that, because there is no channel yet;
  2. validate the other arguments;
  3. create the machine-wide mutex (below);
  4. delete a stale firewall rule and add the rule for T
     ([Firewall](#firewall));
  5. open, hash and check the WinDivert files ([WinDivert
     distribution](#windivert-distribution));
  6. load `WinDivert.dll`, open one NETWORK-layer handle with the static
     filter, read the driver version with `WinDivertGetParam`
     (`WINDIVERT_PARAM_VERSION_MAJOR`, `WINDIVERT_PARAM_VERSION_MINOR`) and
     refuse any version other than the pinned one (`DRIVER_VERSION`, 2.2);
  7. send `ready` and run the engine loop.

  A panic between a successful `add` and the final `delete` is caught. The
  helper releases the handle, deletes the rule, and ends with exit code 5.
  Inside the engine loop, a panic in the packet loop marks the loop ended
  and a panic in the reporter shuts the port down, so neither leaves the
  other thread waiting. A panic in the liveness wait counts as the agent
  gone. Release builds unwind (no `panic = "abort"` in `Cargo.toml` or
  `.cargo/config.toml`, and the Windows 7 build only builds the
  `panic_abort` crate). Built with `panic = "abort"`, a panic would end the
  process at once: Windows closes the handle and the mutex, the pipe breaks,
  and the rule stays until the next helper start, as for a killed helper.
- **What it never does:** see payload beyond the TCP and IP headers it
  rewrites, terminate TLS, hold a credential or a key. The mTLS key stays in
  the agent; this also matters when the UAC prompt is answered with a
  different administrator account, whose user cannot use the device key
  anyway.
- **Lifetime:** until the agent stops. One administrator approval per agent
  run, not per session. With no transparent session open, no packet carries
  a job tag, but packets that other software marks with the same DSCP are
  still captured and dropped while the helper runs.
- **Exit codes** (`divert::helper`): 0 after a normal end, 3 when it could
  not report (invalid pipe name or agent pid, no connection, or a status
  line that could not be written), 4 after writing `error <code>`, 5 after a
  fatal engine error.
- **One helper per machine**: the helper creates the named mutex
  `Global\Gateinto-divert` (`CreateMutexW`, not owned, only its existence
  matters) and answers `error another-helper` if it exists or cannot be
  created; the agent reports it as "another transparent engine is running
  or still ending on this machine; try again in a few seconds", since the
  helper of an earlier agent run may still be in its grace period. Two
  handles with overlapping filters would steal each
  other's packets: the first would divert another agent's sessions to its
  own listener, where attribution fails and the connections are closed. A
  second agent (another `GATEINTO_INSTANCE`, or another Windows user on the
  same machine) is therefore refused with a clear message rather than
  broken. Any local user can create that mutex first and so block
  transparent sessions on the machine; that is a local denial of service,
  not a bypass. Per-instance code points are a possible later step.
- **Agent death and pipe break:** when the agent ends, its job handles close
  and `KILL_ON_JOB_CLOSE` ends the session processes. The helper notices the
  broken pipe, any byte from the agent, a failed write, or the agent's exit
  (it opens the agent process with `SYNCHRONIZE` from `--agent-pid`), keeps
  its WinDivert handle open for a grace period of 5 s (`GRACE_PERIOD`) so
  that packets from processes still being killed are dropped or refused
  rather than leaked, then closes the handle, deletes the firewall rule and
  exits. The 5 s is a margin, not a measurement. Closing the handle restores
  normal networking; according to WinDivert's documentation the driver
  stays loaded until the next reboot (see [WinDivert
  distribution](#windivert-distribution)). On a normal stop the agent
  cancels starts still waiting for UAC, closes its sessions, disconnects the
  helper pipe and waits up to 25 s for the helper to exit before answering.
  The helper closes the handle before it deletes the rule, and releases the
  mutex only after that, because the next helper adds a rule of the same name.
- **Fatal packet-loop error:** when receive fails while the agent is still
  connected, the helper sends `stopping` and keeps the WinDivert handle open
  until the agent disconnects or 25 s elapse. The agent closes the affected
  sessions before disconnecting. The helper then closes the handle and removes
  the firewall rule. A panic in the packet loop uses the same notification.
- **Shutdown watchdog:** WinDivert documents that a `WinDivertRecv` made
  after `WinDivertShutdown` fails with `ERROR_NO_DATA` once the queue is
  empty, but not that a receive already blocked on an idle handle wakes up.
  The helper does not depend on it: once the engine loop has called
  `shutdown()` (after the grace period, or after a panic in the reporter),
  it waits at most `SHUTDOWN_DEADLINE` (5 s) for the packet loop to end.
  If the loop has not ended by then, the helper deletes the firewall rule,
  ignoring the result, and ends the process with exit code 5
  (`Platform::abandon`; `std::process::exit` on Windows). Ending the
  process closes the WinDivert handle and the mutex. When the receive does
  return, nothing changes.

#### Liveness pipe

- The agent creates a named pipe with a random name
  (`\\.\pipe\gateinto-divert-` and 32 lowercase hex digits,
  `PipeName::from_random`), one instance (`max_instances(1)`),
  `PIPE_ACCESS_DUPLEX`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients
  rejected, a server handle that is not inheritable (`bInheritHandle =
  FALSE`), and the security descriptor
  `O:<user>D:P(A;;GA;;;<user>)(A;;GA;;;BA)`, which allows the agent's user
  and the Administrators group only (`transparent::helper::Windows`, as the
  agent pipe in `src/ipc.rs` builds its own). Duplex, because the helper
  opens the pipe for reading and writing and keeps a read pending; not
  inheritable, so that the agent's death breaks the pipe even while a
  process the agent started is still running.
- The helper opens the pipe with `SECURITY_SQOS_PRESENT |
  SECURITY_IDENTIFICATION`, so the pipe server can query the helper's
  identity but cannot act as the helper, and checks
  `GetNamedPipeServerProcessId` against `--agent-pid` before it opens the
  agent process with `SYNCHRONIZE`. It opens the pipe with
  `FILE_FLAG_OVERLAPPED` and no sharing: the reporter's writes wait for
  their own completion for up to 2 s, while the liveness wait keeps a one-byte overlapped
  read pending and waits with `WaitForMultipleObjects` on that read's event
  and the agent process handle. It returns when the read completes (any
  byte, or an error such as a broken pipe) or the agent process ends, then
  cancels the read and waits for it. On a handle opened without
  `FILE_FLAG_OVERLAPPED`, Windows serializes I/O on the handle, so the
  pending read would block every counter line. The agent accepts
  exactly one client and checks
  `GetNamedPipeClientProcessId` against the pid of the process handle
  `ShellExecuteExW` returned before it reads a byte; on a mismatch the start
  fails and the pipe is closed, which makes that helper exit (the unelevated
  agent cannot kill it).
- An agent that sees the helper process end drains the pipe before it
  reports a generic exit: exit code 4 means the helper wrote an `error` line
  just before it ended. The drain lasts at most `DRAIN_TIMEOUT` (1 s), long
  enough for a connection and data the helper sent before it ended to be
  delivered; a `ready` found there still fails the start with the exit
  code, since the helper has ended.
- **Protocol.** The helper's first and only status line is either `ready` or
  `error <code>` with `<code>` from a fixed list (`ErrorCode`):
  `invalid-arguments`, `another-helper`, `firewall-rule`, `files-missing`,
  `digest-mismatch`, `driver-load <win32 error>`, `driver-version`. After
  `ready`, the helper sends counter lines and can end with `stopping`.
  A counter line starts with `counters`, then ` name=value` for the
  16 fields of `Counters` in their order and `receive_errors` and
  `send_errors`, each value a decimal `u64` without sign or leading zeros.
  The helper writes one every 10 s when a value changed since its last line
  (all zero before the first), and a last one when the engine loop ends
  while the agent is still there. These are the only data the agent reads
  from the elevated side. Lines are printable ASCII ending in `\n`, at most
  1024 bytes (`MAX_LINE_BYTES`). Anything else, including a second status
  line, a line after `error` or `stopping`, counters before `ready`, an empty line or the
  end of the stream inside a line, is a protocol error (`StatusReader`) and
  is treated as a broken pipe. The agent sends nothing; a byte from the
  agent means to the helper that the agent is gone.
- A helper that ends before it connected, or before its first line, is
  detected through the process handle from `ShellExecuteExW` and reported
  generically with its exit code. Whether the unelevated agent can wait on
  and query that handle for an elevated child needs verification.
- `Running::wait_for_stop` completes on `stopping` (`Stopped::EngineFailed`),
  a closed or broken pipe (`Stopped::Closed`), a protocol error
  (`Stopped::Protocol`), or helper process exit (`Stopped::Exited` with its
  code). The agent holds `Running` until it finishes closing the generation.
  Dropping `Running` closes the pipe. The supervisor records process exit for
  a subsequent start or an agent stop.
- When the agent receives `stopping`, sees the pipe break, a protocol error, or the helper process
  end, it runs that helper's pipe-break handler (`State::stop`) with the
  helper's generation: if the state is still that generation's, engine
  state `stopped`, every transparent session of that generation marked
  `closing` and its job terminated, the sessions closed, that helper's
  listener closed (the shutdown of its `serve` loop; see [Engine
  state](#engine-state-and-session-registration)); in any other state it
  changes nothing. In the agent this is `Agent::watch_engine`, which also
  logs the cause at `warn` and keeps it as the last helper error
  (`Agent::transparent_engine`) before it stops the generation. `status`
  then reports the engine as stopped with that error; a new transparent session starts a new helper (a new generation)
  and asks UAC again.

#### Engine

The engine reflects packets as WinDivert's `streamdump.c` does. The pure,
platform-independent core is `crate::divert`; the engine loop (`divert::pump`)
receives each packet through the `DivertPort` seam, passes it to
`Engine::process` with its `Direction`, and injects exactly the received
length for `Verdict::InjectInbound`; a failed send is counted and the loop
continues. `DivertPort::shutdown` is sticky: it can land between two `recv`
calls, so every later `recv` returns `RecvError::Shutdown` once the queued
packets are drained. The Windows binding (`src/divert/windows.rs`) implements
the seam with `WinDivertRecv`, `WinDivertSend` and
`WinDivertShutdown(WINDIVERT_SHUTDOWN_BOTH)`, which WinDivert documents as
sticky in that way: after it, `WinDivertRecv` fails with `ERROR_NO_DATA` once
the queue is empty, and that error, and only that one, becomes
`RecvError::Shutdown`. Whether `WinDivertShutdown` also wakes a
`WinDivertRecv` already blocked on an idle handle is not documented; the
[shutdown watchdog](#the-divert-helper) bounds that wait. Each packet is
injected with a copy of the address it was received with: `Outbound` cleared,
so it goes up the inbound path of the interface it was to leave on
(`Network.IfIdx`, `SubIfIdx`), and `IPChecksum` and `TCPChecksum` set, as
`WinDivertHelperCalcChecksums` does after recomputing checksums. WinDivert
requires injected packets to carry correct checksums or the corresponding flag
cleared, and the engine always writes both checksums in full.
`Engine::process` does not check the DSCP itself: every outbound packet it
receives is tagged or comes from port T, because the filter selects nothing
else.

Filter (static, compiled once; `DSCP==N` written as the TOS or traffic
class range `4N` to `4N+3`, so the ECN bits may be anything):

```text
(outbound and !loopback and
   ((ip and ((ip.TOS >= 4N and ip.TOS <= 4N+3) or (tcp and tcp.SrcPort == T)))
    or (ipv6 and ipv6.TrafficClass >= 4N and ipv6.TrafficClass <= 4N+3)))
or (inbound and !loopback and tcp and tcp.DstPort == T)
```

Built by `divert::filter(T, Dscp)` with T a `NonZeroU16`. For N = 43 the
range is 172 to 175. Loopback is excluded so that local traffic stays local;
the experiment README gives as its reason that loopback replies to a tagged
client inherit the tag, which was not measured.

Rewrite:

| Packet | Action |
| --- | --- |
| outbound tagged IPv4 TCP `L:p -> R:port` | look up or create the flow; rewrite to `R:p -> L:T` (addresses swapped, destination port T, DSCP cleared, ECN kept), recompute IPv4 and TCP checksums in full, inject inbound |
| outbound IPv4 TCP from port T, `L:T -> R:p` | find the flow `(R, p)`; rewrite to `R:port -> L:p`, recompute checksums, inject inbound |

Checksums are recomputed over the whole packet, never adjusted
incrementally: with checksum offload the captured outbound packets may
carry a partial or no checksum. The engine never injects a packet that
carries IPv4 options: an IPv4 TCP packet with an IHL above 5 is dropped and
counted in both the client and the listener path. A total length larger than
the captured bytes is malformed; bytes after the total length are left
alone. The helper injects the captured length, as `streamdump.c` does.
Whether large send offload hands the NETWORK layer packets whose total
length differs from the captured length needs verification.

Flow table:

- Key `(R, p)` (remote address, local port); value: remote port, the SYN's
  initial sequence number, FIN seen per direction, last activity, end time.
- A pure SYN (SYN without ACK) with no flow creates one; with the same
  sequence number it is a retransmit; with a new one, or on an ended flow, it
  replaces the flow (the local port was reused). A packet whose remote port
  differs from the flow's is a key collision, dropped and counted.
- A flow ends on RST in either direction, or once FIN has been seen in both
  directions; it then lingers for `LINGER`, 120 s, so late ACKs and
  retransmitted FINs still match. The value is a margin of the order of
  Windows' `TIME_WAIT`, not checked against the Windows default. Idle flows
  age out after `DEFAULT_IDLE_TIMEOUT` (2 h 4 min, the RFC 5382 minimum for
  established mappings) as a backstop.
- Expired flows are removed when looked up. When the table is full, a sweep
  of all expired flows runs at most once per `SWEEP_INTERVAL` (1 s), so a
  tagged process cannot make the helper scan the table on every refused
  SYN.
- Capacity 16384 flows (`DEFAULT_CAPACITY`), passed to `Engine::new`; a SYN
  that finds the table full is dropped and counted, and the client
  retransmits.

Dropped and counted, never injected:

- IPv4 fragments, packets with IPv4 options, and malformed packets;
- non-SYN packets of unknown flows (orphans), and replies from port T
  without a flow;
- tagged IPv4 packets that are not TCP: UDP, QUIC, ICMP and others are
  contained;
- every tagged IPv6 packet: the first version does not translate IPv6, and
  applications are expected to fall back to IPv4 (needs verification; a RST
  in reply to a tagged IPv6 SYN may be needed to make that prompt);
- every inbound packet the filter selects, that is genuine inbound packets
  addressed to port T, so no other machine reaches the listener. This relies
  on WinDivert not re-diverting the handle's own injected inbound packets to
  the same handle (needs verification).

Counters (`divert::Counters`, aggregate integers): `captured`, `new_flows`,
`reflected`, `replies_restored`, `syn_retransmits`, and one per drop reason
(`orphans_dropped`, `key_collisions`, `unknown_replies_dropped`,
`fragments_dropped`, `options_dropped`, `malformed_dropped`, `table_full`,
`contained_udp`, `contained_other`, `contained_ipv6`, `inbound_dropped`).
The engine loop adds `receive_errors` and `send_errors`. They go to the
agent over the pipe and into the agent's log at `debug`, one event
"transparent engine counters" with every field (`Running::stopped`).

### Transparent listener and attribution

**Decision: one agent-level listener on `0.0.0.0:T`, separate from
`proxy::Proxy`.**

- The transparent listener is its own code, not a `Proxy`:
  `transparent::listener` reserves and later opens its socket, and
  `transparent::serve::serve` runs its accept and dispatch loop.
  `Proxy::bind` keeps its loopback-only invariant
  (`Error::NonLoopbackListen`) unchanged.
- A non-loopback bind is unavoidable: the reflected packets are addressed to
  the NIC address L that the application used, and WinDivert cannot turn a
  non-loopback packet into a loopback one. The port is chosen as in [Order
  of operations](#order-of-operations), with `SO_EXCLUSIVEADDRUSE`.
- For an accepted connection with peer `R:p` and local address `L:T`, the
  agent reads both TCP tables, IPv4 and IPv6, as `os_user::lookup` does
  with `families`: a dual-stack IPv6 socket carrying IPv4 (Java, .NET)
  appears in the IPv6 table as `::ffff:L:p` to `::ffff:R`. Addresses are
  compared canonically.
- **Direct dials are refused first** (`SelfTarget`). A loopback peer
  (127.0.0.0/8 or `::1`, also IPv4-mapped) is refused at once: the filter
  excludes loopback, so a reflected peer never is one. So is a connection
  for which any row, whatever its pid or state, has local end `R:p` and
  remote end `L:T`: a reflected peer R is a remote host, never a local
  socket, so such a row is the dialer's own socket. A dialer that is still
  connected, or that closed with a FIN, leaves that row (in `TIME_WAIT`
  with pid 0 once it has closed). One that closes abortively (RST) leaves
  none, but its reset also ends the listener's accepted socket, so every
  reading must also contain the listener's own row, local end `L:T`,
  remote end `R:p`, a pid other than 0 and the state `ESTABLISHED` or
  `CLOSE_WAIT` (`Row::state`, `TcpState`, read from the tables'
  `dwState`); without it the connection is not found (`NotFound`). The
  state matters in case Windows still lists a reset socket, as `CLOSED`
  with the agent's pid; `CLOSE_WAIT` is kept so that a client that has
  already sent its FIN is still attributed. The dialer's row, in contrast,
  counts in any state. A dialer that resets between the two readings is
  caught by the second one. Without these rules a process
  outside every job could take the local port of a client in a transparent
  job (`SO_REUSEADDR`), or the same port on a second local address, dial
  the listener, and be attributed to the client's session with the
  client's destination. A process inside a job that dials the listener,
  through L, another local address or loopback, is refused the same way.
- Candidate rows are those whose local end is `L:p` and whose remote
  address is R. Rows with pid 0 (such as a `TIME_WAIT` row left by an
  earlier use of the port) or remote port 0 are not candidates, and the
  same socket listed in both tables (same pid, canonically equal ends)
  counts once.
- For each candidate the owner's process is opened, its SID must equal the
  agent's, and `IsProcessInJob` must be true for the job of exactly one
  live transparent session. A row whose owner is outside every transparent
  job is discarded, so a row left by another owner does not make two. A
  row whose owner is another user is discarded too, which is equivalent:
  the agent starts the processes of its jobs under its own token, so
  another user's process is in none of them. An owner in the jobs of more
  than one session, or one that could not be opened or queried (a lookup
  error, the deadline), ends the lookup with that denial instead, so that
  an owner the agent could not attribute cannot let another row win.
- Exactly one row must then remain. Its remote port is the original
  destination port. The tables are read again while the owners' handles
  are held (pid reuse), as `System::check` does, and both readings must
  agree on the owner and the destination. The lookup retries like
  `System::find`, only when no row was found or the readings disagree, and
  runs in `spawn_blocking` under the handshake deadline.
- No row, more than one row, a direct dial, an owner outside every
  transparent job or in several sessions' jobs, an owner of another user,
  or a lookup error closes the connection without contacting any upstream.
  When no owner is admitted, the first refusal is the denial.
- This one lookup gives both the session (and so its gateway and route) and
  the original destination `R:port`, so the helper needs no data channel to
  the agent. Taking the destination from the TCP tables is untested (the
  experiment used the engine's translation map); the fallback, if it proves
  unreliable, is a per-flow message from the helper on the pipe, which would
  widen what the agent parses from the elevated side.
- The matcher is `os_user::original`, a pure function over `Row` next to
  `owner`, so it is tested on every platform; `Attribution`
  (`src/proxy/os_user/windows.rs`) is its Windows lookup.
- **Dispatch** (`transparent::serve::serve`, over the `Attribute` seam that
  `Attribution` implements on Windows). `serve` is given the generation
  whose listener it runs. A peer that can never be reflected is reset at
  once, before it takes an attribution permit or reads any table: a
  loopback peer (127.0.0.0/8 or `::1`, also IPv4-mapped), one whose
  address is the accepted socket's own local address, and one with any
  other address of this host, such as that of a Hyper-V, WSL, Docker or
  VPN adapter. A reflected peer is always a remote host, because traffic
  to the host's own addresses goes over loopback, which the filter
  excludes. The last check reads the host's IPv4 unicast address table
  (`GetUnicastIpAddressTable` with `AF_INET`, freed with `FreeMibTable`),
  not the TCP tables: the engine reflects IPv4 only and the listener is
  IPv4, so every peer is, and an IPv4-mapped peer is compared by its IPv4
  address. Only an address in use, whose `DadState` is preferred or
  deprecated, counts as this host's: a tentative one is still being
  checked for a conflict, a duplicate one is another host's, and an
  invalid one is not in use. The table is read for every stream that
  passes the two cheaper checks, in the accept loop: the call queries the
  system and waits on nothing, and an attribution reads two larger tables
  anyway. Nothing is bound: the agent never binds a socket to an address a
  peer chose, which, if it could raise Windows Defender Firewall's "allow
  this app" prompt, would let any local process raise it at will. An
  address that is not in use, like a table that cannot be read, counts as
  remote, because a peer wrongly counted as local would have a genuine
  stream reset, while one wrongly counted as remote only takes a permit
  and is then refused by `original`. So a local process, of any user, that
  dials the listener over loopback (where the firewall rule does not
  apply) or from any address of this host is reset before it can hold a
  permit for two table readings, unless the address table cannot be read.
  `original` keeps its own direct-dial checks behind it. Transparent
  sessions exist only on Windows; elsewhere the same check binds a UDP
  socket to the peer's address with port 0, which succeeds only for an
  address of the host, so that it can be tested. For
  every other stream the loop takes the snapshot of the sessions
  registered under its generation (`State::jobs(g)`), runs the attribution
  in `spawn_blocking` with the handshake timeout as its deadline, and on a
  match hands the stream with `Authority::from(destination)` to that
  session through `State::adopt(g, ..)`, which looks the session up and
  sends under the state lock. A session registered under another
  generation is in neither, so the listener of an older generation that is
  still shutting down cannot dispatch into a newer generation's sessions.
  A denial, the timeout, a failed (panicked) attribution task, a session
  that is no longer registered under the generation, and an adopter that
  hands the stream back (full or closed) each reset the stream (zero
  linger). At most 64 attributions are in flight (`MAX_ATTRIBUTIONS`); each
  holds its permit until the blocking lookup returns, also after its
  timeout, so lookups that outlive their deadline still count, and a
  stream beyond the bound is reset at once. The shutdown future given to
  `serve` ends the loop: the listener is dropped and every dispatch in
  flight is aborted, which resets its stream; a lookup already running
  finishes on its thread and its result is discarded. The agent passes the
  default handshake timeout of a session (`proxy::Limits::default()`,
  10 s), since the listener belongs to no session: `[limits]
  connect_timeout_seconds`, which sets a session's `handshake_timeout`,
  does not apply to the transparent listener.

**Decision: proxy settings are kept.** The session's own loopback listener
stays as today, with `os_user` restricted to the job (terminal) or
`browser_local_auth(true)` (browser), and the application is still pointed
at it: a transparent browser gets `--proxy-server` from
`browser::browser_args`, a transparent terminal the proxy variables from
`terminal::terminal_environment`. Connections to that loopback listener are
outside the filter (`!loopback`), so they work as today. Programs that
honour the settings keep sending host names to the gateway and resolve
nothing locally; only connections that bypass the settings arrive at the
transparent listener, as IP literals.

### Adoption into the session's proxy

**Decision: an accepted stream is handed to its session's proxy, sharing
its tunnel limit, route, upstream pool, counters and lifetime.**

`Proxy::run_until` owns the listener and the session keeps no handle to
`Shared`, so a new entry point is needed:

- `Proxy::adopter() -> Adopter` before `run_until`; `Adopter` wraps a
  bounded `mpsc` sender of `(TcpStream, Authority)` with capacity
  `max_tunnels.max(1)`: a queued stream beyond the tunnel limit could
  only be reset. `Adopter::adopt` uses `try_send` and never waits, so one
  slow session cannot block the transparent listener; a full or closed
  channel hands the stream back, and the caller resets it with
  `proxy::reset` (zero linger). `run_until` selects on the shutdown
  signal, the listener and the adoption receiver.
- **Tunnel limit.** An adopted stream takes a permit from the same
  `Shared::tunnels` semaphore (`Limits::max_tunnels`) with
  `try_acquire_owned`, exactly like an accepted connection, and holds it
  until its task ends. Without a permit it is reset at once (no `503`: the
  application speaks TLS, not HTTP), and it never takes a `rejects` permit.
- `Shared::adopt(stream, target, permit)` skips the `os_user` lookup
  (attribution already did it), `read_head` and `Authenticator::check`,
  calls `open_upstream(&target)` under `handshake_timeout`, writes no local
  status line, forwards the gateway's early bytes to the client, and relays
  with `relay::relay`. Any upstream failure closes the client, with a RST
  (zero linger) so the application sees a refused connection rather than a
  clean end of stream. On `UpstreamError::Challenge` the verification offer
  is stored as in proxy mode (`Verifications::offer`), so the GUI and
  `session list` show it, and the stream is closed: nothing can be sent to a
  raw TCP client.
- **Lifetime.** The adopted stream's task is spawned into the same
  `connections` `JoinSet` as accepted connections. Closing the session sends
  its close signal; `run_until` leaves its loop, drops the listener, closes
  the adoption receiver and resets every stream still queued in it
  (receiving until the channel reports its end, so a send that had already
  reserved capacity is not lost), and `connections.shutdown()` aborts every
  task, adopted tunnels included, before the session's task ends.
  `Session::adopter` returns the adopter that `SessionManager::start` took
  from the proxy before `run_until`; the agent's registry of transparent
  sessions (`State::register`) maps each session to its job and adopter,
  and the agent drops the entry (`State::unregister`) when the session
  closes. A send after the close fails, and that stream is
  handed back and reset.
- `OpenTunnels` counts adopted tunnels like the others, so `session list`
  shows them.

### Target naming

**Decision: the first version sends `CONNECT <IP literal>:<port>`.**

That is what the application dialed. `Authority { host: Host::Ipv4(..) }`
already formats and parses it, and `routing::attempt` treats it like any
target: on `mixed` the agent connects directly unless the address is a
gateway address, without a DNS lookup. Reading the host name from the TLS
ClientHello SNI is a possible later step (it means buffering the first
client flight before choosing the route). Programs that honour the session's
proxy settings are not affected: they still send host names. Whether the
production gateway accepts IP-literal targets under its policy needs
verification; gateway policies keyed on host names will not match.

### WinDivert distribution

**Decision: an optional component, loaded at runtime by the helper only.**

- `WinDivert.dll` and the driver (`WinDivert64.sys`, and for x86 also
  `WinDivert32.sys`) of one pinned WinDivert release are installed next to
  `gateinto.exe` by an optional MSI feature. They are never linked into
  `gateinto.exe` and never loaded by the agent or the GUI.
- The feature is `Transparent`, "Transparent sessions (WinDivert driver)",
  inside `Main` in `packaging/wix/gateinto.wxs`: level 2, so off by default,
  and level 1 when `TRANSPARENT=1`, like `Autostart` with `AUTOSTART=1`. It
  installs the files of the MSI's arch and the release's `LICENSE` as
  `WinDivert-LICENSE.txt`, with `HKCU` key paths like the other components.
  It exists only in an MSI built with `build.ps1 -WinDivert <dir>`
  (`<?ifdef WinDivertDir?>`); without the option the MSI is built as
  before. The release workflow always passes it: for each arch,
  `.github/scripts/fetch-windivert.ps1` downloads the zip, checks its
  digest before opening it, extracts only that arch's files and the
  license, and checks each digest again; `build.ps1` checks them once more
  and refuses a directory with any other entry. Both scripts read the
  names and digests from `packaging/wix/windivert.txt` through
  `packaging/wix/windivert.ps1`, and the unit tests in
  `src/divert/windivert/packaging.rs` check that manifest against
  `src/divert/windivert.rs` and the zip digest below, and that the `.wxs`
  packages exactly the manifest's files per arch. The binaries are never
  committed. On a major upgrade Windows Installer keeps the feature's
  state (`MigrateFeatureStates`) and `TRANSPARENT=1` has no effect, except
  from a build without the feature; `ADDLOCAL=Transparent` or
  `REMOVE=Transparent` with the installed build's MSI adds or removes it
  later (not verified; see `packaging/wix/README.md`).
- The pinned release is WinDivert 2.2.2, `WinDivert-2.2.2-A.zip` from the
  upstream GitHub release (SHA-256
  `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`; the
  driver's Authenticode chain, a Sectigo EV certificate, was checked with
  `osslsigncode`). The files and their SHA-256 digests, pinned in
  `src/divert/windivert.rs`:

  | Build | File | SHA-256 |
  | --- | --- | --- |
  | x64 | `WinDivert.dll` | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
  | x64 | `WinDivert64.sys` | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |
  | x86 | `WinDivert.dll` | `a321649090c21aaa7529ce5d019d242b1d5f2a2aff04bc3224db409641604a83` |
  | x86 | `WinDivert32.sys` | `2f43f4251be4d72dd56c91bf6cce475d379eb9ba6c4dda2be3022ea633d5e807` |
  | x86 | `WinDivert64.sys` | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |

  The x86 build needs all three files: under WOW64 on a 64-bit Windows the
  64-bit driver is loaded. The release's `WinDivert.dll` imports only
  `KERNEL32.dll` and `ADVAPI32.dll`, both KnownDLLs. Its exports are
  `__cdecl` on x86 (no `WINAPI` in `windivert.h`, undecorated
  `_WinDivertOpen` in the x86 import library, and a plain `ret` in every
  export used), so the binding uses `extern "C"` on both builds.
- The helper looks for them in the directory of its own image
  (`std::env::current_exe`, that is `GetModuleFileNameW`) and loads them by
  absolute path after checking their SHA-256 digests. The installation
  directory is writable by the user, so the helper opens every file with
  `GENERIC_READ` and `FILE_SHARE_READ` only (no write or delete sharing),
  hashes it through that handle and keeps the handles open until the handle
  is open and its driver version checked, so they cannot be swapped between
  the check and the load (needs verification). A file that cannot be opened
  is `files-missing`, one whose digest differs (or that cannot be read) is
  `digest-mismatch`. `LoadLibraryExW` gets the absolute path with
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, never
  the default search order. The loaded module belongs to the WinDivert
  handle, not to the held files, because the files are released while the
  handle is live: the handle is closed first and the module freed after
  it.
- The digests do not decide which driver runs if another product's WinDivert
  driver is already loaded: `WinDivertOpen` then uses that driver. The
  helper therefore reads the driver version after opening the handle and
  refuses any version other than the pinned one (`error driver-version`).
- The driver is installed and started by the first `WinDivertOpen`. WinDivert's
  documentation (`doc/WinDivert.html` in the zip, "Uninstalling") says
  that its files can be deleted while the driver runs, that the driver is
  then removed at the next reboot, and that `sc stop WinDivert` and `sc
  delete WinDivert`, once no process uses WinDivert, remove it earlier. So
  the driver does not block removing the feature or uninstalling; the files
  that can be in use are `gateinto.exe` and `WinDivert.dll`, while the
  elevated helper runs. The MSI runs `StopAgent` before `InstallValidate`
  during uninstall, upgrade and removal of the installed `Transparent`
  feature. It waits for the command to succeed before validating file
  removal. CI builds and tests the WinDivert packages on x64 and x86.
- Without the files, or with a digest mismatch, Gateinto works as today;
  `status` and the error for a transparent request say which file is
  missing or differs.
- License: the release's `LICENSE` says "WinDivert is dual-licensed under
  your choice of the GNU Lesser General Public License (LGPL) Version 3 or
  the GNU General Public License (GPL) Version 2". Gateinto loads the
  unmodified DLL dynamically and installs the unmodified upstream files
  with that license text next to them as `WinDivert-LICENSE.txt`; the
  README's "Third-party software" names them. Gateinto's own license is
  unchanged.

### Firewall

**Decision: the helper adds a scoped inbound allow rule for its lifetime
with `netsh`.**

- The rule has one fixed name without spaces,
  `Gateinto-transparent-listener` (`divert::firewall::RULE_NAME`; `netsh
  advfirewall firewall add rule` has no group parameter as far as is
  known).
- At start the helper runs `netsh advfirewall firewall delete rule
  name=<name>` and ignores its exit code, because `delete rule` exits non-zero
  when nothing matches. It then adds one inbound TCP allow rule for local port
  T and the program `gateinto.exe` (the helper's own image path) with `add
  rule`; a failing `add` is fatal (`error firewall-rule`) and is followed by
  the same ignored `delete`, because an `add` killed at the timeout may still
  have added the rule. It deletes the rule on exit. The arguments, passed
  verbatim:

  ```text
  advfirewall firewall delete rule name=Gateinto-transparent-listener
  advfirewall firewall add rule name=Gateinto-transparent-listener dir=in action=allow protocol=TCP localport=<T> program="<image path>" enable=yes profile=any
  ```

  An image path that is not absolute on a drive (`X:\` or `\\?\X:\`; so
  no `\\?\UNC\`, `\\?\GLOBALROOT\` or volume paths), or that contains `"`,
  `%` or a control character, or ends with `\`, is refused
  (`error firewall-rule`): the quoted path cannot end early, and the
  firewall would expand `%NAME%`.
- `netsh` is started by absolute path under the system directory
  (`GetSystemDirectoryW`), never through `PATH`, with fixed arguments apart
  from the validated port and the helper's own image path; only
  its exit code is used, its output is not parsed. Its standard handles are
  null and it gets `CREATE_NO_WINDOW`. A `netsh` that has not ended after
  10 s (`NETSH_TIMEOUT`) is killed and counts as failed, so a hung `netsh`
  cannot hold the mutex past the agent's 60 s start timeout. The exact
  syntax needs verification. The Windows Firewall COM API (`INetFwPolicy2`)
  is the alternative if `netsh` proves unreliable; it would add `ole32.dll`
  and `oleaut32.dll` imports.
- A rule left by a killed helper stays until the next helper start. It
  allows inbound TCP to that port for the Gateinto executable only.
- The firewall is not what protects the listener: genuine inbound packets
  to T are dropped by the engine, and every accepted connection must pass
  attribution. The rule exists so that the injected inbound packets, whose
  source is a remote address, are not blocked.
- A policy that blocks all inbound connections, or a user rule blocking
  `gateinto.exe`, makes transparent connections time out; see [Needs
  verification](#needs-verification).

### CLI, IPC, GUI and status

The IPC mode, `SessionInfo::transparent`, the availability check, the
`transparent` status request, the `session list` marking, the `status`
lines, the CLI flags, the GUI's mode choice and its marking exist (step 5
of the [Implementation plan](#implementation-plan)).

- CLI: `gateinto session terminal --agent --transparent` and
  `gateinto open --transparent -- <uri>`. `--transparent` of
  `session terminal` requires `--agent` (clap's `requires`, so a missing
  `--agent` is clap's usual error). `gateinto open` is the command that
  asks the agent for a browser session; it always goes through the agent
  and has no `--agent`, so its flag requires nothing. `gateinto session
  browser` runs its own session without an agent and has no flag. Without
  the flag the request is unchanged and has no `mode` word.
  - Before sending a transparent request the CLI prints `starting the
    transparent engine may ask for administrator approval` on stderr.
  - A transparent `open` is not handed to an installed GUI, which receives
    only the link and would lose the mode; `gateinto open` sends it to the
    agent itself.
  - The client waits `ipc::TRANSPARENT_REQUEST_TIMEOUT` (300 s) for the
    answer to a transparent launch or terminal request and
    `ipc::REQUEST_TIMEOUT` (60 s) for any other request. The worst case of
    a transparent request is the wait for a previous helper (25 s), the UAC
    prompt (as long as the user takes), the start timeout (60 s) and the
    plan builds, so 300 s leaves more than three minutes for the prompt.
    `Request::timeout` chooses the limit and `ipc::send` applies it, so
    every client gets it. `RequestError::TimedOut` carries the limit that
    ran out and names it. When `gateinto open` has just started the agent,
    a transparent request waits the 300 s instead of what is left of the
    agent's 30 s start time. The Windows client's wait for a busy pipe
    keeps its 60 s limit and names it.
  - The agent sets no deadline on handling a request or writing its answer;
    its 10 s limit covers only reading the request line, so it does not cut
    a transparent request short. It does not watch the connection either:
    a client that gives up while the prompt is still shown does not stop
    the start, and the session may start after the CLI reported the
    timeout; `session list` then shows it.
  - An answer of exactly `invalid launch request` or `invalid terminal
    request` to a transparent request comes from an older agent (a current
    one parses every line the CLI writes) and is shown as "the agent is too
    old for transparent sessions; restart it". Proxy-mode requests keep the
    agent's message.
  - The answer to a transparent request gets a `mode: transparent` line
    after its `session:` line.
- IPC (`src/ipc.rs`): `terminal <gateway> route=<..> mode=transparent`, and
  for browsers the word `mode=transparent` at the end of the IPC `launch`
  line, after `route=`, `url=`, `gateway=` and `portal=`
  (`launch office session_credentials mode=transparent`). The word is
  accepted once, only as the last word, and only with the value
  `transparent`; a proxy-mode request has no `mode` word, and `mode=proxy`
  is refused, so every request has one spelling. `Request::Launch` carries
  `uri::LaunchRequest`, the type links produce, so the mode is a separate
  field of the IPC request (`Request::Launch(LaunchRequest, Mode)`;
  `TerminalRequest::mode`), not of `LaunchRequest`, and the `gateinto://`
  parser has no field for it (`mode`, `transparent` and any other unknown
  field fail as `UnknownField`). An older agent answers `invalid launch
  request` or `invalid terminal request`; the CLI says the agent is too old
  for transparent sessions, and so does the GUI.
- IPC status: the request `transparent`, without arguments, answers `ok`
  with `key: value` lines, in the style of the other answers:
  `availability: available` or `availability: unavailable: <reason>`, and
  `engine: running`, `engine: starting`, `engine: stopped` or
  `engine: stopped: <error>` (`ipc::TransparentStatus`). The error is the
  last helper error, the one that stopped the engine or made its last start
  fail; a successful start clears it, so it is sent only with `stopped`.
  The request starts nothing; the agent checks the availability through
  the engine seam in `spawn_blocking`, because on Windows it opens the
  WinDivert files and hashes them when they changed. The client (`ipc::transparent_status`)
  ignores lines with keys it does not know, so a later agent can add some,
  and refuses an answer with a line without `: `, a missing or repeated
  `availability` or `engine` line, an unknown value or an empty reason or
  error. An older agent answers `error: invalid request`, its answer to any
  request it does not know, which the client reads as "the agent is too
  old; restart it".
- GUI (`gateinto-gui`): while the agent runs, each refresh asks
  `transparent` after `config` (`worker::poll`), and `agent::Transparent`
  keeps the answer; a refused or failed request is `Unreported` and leaves
  the rest of the refresh as it was.
  - The Gateways page shows a "Proxy | Transparent" choice under its
    subtitle, at the left of the row that holds Add gateway, only when the
    answer is `availability: available` (`Transparent::offer`). The subtitle
    has the whole width of the page above that row, so the approval notice
    and failures such as the older-agent message fit at the minimum window
    size; the cards start under the row whether or not the choice is shown,
    so they do not move when it appears or goes. It is one choice for
    both Start browser and Open terminal of every gateway card, the only
    place that offers both, so it needs no new menu or dialog. It is drawn
    as the segmented control of Settings and is its own arrow-key group.
    Its tooltip says that every IPv4 TCP connection of the browser or
    terminal follows the gateway's route, that other traffic, such as UDP
    and IPv6, is blocked, and that starting the engine may ask for
    administrator approval. When the choice is hidden (unavailable,
    an older agent, an error, no agent) both buttons send proxy-mode
    requests; the choice is kept in memory only and comes back with the
    availability.
  - `Command::Launch` and `Command::Terminal` carry the `Mode` into the IPC
    request, so `ipc::send` applies the 300 s limit; the GUI has no timeout
    of its own. `Transparent::start` gives each start its mode by where it
    comes from (`agent::Origin`): a Gateways card gets the chosen mode while
    it is offered and `Mode::Proxy` otherwise; the Sessions page's Start
    browser, the tray flyout and `gateinto://` links always get
    `Mode::Proxy`.
  - While a transparent start is pending (`Launches::notice`), the
    Gateways and Sessions subtitles say "Starting the transparent engine
    may ask for administrator approval". The worker keeps one launch or
    terminal request in flight beside its polls, as it keeps a link's
    request, so the lists keep refreshing and other commands (Close, Stop,
    credentials, verification, Start, links and their answers) are handled
    during the wait; an approved link sends its own proxy-mode launch. The
    window sends no other start while one is pending (`Launches::busy`); a
    launch or terminal that reaches the worker meanwhile all the same waits
    in order and is sent once the one in flight is answered; closing the
    window drops both.
  - A transparent request refused as sent to an older agent
    (`ipc::agent_too_old_for_transparent`) shows "the agent is too old for
    transparent sessions; restart it"; proxy-mode answers keep their
    handling, including the terminal's `invalid request` check.
  - A session with `transparent` has a "Transparent" pill after its number
    on the Sessions page; proxy sessions have no mark, for the same reason
    `session list` has no mode column.
  - The Agent card of Settings ends with a "Transparent sessions" row:
    "Unavailable: <reason>", or "Available · engine running", "starting",
    "stopped" or "stopped: <error>"; it has no row while unreported.
- `SessionInfo` has `transparent: bool`, serialized only when true and set
  by the agent for its transparent browser and terminal sessions.
  `session list` and the session table of `status` append ` (transparent)`
  to the `PROGRAM` cell of such a session (`pwsh.exe (transparent)`): a mode
  column would read `proxy` on almost every row, and a marker in the last
  column leaves every earlier cell a single word.
- `gateinto status` always prints `transparent-sessions: available` or
  `transparent-sessions: unavailable: <reason>` (not Windows, system too
  old, ARM64, WinDivert files missing or digest mismatch) from its own
  check, so the line is there without an agent. When the agent answered
  `list`, it also asks for `transparent` and prints
  `transparent-engine: running`, `transparent-engine: starting`,
  `transparent-engine: stopped` or `transparent-engine: stopped: <error>`;
  an older agent gives `transparent-engine: unknown: the agent is too old;
  restart it`, and any other failure `transparent-engine: unknown:
  <reason>`. Without a running agent there is no engine line. The lines
  follow the session table and come before `uri-handler`. The check is
  `transparent::availability::available()`, in this order: not Windows
  ("transparent sessions need Windows"); a version older than 10.0.14393
  from `RtlGetVersion`, which does not depend on the executable's manifest
  as `GetVersionExW` does, or no version ("Windows 10 1607 or Windows Server
  2016 or later is required"); ARM64 ("Windows on ARM64 is not supported"),
  for a build that is neither x86 nor x64 or a native machine
  `IMAGE_FILE_MACHINE_ARM64` from `IsWow64Process2`, which covers the x86
  build under WOW64 and is expected to cover the x64 build under emulation
  (see [Needs verification](#needs-verification)); then the pinned files
  next to the executable, all opened before any is hashed, naming the first
  one missing ("WinDivert64.sys is missing next to gateinto.exe") or whose
  SHA-256 differs or cannot be read. The GUI asks every 2 s, so
  `available()` keeps, for the life of the process, the `Stamp` of every
  file it last found matching (`GetFileInformationByHandle` on the open
  file: volume serial number, file index, size and last write time) and
  skips the hashing while every stamp is unchanged; a changed or missing
  stamp hashes all files again, and a mismatch forgets them. The version,
  ARM64 and the opens are checked every time. A file rewritten in place
  with its old size and last write time put back would still count as
  available; that is acceptable because the answer only informs: the
  helper verifies the digests itself, through handles that deny writing,
  before it loads anything (see [WinDivert
  distribution](#windivert-distribution)). `RtlGetVersion` and `IsWow64Process2`
  are looked up at runtime (`GetModuleHandleW`, `GetProcAddress`), so
  neither becomes a static import, and `IsWow64Process2`, which Windows 7
  lacks, is only asked for after the version check passed.
- Links never select a transparent session: a page must not be able to
  trigger a UAC prompt.

### Logging

**Decision: proxy-mode logging does not change.**

- The agent logs the engine's start at `info` ("started the transparent
  engine"), a failed start at `warn` with the helper's message ("starting
  the transparent engine failed: ..."), and a stop at `warn` ("the
  transparent engine stopped: ...; closing its transparent sessions"); these
  messages carry error codes, exit codes and timeouts, never a pipe name,
  pid, port or path. A session's start line has a `transparent` field.
- Adopted tunnels log the target `R:port` at the same levels and in the same
  events as proxy-mode tunnels: `debug` when opening, `warn` with the cause
  when the upstream refuses
  ([security model](../security-model.md#exposure-and-logs)).
- Adopted tunnels never log the peer. `Proxy::run_until` opens an `info`
  span with the client's peer address for every accepted connection; for an
  adopted stream the peer `R:p` only repeats the destination address plus a
  local port, so the adoption path uses a span without it.
- The helper, the engine and the transparent listener's attribution log
  aggregate data only: counters, booleans, error codes. No addresses, ports,
  pids or paths. `serve` logs each refused stream at `debug` with the
  denial's kind only (`Denial::kind`, such as `not-in-job`, and
  `self-target` for a peer reset before any attribution), or that the
  session has closed or cannot take the stream, or that too many
  attributions are in flight; a denial's details, which may carry an OS
  error text, are not logged.

## Limits of the first version

- **DNS is local for connections that bypass the proxy settings.** Programs
  that honour the session's proxy settings resolve nothing locally and send
  host names, as today. For the rest, names are resolved by the system DNS
  client service (Dnscache), which runs outside the job, so queries are not
  tagged, go to the local resolver and are visible locally, even on the
  `gateway` route (inference, untested); the gateway sees IP literals for
  those connections.
- **UDP is dropped.** Tagged UDP never leaves the machine. QUIC falls back
  to TCP; applications that send their own UDP DNS (for example a browser's
  built-in resolver) depend on their fallback. ICMP from the job (`ping`)
  is dropped too.
- **IPv6 is dropped.** Applications must fall back to IPv4.
- **IPv4 options.** TCP packets with IPv4 options are dropped.
- **No LAN bypass.** Private and LAN destinations follow the session's route
  like any other target: through the gateway on `gateway`, direct from the
  agent on `mixed` unless they match a gateway address.
- **Processes outside the job are not covered**: services, COM servers,
  elevated children started through UAC, WSL 2 and containers, and requests
  handed to an already running process (inference).
- **QoS marking.** The job tag is expected to replace the application's own
  DSCP marking (only a QoS policy was tested). A QoS policy or application
  that uses the same code point outside a job has its packets captured and
  dropped or closed while the helper runs, also when no transparent session
  is open.
- **Administrator approval** once per agent run.
- **Kernel driver.** Antivirus, anti-cheat and endpoint products may flag or
  block WinDivert; coexistence with VPN clients and other WFP callouts is
  unverified. If another product's WinDivert driver is already loaded, the
  helper refuses it unless its version is the pinned one, and the pinned
  digest does not prove which driver binary runs.
- **One helper per machine.** A second agent or Windows user cannot use
  transparent sessions while one helper runs; any local user can block them
  by creating the mutex first.
- **No ARM64**, no Windows before 10 1607.
- **Throughput** is not measured.
- **Residual leak window.** If the helper dies unexpectedly or the stop
  acknowledgment times out, tagged packets can go out directly (with DSCP N
  on the wire) until the agent kills the jobs. A
  candidate hardening is to also set a minimal `MaxBandwidth` on the job:
  if net rate control throttles below the WinDivert NETWORK layer, diverted
  packets would be unaffected and leaked ones throttled. This is a
  hypothesis only.
- **Not an enforcement boundary**, as for every session
  ([security model](../security-model.md#routing-scope)).

## Security

- **Same-user code is not a boundary.** Code of the user can join a
  transparent job or inject into a process in it, and so use the gateway,
  as with `os_user` today. Tagging its own job with N does not help it:
  attribution requires one of the agent's own jobs. It can also kill the
  agent, which closes the sessions, or the job's processes.
- **The elevated helper** runs code from `%LOCALAPPDATA%\Programs\Gateinto`,
  which the user can write. Malware of the user could replace
  `gateinto.exe` and wait for the user to approve the next UAC prompt. It
  could also plant a DLL next to `gateinto.exe` whose name is not a KnownDLL
  (for example `iphlpapi.dll`), which the loader would map into the
  elevated helper without the executable being replaced. Both have the same
  root cause and need the same access. UAC is not a security boundary
  against code of the same administrator, but this design makes such
  prompts routine. `gateinto.exe` is not code-signed yet
  (CONTRIBUTING.md), so the prompt shows an unknown publisher. The linker
  option `/DEPENDENTLOADFLAG:0x800` (search only System32 for load-time
  dependencies) is possible hardening against planting; it is not part of
  this design and not verified.
- **The helper's input from the unelevated side** is its command line,
  validated as above, and nothing else: it reads nothing from the pipe and
  no configuration. `netsh` runs by absolute path with fixed arguments
  apart from the validated port and the helper's own image path.
  Packet headers are parsed with bounds checks (fuzzed, see [Test
  plan](#test-plan)).
- **The pipe** is opened with `SECURITY_IDENTIFICATION`, so the unelevated
  pipe server can query the elevated helper's identity but cannot act as
  it. The agent parses only
  `ready`, a fixed `error` line, and integer counter lines from the helper.
- **A kernel driver** from a third party is loaded with the user's approval.
  A vulnerability in it is a kernel vulnerability. The digest and the version
  check pin one release; updating it is a deliberate change.
- **The non-loopback listener.** Remote hosts are kept out by the engine's
  inbound drop and the firewall. If both failed, a host R connecting from a
  source port p could match the row of a client in a transparent job that
  is connected to R from local port p, and would be attributed to that
  session; the TCP-table lookup is defence in depth for that case, not a
  guarantee. When the helper is not running, the listener is closed.
- **No credentials** cross into the helper; it cannot open tunnels, read
  tunnel content beyond headers, or use the device key.
- **Two users on one machine.** The single helper diverts tagged packets of
  every user. Another user's job with the same tag is attributed to no
  session (different SID, not in any of our jobs) and closed. Any local
  user can deny transparent sessions to everyone by holding the mutex.
- **Documentation changes required** with the implementation:
  - [security model](../security-model.md#exposure-and-logs), which says
    that every session listens on loopback and that no other machine can
    reach a session, gains the transparent listener;
  - [Routing scope](../security-model.md#routing-scope) gains the local DNS,
    IPv6 and UDP limits;
  - `docs/threat-model.md` (the row "The listen address must be loopback")
    and `docs/security-boundaries.md` item 1 ("the listener is
    loopback-only") name the transparent listener;
  - the threat model gains the rows below;
  - `docs/install.md` gains the optional component and the UAC prompt.

Threat-model additions *(to be made with the implementation)*:

| Threat | Mitigation |
| --- | --- |
| A host on the network connects to the listener port. | The engine drops genuine inbound packets to T and the firewall rule is scoped to the port; if both fail, attribution is defence in depth only (a host R using a client's local port p can match). |
| A local process outside the job connects to the listener. | Attribution requires an owner in a live transparent job. A peer with a loopback address or any other address of this host (the listener's own, or another adapter's, found as preferred or deprecated in the host's IPv4 unicast address table without binding anything) is reset before it takes an attribution permit or reads a TCP table, so direct dials from this host cannot exhaust the attributions in flight; only if the address table cannot be read, or if the address is not in use and so cannot be bound, does such a dial take a permit, and attribution then refuses it. Dials from other hosts are the row above. Any other direct dial is refused before any owner is looked at: a loopback peer, or any row (whatever its pid or state) from the peer's address to the listener's, which is the dialer's own socket while it is connected or after it closed with a FIN; a dialer that resets leaves no such row, but its reset also ends the listener's accepted socket, whose row both readings must contain in the state `ESTABLISHED` or `CLOSE_WAIT`. So a process cannot borrow the port of a client in a job (`SO_REUSEADDR`, or the same port on another local address) to take over that client's session and destination; a process in a job that dials the listener is refused the same way. |
| A local process uses a transparent session by tagging its own job with N. | Attribution requires one of the agent's own jobs, so a foreign job is closed; code that joins or injects into the session's job is trusted, as with `os_user`. |
| The helper dies and tagged traffic leaks. | The pipe breaks; the agent marks the engine stopped, refuses new launches and kills every transparent job; the window between is documented. `MaxBandwidth` hardening needs verification. |
| The agent dies and its session processes are still sending. | `KILL_ON_JOB_CLOSE` ends them; the helper keeps dropping for 5 s before it exits. |
| A replaced `gateinto.exe`, a planted DLL or a replaced WinDivert file gains elevation. | Digest check of WinDivert files with the handles held and a driver version check; nothing for `gateinto.exe` or planted DLLs beyond UAC; documented residual risk. |
| The unelevated side misuses the helper to black-hole a port. | The helper accepts only ports 49152 to 65535, DSCP 1 to 63 and the fixed pipe name pattern. |
| A local user blocks transparent sessions. | None; local denial of service through the machine-wide mutex, documented. |
| A link triggers UAC prompts. | No link field selects a transparent session; the IPC mode word is not part of `LaunchRequest`. |
| The engine misparses a hostile packet. | Bounds-checked pure parser, unit and fuzz tests, drops on any malformed input or IPv4 options. |

## Compatibility

Nothing here has been verified on client Windows.

| Category | Expected behaviour | Status |
| --- | --- | --- |
| Windows Server 2022 and 2025, elevated, IPv4, TCP | Routed; untagged traffic direct | Experiment 2, small samples |
| Windows 10 1607 and later, Windows 11 | As on Server | Needs verification |
| Windows before 10 1607, experimental Windows 7 build | Unavailable, `status` says why | Expected by design |
| ARM64 | Unavailable | Expected by design |
| i686 build under WOW64 | x86 DLL with the 64-bit driver | Needs verification |
| curl, git, pip and other programs that honour the proxy variables, in a transparent terminal | Through the session's loopback proxy with host names, as today | Expected, needs verification |
| Java, Node.js, `ssh`, PowerShell 5.1, `winget` in a transparent terminal | TCP routed by IP literal, also from dual-stack IPv6 sockets carrying IPv4 | Needs verification |
| Chrome and Edge in a transparent browser session | Through `--proxy-server` as today; connections that bypass it are routed if the tag reaches processes in Chrome's own nested sandbox jobs | Needs verification |
| QUIC, WebRTC UDP, application UDP DNS | Dropped; application fallback | Needs verification |
| IPv6-preferring applications | Dropped; fallback to IPv4 | Needs verification |
| Gateway policy keyed on host names | Sees IP literals for transparently routed connections | Needs verification against the production gateway |
| VPN clients, antivirus, anti-cheat, other WFP products, another product's WinDivert | Unknown; a foreign WinDivert driver of another version is refused | Needs verification |
| QoS policies using DSCP N | Broken while the helper runs | Expected by design |
| Configuration file with `[transparent]` read by an older Gateinto | Refused (unknown section) | Expected, by `deny_unknown_fields` |
| Older agent receiving `mode=transparent` | `invalid launch request` or `invalid terminal request`; CLI and GUI ask for an agent restart | Expected |

## Test plan

TDD order: each item starts as a failing test. Logs and CI output stay
aggregate (counts, booleans, error codes); no addresses, ports, pids or
paths.

**(a) Packet core, every platform including Linux CI (`cargo test`;
implemented in `src/divert/`):**

- IPv4 and TCP parsing: header lengths, IPv4 and TCP options, total length,
  truncated and inconsistent packets, fragments (MF or offset), non-TCP
  protocols; IPv6 detection.
- Rewrite: outbound tagged SYN to the reflected form (addresses, ports,
  DSCP cleared, ECN kept), reply to the restored form, with full checksums
  checked by an independent verifier, including packets with zeroed or
  partial checksums; packets with IPv4 options dropped unchanged in both
  directions.
- Flow table: creation by pure SYN, retransmit, replacement on a new
  sequence number or after the flow ended, key collision, orphan, reply
  without a flow, end on RST, end on FIN in both directions, linger, idle
  expiry, capacity, the full-table sweep at most once per second.
- Drop classification for every reason, with counters.
- `divert::filter` for N = 1, 43 and 63 and a few ports.
- A cargo-fuzz target `divert-engine` over `Engine::process`, using the
  checker in `divert::fuzzing`.

Implemented with step 4 (`src/proxy/os_user.rs`,
`src/transparent/listener.rs`): `os_user::original` with exactly one row, no
row, two rows, pid 0, a `TIME_WAIT` row of another owner next to the
client's row, a wrong local address or port, mapped rows (`::ffff:L:p` to
`::ffff:R`) found in the IPv6 table, the same socket listed in both tables,
an owner that could not be inspected or is in two sessions' jobs next to an
admitted row (in both row orders), the first refusal as the denial, a
process in a job that dials the listener, a direct dial from a port shared
with an in-job client, from the same port on a second local address and
from a closed dialer row with pid 0, a dialer row in any state, a dialer
that reset (neither its row nor the listener's left, only the in-job row),
a listener row with pid 0, a listener row that counts only in
`ESTABLISHED` or `CLOSE_WAIT`, the owner of a proxied connection found
whatever the state of its row, a loopback peer, a reflected
connection to a remote port equal to T that is still accepted, and ports 0,
1 and 65535; the session of exactly one job; reading both tables; the
second reading and the retries under a deadline; the listener's port choice
with a fake binder (an ephemeral port in range kept, one outside closed
before the explicit draws, ports in use or excluded skipped, the attempt
limit, other errors).

Also implemented with step 4, on every platform with fake jobs and a fake
attribution:

- the engine state (`src/transparent/state.rs`): concurrent requests share
  one start and its success or failure, and the next start is a new
  generation; the joiners of a start are counted (`State::joiners`, for
  tests) so that tests can wait for them instead of sleeping; a joiner gets
  the outcome of the generation it joined, never a later one; a helper that
  stops after `ready` but before the hand-over leaves the engine `stopped`,
  fails the hand-over and refuses registration; a stale start's hand-over,
  failure path or abandonment neither completes nor clears a newer start; an
  abandoned start stops the engine and fails its joiners; only an
  abandoned start calls its `on_abandon` hook, and before the engine counts
  as stopped; registration succeeds only under `running(g)` and once per
  key; a break terminates every session of its generation and marks it
  `closing`, and a late or repeated break changes nothing, so a newer
  generation keeps running, keeps its sessions and still accepts
  registrations; a failed terminate is logged
  and the other jobs are still terminated; a terminate that panics is logged
  and every session is still marked `closing`, terminated and returned;
  unregistered sessions leave the snapshot; a launch that holds the mark
  before the break is terminated by it (the fake job records the spawn
  before the terminate) and one after it sees `closing`; and the break
  releases the engine lock before it terminates a job (a registration from
  another thread during the terminate completes and is refused); the
  snapshot and the adoption see only the sessions of the given generation; a
  full session hands the stream back; and no stream is adopted once
  `unregister` or a break has taken the session, also from within the
  break's terminate, while one adopted before it stays in the session's
  channel. Because the adoption looks the session up and sends under the
  state lock, those two orders are the only ones, so there is no
  interleaving left for a test to provoke;
- the dispatch loop (`src/transparent/serve.rs`), with real loopback
  sockets: only a remote peer other than the local address is reflectable
  (loopback, IPv4-mapped loopback and the local address refused); the
  listener resets a loopback peer without attributing it and logs only
  `self-target`; 65 such peers in a row take no permit and reach no
  attribution, and a genuine stream after them is still attributed and
  adopted (the loop tests other than the real `serve` one take a peer
  check that lets loopback through, since a loopback test client cannot
  have a non-loopback address on every platform); a peer with another
  address of this host, also IPv4-mapped, is not reflectable, and only
  such an address, no documentation address, is of this host; the real
  listener resets a client bound to such an address without attributing
  it and logs only `self-target` (Linux only, where a client bound to a
  non-loopback address can dial a loopback listener); the address table
  matches a peer by its IPv4 address, also IPv4-mapped, never an IPv6
  peer, and only a preferred or deprecated address, not a tentative,
  duplicate or invalid one; a listener of an older generation dispatches
  into no session of a newer one, whose snapshot it does not see, while
  the newer generation's listener does; an attributed stream reaches its
  session's adopter with its destination as an IP-literal `Authority`,
  and the attribution sees the peer, the local address and the snapshot;
  a denial, a timeout and a panicking attribution each reset the stream
  within the timeout and reach no session; a session that unregistered
  during the attribution resets the stream; a full and a closed adopter
  hand the stream back and it is reset; beyond 64 attributions in flight a
  stream is reset at once without an attribution; shutdown ends the loop,
  closes the listener, resets the stream of an attribution in flight and
  discards its result; refusals are logged at `debug` by kind, with no
  address, port, pid or denial detail in any line. The tests that need
  another address of this host take the one of its IPv4 default route,
  found by connecting a UDP socket to a documentation address, which sends
  nothing, so they fail on a host without an IPv4 default route;
- the configuration (`src/config.rs`): `[transparent] dscp` accepts 1 to 63,
  also as the dotted key `transparent.dscp` or an inline table, and is 43
  without the key or the section; 0, 64, -1, 256, integers outside the i64
  range up to 128 bits (`invalid value` like the others), a string, a float,
  an unknown key and a `transparent` that is not a table (an integer, an
  empty array, `[10]` and `[10, 11]`) are refused with an error whose
  message line starts with `[transparent]` and names the key at fault; and
  the agent takes the value into `AgentOptions::dscp` (`agent_options` in
  `src/main.rs`).

**(b) Windows unit tests:**

- `Job::set_dscp_tag` sets 43 and reads it back, keeps
  `KILL_ON_JOB_CLOSE`, and the last tag set wins (implemented, run only on
  Windows CI); values outside 1 to 63 are refused by `Dscp`.
- The agent's own-job check.
- Attribution (`src/proxy/os_user/windows.rs`, implemented, unelevated,
  type-checked from Linux only), with a child process in a job connected to
  a server on the host's own non-loopback address: an IPv4 and a dual-stack
  client attributed to the right one of two sessions with its pid and
  destination; a client in no given session's job and an owner outside
  every job refused (`NotInJob`); a client that dials the listener address
  refused; a process outside the job that binds the client's port with
  `SO_REUSEADDR` and dials the reserved listener refused, and not found
  once it has reset the connection; no row and a passed deadline; the
  tables' `dwState` values mapped to `TcpState`. Without
  the engine no socket of the listener is connected to the peer, so the
  cases that expect an attribution or a job refusal add the row that
  reflection would give the listener's accepted socket to the real tables.
  These tests listen on the host's non-loopback address, so on a desktop
  they may make Windows Defender Firewall ask whether to allow the test
  executable; CI is unaffected.
- The host's address table (`src/transparent/serve/windows.rs`,
  implemented, type-checked from Linux only): it holds the address of the
  host's IPv4 default route as preferred or deprecated and no
  documentation address; like the dispatch tests above, it needs an IPv4
  default route.
- The listener socket (`src/transparent/listener/windows.rs`, implemented,
  type-checked from Linux only): a reserved port in range with
  `SO_EXCLUSIVEADDRUSE` read back, other binds of the port refused (also
  with `SO_REUSEADDR`), and connections refused before `listen` and
  accepted after it.

**Agent tests (all platforms, fake `Launcher` and a fake helper seam;
those implemented with step 5 are listed after this list):**

- order of operations: no job is created before `ready`, no process before
  the tag is read back; each failure starts nothing and leaves no session;
- the helper's first line: `ready` starts the engine, each `error <code>`
  becomes its message, an exit before the first line becomes a generic
  message with the exit code, a second status line or a malformed counter
  line is treated as a broken pipe;
- a helper that writes `error <code>` and exits at once is reported with
  its code, not as a generic exit: the agent drains the pipe when the
  process handle signals;
- the helper stops between `ready` and registration: registration fails, the
  session is closed and no process is launched;
- the pipe breaks while a terminal launch holds `terminals` and waits to
  register: the handler completes without deadlock, registration fails, and
  the launch closes its session and starts nothing;
- concurrent requests while the engine is `starting(g)` raise one helper
  start and share the outcome of generation `g`; a request waits for a
  previous helper still in its grace period and fails with a clear error
  when it does not end in time;
- waiting for the helper blocks no other launch and no close;
- the helper dies right after `ready`, before the start moves `starting(g)`
  to `running(g)`: the state stays `stopped`, the request fails, and no
  process is launched;
- helper A dies after `ready`, request B begins a new start
  (`starting(g+1)`) and waits on A's process handle, then A's hand-over
  runs: it fails without making B's start `running` or clearing it, and no
  process is launched for A's request; B's start completes on its own
  outcome;
- a late break from an older helper (and a second break from the same
  helper, pipe break then process exit) changes nothing: the newer
  generation stays `running`, its sessions stay open and registration
  under it still succeeds;
- each pre-check (rate limit, platform, capacity, gateway, a browser request
  that would need a confirmation) refuses without starting a helper;
- a transparent browser launch builds its plan twice, in the pre-check and
  in `Agent::start`, and a transparent terminal twice, in the pre-check and
  in `Agent::terminal`; a proxy-mode launch of either builds it once, and
  every build runs off the async worker;
- every read of the known gateways (both launch modes, terminals and
  approvals), the store of an approved gateway and every attempt to delete
  a browser profile run off the async worker, and the profile deletion
  still pauses between attempts;
- a rate-limited transparent request is refused by the pre-check with the
  existing rate-limit error and raises no helper start; the pre-check
  consumes no slot, so a request it lets through is counted once, under
  `launching`;
- a launch after the pipe-break handler ran sees `closing` and starts
  nothing; a launch that finished before the handler is killed by it;
- no fallback to proxy mode and, for browsers, no fallback without a job;
- pipe break closes every transparent session and the listener, and leaves
  proxy-mode sessions open;
- the helper is started once per agent run, and the 60 s start timeout
  runs from `ShellExecuteExW` returning;
- the listener port is in 49152 to 65535;
- the session still gets its proxy settings (`--proxy-server`, proxy
  variables);
- an adopted stream takes a permit from the session's tunnel limit and is
  closed without one; closing the session aborts adopted tunnels; a
  challenge stores the verification offer and closes the stream; adopted
  tunnels log the target like proxy-mode tunnels and never the peer.

Implemented with step 5 in the agent (`src/agent/tests/transparent.rs`,
Unix only, like the inline `#[cfg(unix)]` modules `no_job_retry` and
`terminal_sessions` in `src/agent.rs`: the fakes use `Job::fake`, which
exists only outside Windows because the Windows `Job` is a real job object,
spawn `/bin/sleep` through `browser::spawn`, and give an absolute Unix
`USERPROFILE`; on Windows the job and `os_user` paths behind them are real.
The tests wait on what they can observe (the helper start, the joiners of a
start, the listener's serve), never on a sleep. With a fake `Launcher`, a
fake `Engine` whose helper is started, gated, failed or stopped by the test
and whose listener records when it serves and when it is shut down, and fake
jobs): a transparent terminal and a transparent browser start the helper
with the configured DSCP, then create the job, then tag it, and only then
spawn, are registered under the running generation with a live adopter, keep
their proxy settings (`--proxy-server`, the proxy variables) and are listed
with `transparent`; proxy-mode sessions start no helper, set no tag and are
not listed as transparent; each helper failure (an error code, a declined
prompt, a timeout, the previous helper still running, an exit) is answered
with its message, recorded as the last error and starts nothing; a helper
whose pipe has broken by the hand-over fails the start with its message
and no listener is served; a tag that cannot be set starts no session and
registers nothing; a transparent browser without a job starts nothing; a
failed spawn (job refused or process error) closes and unregisters its
session and is not retried in proxy mode or without a job; a helper that
stops while a launch waits before registration (inside the tag, while a
terminal launch holds `terminals`) stops the engine and its listener
without waiting for the launch, and the launch is then refused and starts
nothing; a launch that holds the mark when the helper stops spawns, and its
session is then closed; the spawn guard refuses under a closing mark; two
terminals and a browser waiting for one start share it, and two requests
share its failure, with one helper start; waiting for the helper blocks no
proxy-mode launch and no close; the rate limit, an unsupported platform,
unavailable transparent sessions (with the reason), full capacity, an
unknown gateway, a browser request that needs a confirmation (the mixed
route on a gateway saved with the gateway route, a new gateway), a browser
plan that fails, a missing browser and a missing or relative `USERPROFILE`
for a terminal are each refused before any helper start, and a refused
confirmation never becomes the pending one; after the start, a gateway
forgotten while the helper starts refuses a browser launch and a terminal
plan that no longer builds (here, a CA file that can no longer be read)
refuses a terminal launch, each with no session and nothing spawned, and
the helper keeps running; the
pre-check takes no rate-limit slot; a helper that stops closes every
transparent session of its generation and shuts down its listener, leaves
proxy-mode sessions open and records the cause; a stop whose blocking task
did not finish closes every transparent session, whatever its generation,
and no proxy-mode session; and the helper is started once while it runs and
again, as a new generation, after it stopped. Not covered at the agent
level: the 60 s timeout from `ShellExecuteExW` returning and the waits for a
previous helper (tested in `src/transparent/helper.rs`), and the listener
port range (tested in `src/transparent/listener.rs`).

Implemented with step 5 for the status: the `transparent` answer follows the
engine from stopped through starting (a gated start) to running and to
stopped with the helper's message, names why the last start failed (a
failed start, a helper gone by the hand-over, a start abandoned because its
request was cancelled) and no longer names it after a successful start; the
stop-watcher stores the helper's message before the engine counts as
stopped, even while a launch holds `launching`; the availability check runs
on a blocking thread, its reason is answered with the engine stopped, and a
check that panics is answered as an error and starts nothing
(`src/agent/tests/transparent.rs`).
In `src/ipc.rs`: the request round-trips and its malformed forms are
refused; the status round-trips as its lines, is read in any order with
unknown keys skipped, and a line without `: `, a missing or repeated key, an
unknown or empty value is refused; an `invalid request`, which an agent
answers to a request it does not know (checked against the parser and the
encoding), is read as too old. In `src/main.rs`, the `transparent-engine`
line for each phase, an older agent, a malformed answer, an agent error and a
failed request; in `src/session_table.rs` and `src/main.rs`, the
` (transparent)` marking. `tests/cli.rs` and `tests/launch.rs` through the
binary: `transparent-sessions: unavailable: transparent sessions need
Windows` without an agent and no engine line, and `transparent-engine:
stopped` from a running agent. The fuzz target `ipc-line` checks that an
accepted status re-encodes to itself, with seeds for the request and two
answers. The demo GUI agent answers available with the engine running.

Implemented with step 5 for the GUI (`gui/src`): the worker asks
`transparent` on each poll only while the agent runs, a failed or refused
request leaves the gateways, sessions and config of the refresh intact,
transparent launch and terminal commands send `mode=transparent`, links
send proxy-mode launches even while transparent sessions are available,
and only a transparent request refused as sent to an older agent is named
too old; with a paused clock and an agent that never answers a
transparent launch, the polls go on every 2 s, a Close sent meanwhile
reaches the agent, a link shows its prompt, a second launch waits until the
first is answered, the answer brings its failure and the launch count in
the next update, and closing the window drops the pending launch and those
queued behind it (`worker.rs`); the choice is offered only for
`available`, never for `unavailable`, an error, an older agent or no
agent, and only a gateway card starts in the chosen mode, the tray, the
Sessions picker and a link always in proxy mode (`agent.rs`
`Transparent::start`); the choice sits under the full-width subtitle at
the left of the Add gateway row, is worded in both languages, maps to its
mode for the pointer and is its own focus group, and at the minimum window
the subtitle fits the approval notice and the older-agent message while the
choice is shown, in both languages (`board/gateways.rs`, `pointer.rs`,
`focus.rs`);
a pending transparent start shows the approval notice (`gateways.rs`
`Launches::notice`); the Transparent tooltip says that IPv4 TCP follows
the gateway's route, that UDP and IPv6 are blocked and that the engine
may ask for administrator approval, and does not claim every connection
(`board.rs`); a transparent session is marked and a proxy one is not
(`sessions.rs`, `board.rs`); the engine row in each state
(`settings.rs`, `board/settings.rs`); every new text exists in English and
Traditional Chinese (`i18n.rs`); and the demo offers the choice with the
engine running, refuses transparent starts like proxy ones and shows one
transparent terminal session (`demo.rs`).

Implemented with step 5 for the CLI: in `src/ipc.rs`, only transparent
launch and terminal requests choose the 300 s limit, a timeout names the
limit that was waited, and only a transparent request refused with exactly
the parser's `invalid launch request` or `invalid terminal request` (the
constants the parser uses) counts as sent to an older agent;
`tests/agent.rs` checks with a paused clock that a hung agent is waited on
60 s for a proxy-mode terminal request and 300 s for a transparent one. In
`src/main.rs`: the terminal flag sends `mode=transparent` only with
`--agent` and is refused by clap without it; `open --transparent` asks for
the transparent mode, is not handed to the GUI, and waits the 300 s on an
agent it has just started, checked through the start loop with a fake
agent process and a paused clock; the answer is marked after its
`session:` line, or first when it has none, and an older agent is named
for launches and terminals, and proxy-mode answers are unchanged.
`tests/cli.rs`, against a fake agent that holds its answer until the
notice is on the client's standard error, so the notice must come before
the request: the request lines, the notice before the too-old message for
both commands, the marked terminal answer, a proxy-mode terminal that
keeps `invalid terminal request`, and, with a fake GUI named by the
`test-hooks` variable `GATEINTO_TEST_GUI`, a proxy-mode `open` handed to
the GUI and a transparent one sent to the agent instead.
`tests/launch.rs`, against a real agent outside Windows: `open
--transparent` starts the agent and is refused as unavailable, and
`session terminal --agent --transparent` is refused as unsupported on this
platform, each after the notice.

Implemented with step 5 (`src/transparent/helper.rs`,
`src/transparent/availability.rs`), on every platform with a fake platform
and paused time: `ready` returns a running handle and the helper got
`divert --pipe <name> --agent-pid <own pid> --port T --dscp N` with the name
of the pipe that was created, a new random name per start; each `error
<code>` becomes its message; counters, an unknown line, an empty line, a
second status line, a line after `error` and a line cut off by the end of
the pipe before the first status fail as protocol errors; an exit before
connecting is reported with its exit code (3, 4, 5, 0 and others) one drain
period later; an `error` line followed by an immediate exit is drained and
reported with its code, and a `ready` found by the drain still fails with
the exit code; a pipe closed without a line is reported with the exit code
once the process ends, or as a timeout; the timeout counts from the launch
returning (a 30 s prompt plus 60 s); a declined prompt and another launch
error; a pipe that cannot be created starts nothing; a client with another
pid fails the start and finds the pipe closed; after `ready`, counters keep
it running, a broken pipe, a protocol error (a second status line, an
`error` line, an invalid counter line, an unfinished line) or the exit end
the run with the reason; dropping the handle closes the pipe; counter lines
are logged at `debug` with every field and no pipe name, pid or port; the
next start waits for the previous helper, also after a failed start, and
fails after 25 s when it does not end, without creating a pipe; a helper
whose run has ended is not waited for. The availability check over a fake
probe: supported versions with the pinned files, older versions and an
unknown version probe nothing else, ARM64 before any file, a missing or
refused file named before any digest, the first file that differs or cannot
be read named, and "not Windows" off Windows; files whose stamps are
unchanged since they matched are not hashed again (an unreadable file still
counts), a change of any stamp field, a file without a stamp and a mismatch
make the next check hash again, and a cached match still needs a supported
version, no ARM64 and every file present.

**Agent side of the helper on Windows** (`src/transparent/helper/windows.rs`,
`src/transparent/availability/windows.rs`, unelevated; type-checked from
Linux only): the pipe's DACL read back holds exactly the user and
`BA`; a client of the same user connects, its pid is read and its line
arrives; one instance, a second client gets `ERROR_PIPE_BUSY`; a second
server of the same name cannot be created; the options are duplex,
first-instance and reject remote clients; the server handle is not
inheritable; the pid and exit code of a process handle; the version from
`RtlGetVersion`, not ARM64 on the runners, the WinDivert files missing
beside the test executable, and a file's stamp, equal for two opens of the
file, different for another file, and with the same volume and index but a
new size after a rewrite. `ShellExecuteExW` is not called by unit tests,
since it would raise a UAC prompt on a desktop; it is left for the
integration test.

**Helper tests on Windows** (`src/divert/windows.rs`, unelevated, without
WinDivert; type-checked from Linux only): a missing file, a digest mismatch,
held files that can be read but not written, renamed or deleted, and a
directory of held files and its parent that cannot be renamed; a library that
is not WinDivert refused with its Win32 error; the mutex held by a second
lock; the pipe refused when another process serves it, lines written to the
agent, and the liveness wait ending on a closed pipe, on a byte from the agent
and on the end of the agent process; `netsh` taken from the system directory;
a command killed after its timeout; the subcommand's raw arguments and its
absence from the help. Opening WinDivert itself needs elevation and is left
for the integration test.

**Helper tests** (implemented in `src/divert/`, every platform):
argument validation (DSCP 0 and 64, port 49151 and 0 are refused with
`invalid-arguments`; a pipe name outside the pattern ends the helper with
an exit code and nothing on any pipe); the `netsh` command lines; the
protocol lines it writes and the agent-side reader, with a fuzz target
`divert-status`; the engine loop with a fake port and a manual clock; the
order of the helper sequence and its cleanup with a recording fake
platform.

**(c) Windows CI integration (elevated hosted runner, proposed
`tests/transparent_windows.rs`, serialized):** a workflow setup step
downloads the pinned WinDivert release and verifies it by SHA-256 before
the tests run; no test downloads anything. No internet: the client in a
tagged job dials a TEST-NET-1 address (`192.0.2.0/24`, RFC 5737), so the
SYN never leaves the machine when the engine reflects it, and the
in-process TLS upstream fixture on loopback serves `CONNECT 192.0.2.1:443`.
The session uses the `gateway` route: on `mixed`, `routing::attempt` would
dial 192.0.2.1 directly. `UpstreamProxy` records request heads
(`requests()`), and `Behavior::TunnelTo` tunnels to a loopback echo server
whatever the target. Cases:

- routed: the fixture records exactly one `CONNECT 192.0.2.1:443` and data
  round-trips;
- an untagged process is not routed: the fixture records no `CONNECT`; its
  SYN goes to the documentation address unanswered and contacts no service;
- a connection made directly to the listener port is closed and reaches no
  upstream;
- a foreign owner (a process in a job tagged with N that is not a session's
  job) is closed;
- stopping the helper closes the session, kills its job and removes the
  firewall rule (checked with `netsh`'s exit code);
- the helper ends within 20 s of the agent ending with no traffic on the
  handle (grace period 5 s, shutdown deadline 5 s, `netsh` up to 10 s), and
  the test records how: exit code 0 when `WinDivertShutdown` woke the
  blocked receive, 5 when the shutdown watchdog ended it; the firewall rule
  is gone either way;
- tagged UDP is contained (engine counter equals datagrams sent);
- a large upload through the transparent path (large send offload).

**(d) Type-check only from Linux:** the Windows-only code (job tag, helper,
WinDivert binding, firewall, `ShellExecuteExW`) with the recipe in
[compatibility.md](../compatibility.md#windows-type-check-from-linux), which
links and runs nothing.

**Manual checklist (Windows 10 and 11, results go to
`docs/verification.md`):** an unelevated agent with a UAC prompt (same and
different administrator account, agent with and without a foreground
window), Chrome and Edge in a transparent browser, `ssh`, `git`, Java and
`winget` in a transparent terminal, IPv6-capable networks, a VPN client,
Defender with "block all incoming connections", the helper killed while
tunnels are open, the agent killed while tunnels are open.

## Decisions

1. **Scope.** Windows 10 1607 / Server 2016 or later, x86 and x64; opt-in
   per agent browser or terminal session; proxy-mode sessions unchanged.
2. **Mark.** One DSCP for all transparent sessions, default 43,
   configurable 1 to 63, set on the job and read back; failure is reported.
3. **Engine.** A separate elevated `gateinto divert` helper started on
   demand through UAC, one WinDivert NETWORK-layer handle with a static
   filter, packet reflection only, no plaintext, credentials or key; IPv4
   options dropped.
4. **Listener.** One agent-level listener on `0.0.0.0:T`, a type separate
   from `proxy::Proxy`; attribution and the original destination come from
   one lookup in both TCP tables with `IsProcessInJob`; the stream is
   adopted by the session's proxy.
5. **Target naming.** `CONNECT <IP literal>:<port>`; SNI later.
6. **Fail closed.** Helper ready, listener, tag, registration, processes; a
   liveness pipe; one engine state (`stopped`, `starting(g)`, `running(g)`,
   with a generation per start) and a per-session open/closing mark under
   locks that are innermost in the agent's lock order; every transition
   checks its own generation; the helper is ensured before any existing
   lock is taken; a pipe break closes every transparent session of its
   generation; no downgrade to proxy
   mode; the residual window is documented.
7. **WinDivert distribution.** Optional MSI feature (`TRANSPARENT=1`),
   loaded at runtime by the helper only, pinned version, SHA-256 digests
   checked through held handles, driver version checked after opening.
8. **Firewall.** One fixed-name inbound rule for the helper's lifetime,
   added and removed with `netsh advfirewall firewall` by absolute path,
   exit code only; the cleanup delete ignores its exit code; `INetFwPolicy2`
   as the alternative; protection rests on the engine and attribution.
9. **Known limits** as listed in [Limits of the first
   version](#limits-of-the-first-version).
10. **Tests** as in the [Test plan](#test-plan).
11. **Order of work** as in the [Implementation plan](#implementation-plan).
12. **Proxy settings are kept.** A transparent browser still gets
    `--proxy-server` and a transparent terminal the proxy variables;
    transparent routing is the catch-all for what ignores them.
13. **Logging.** Proxy-mode logging is unchanged; adopted tunnels log the
    target as proxy-mode tunnels do and never the peer; helper and engine
    output is aggregate.
14. **Helper reporting.** The helper connects to the pipe first, with
    `SECURITY_IDENTIFICATION`, and sends exactly one status line, `ready` or
    `error <code>` from a fixed list. After `ready` it sends counter lines and
    can end with `stopping`. Anything else
    is a broken pipe; a helper that ends earlier is reported with its exit
    code from the `ShellExecuteExW` process handle.
15. **Helper lifetime.** Until the agent stops: one approval per agent run.
    After the agent's death or a pipe break it keeps dropping for 5 s.
16. **Configuration.** `[transparent] dscp` in the configuration file.
17. **Values.** Flow linger 120 s, 16384 flows, idle backstop 2 h 4 min,
    full-table sweep at most once per second, helper start timeout 60 s from
    `ShellExecuteExW` returning, grace period 5 s, listener port 49152 to
    65535.
18. **Refinements.** Bind first with `SO_EXCLUSIVEADDRUSE` and listen only
    after `ready` and the firewall rule; `Proxy::adopter` and
    `Shared::adopt`; `os_user::original` matching the accepted socket's
    local address in both tables; no job-less browser fallback; the
    transparent mode is an IPC field a link cannot set; one helper per
    machine (`Global\Gateinto-divert`); the agent's own-job check as a
    best-effort diagnostic; the helper validates its arguments.

## Alternatives rejected

Based only on what the experiments on `claude/dreamy-cerf-2f0b4c`
evaluated.

- **Per-application attribution at the first packet**
  (`experiments/wfp-divert`): hold each new flow's first packet at the
  NETWORK layer and identify the application from native WFP net events or
  WinDivert SOCKET events before releasing or translating it. Its restricted
  same-host cases passed in part, but recorded runs also had failing cases
  (short cases in one comparison, a burst round with conflicting
  application candidates in another), its native WFP and Security 5156
  variant needs connection audits and WFP event collection enabled
  system-wide (the SOCKET variant used them only to validate the
  experiment), it rejects reused tuples, and it
  adds a hold before every first packet. The job tag marks the first packet
  itself, so no hold and no event correlation are needed.
- **A different code point per session** (DSCP 10 and 20 in experiment 2):
  it would spend the 63 code points and every value would need an exact
  filter of its own. Experiment 2's `shared-dscp` case attributed two
  sessions sharing one code point correctly by the owner lookup at accept
  time, so one shared value is enough.
- **The "any non-zero DSCP" filter** (`ip.TOS >= 4`, used in
  `https-external` and `load`): it would divert every packet any QoS policy
  marks. The exact-match filter ignored a DSCP 46 policy in `qos-policy`.

## Implementation plan

Each step is one small pull request, test first: a failing test, the minimal
code to pass it, then a refactor.

1. **Job DSCP tag with read-back.** `Dscp`, `Job::set_dscp_tag`
   (implemented; type-checked from Linux only), the own-job check.
2. **Platform-independent packet core.** Parsing, rewrite, checksums, flow
   table, drop counters, `divert::filter` (implemented), the fuzz target
   `divert-engine`.
3. **WinDivert runtime binding, engine loop, `divert` helper subcommand,
   liveness pipe and firewall rule** (implemented; the Windows part
   type-checked from Linux only). Argument validation, the pipe protocol
   with `SECURITY_IDENTIFICATION`, digest check with held handles,
   `LoadLibraryExW`, `WinDivertOpen`, the driver version check, the
   machine-wide mutex, the grace period, counters on the pipe, and the
   `netsh` command lines with the delete, add and final delete of the rule.
   The new imports (`CreateEventW`, `CreateMutexW`,
   `GetNamedPipeServerProcessId`, `WaitForMultipleObjects`) are in the
   Windows 7 import allow-list.
4. **Session adoption and the transparent listener** (implemented as parts
   that the agent wiring of step 5 uses; the Windows parts type-checked
   from Linux only).
   `Proxy::adopter`, `Shared::adopt`, `Adopter` and `proxy::reset`;
   `os_user::original`, which also requires the listener's own row, and
   its Windows lookup `Attribution`; the listener socket with
   `SO_EXCLUSIVEADDRUSE` and the port range (`transparent::listener`); the
   engine state with its generations, the registry of transparent sessions
   and the session marks (`transparent::state`); and the listener's
   dispatch loop with its in-flight bound (`transparent::serve`).
5. **Agent wiring** (implemented; the Windows parts type-checked from
   Linux only). On-demand helper with
   `ShellExecuteExW`, the order of operations, fail-closed handling,
   `[transparent]`, the CLI flags, the IPC mode, the GUI option,
   `SessionInfo::transparent` and the `status` lines; `Win32_UI_Shell` in
   `Cargo.toml` and `shell32.dll` in the Windows 7 import allow-list.
   Implemented so far: the agent side of the helper
   (`transparent::helper`: the previous-helper wait, the pipe with its DACL,
   the launch, the first status line with the pid check, the drain and the
   timeouts, and the running handle that reports how the helper stopped),
   the availability check (`transparent::availability`), with
   `Win32_UI_Shell` and the new imports in the allow-list, the IPC mode,
   `SessionInfo::transparent` and the agent wiring (the order of
   operations, the engine seam and its Windows implementation, the
   stop-watcher and fail-closed handling), `[transparent] dscp`, the IPC
   `transparent` request, the `status` lines, the `session list` marking
   and the CLI flags (`session terminal --agent --transparent`, `open
   --transparent`), and the GUI's mode choice, approval notice, too-old
   message, marking of transparent sessions and engine row in Settings.
6. **Packaging and user documentation**, in two parts:
   - 6a. **Packaging** (implemented; not built or installed on Windows).
     The optional MSI feature with the WinDivert files and license, the
     release workflow's download and checks, `build.ps1 -WinDivert`, the
     manifest tests, the availability cache, and the install page.
   - 6b. **Security and compatibility pages.** The security model, threat
     model, security boundaries and compatibility pages.
7. **Windows CI integration test** on an elevated runner.

## Needs verification

Each item is a premise the design relies on that has not been checked.
Where the design has a fallback it is named; the items marked "no fallback"
would need a design change if they fail. Results go to
`docs/verification.md`.

- An unelevated process can set the job's net rate control tag (CI runners
  are elevated). No fallback: if it cannot, the helper would have to tag
  jobs, which this document does not cover.
- Behaviour on Windows 10 and 11 client editions, including Home. No
  fallback.
- WinDivert does not re-divert a handle's own injected packets to that same
  handle, which the inbound-drop clause relies on. No fallback.
- Injected inbound packets pass Windows Firewall with the scoped rule, also
  with "block all incoming connections" and on public networks; the
  fallback for the rule itself is `INetFwPolicy2`.
- The exact `netsh advfirewall firewall add rule` and `delete rule` syntax
  and exit codes, including that `delete rule` exits non-zero when nothing
  matches.
- Listening only after the rule exists avoids the firewall's "allow this
  app" prompt.
- A reset accepted socket leaves `ESTABLISHED` (its row disappears, or is
  listed in another state such as `CLOSED`), so that the listener-row rule
  refuses a dialer that resets. The Windows unit test
  `a_process_outside_the_job_that_dials_from_a_client_port_and_resets_is_not_found`
  is that check; it has not run yet.
- TCP-table rows are visible at accept time and taking the original
  destination from them is reliable;
  fallback: a per-flow message from the helper.
- Dual-stack IPv6 sockets carrying IPv4 appear in the IPv6 table with
  IPv4-mapped addresses at accept time.
- The production gateway accepts `CONNECT` to IP literals under its policy.
  Fallback: SNI, a later step.
- Browsers' built-in DNS and QUIC fall back when tagged UDP is dropped.
- Nested jobs: that only one job in a hierarchy can hold net rate control
  and the call fails otherwise; whether the tag reaches processes in nested
  jobs (Chrome's sandbox puts its processes in their own jobs; a terminal
  may already run in a job, for example Windows Terminal or a CI agent).
- An application-set DSCP inside a tagged job is replaced by the job tag.
- The `MaxBandwidth` kill-switch hypothesis.
- Coexistence with VPN clients, antivirus, anti-cheat and other WFP
  products; driver loading with HVCI, Smart App Control and the vulnerable
  driver blocklist; behaviour when another product's WinDivert driver is
  loaded, and that `WinDivertGetParam` reports its version.
- IPv6 drop falls back to IPv4 promptly; otherwise a RST reply to tagged
  IPv6 SYNs.
- Under large send offload, whether an outbound packet captured at the
  NETWORK layer has an IPv4 total length equal to the captured length (the
  helper injects the captured length).
- The i686 build under WOW64 with the x86 `WinDivert.dll` and the 64-bit
  driver.
- The pipe DACL when UAC is answered with a different administrator
  account.
- The unelevated agent can wait on and query the exit code of the elevated
  child's process handle returned by `ShellExecuteExW`.
- Whether `ShellExecuteExW` with `runas` blocks until the user answers the
  prompt (the 60 s timeout from its return depends on it, and so does the
  client's 300 s limit, which leaves more than three minutes for the
  prompt), and whether a
  prompt raised by a background agent without a foreground window only
  flashes in the taskbar.
- `ShellExecuteExW` with `runas` for an executable works without
  `CoInitializeEx` on the calling thread, a Tokio blocking-pool thread with
  `SEE_MASK_NOASYNC`. The documentation asks callers to initialize COM
  because shell extensions may run; none is expected for an executable.
  Fallback: run the call on a thread of its own after
  `CoInitializeEx(COINIT_APARTMENTTHREADED)`, which adds `ole32.dll`
  (present on Windows 7) to the imports.
- `ShellExecuteExW` accepts the image path `std::env::current_exe` returns
  when the agent was started through a `\\?\` path.
- The consent prompt still appears with `SEE_MASK_FLAG_NO_UI`, which is
  meant to suppress only the shell's own error dialogs; if it does not, the
  flag is dropped.
- `IsWow64Process2` reports `IMAGE_FILE_MACHINE_ARM64` as the native machine
  for the x64 build under emulation on ARM64, as it does for the x86 build
  under WOW64; otherwise the x64 build under emulation is reported as
  available and fails when the helper loads the driver.
- Holding the WinDivert files open without write or delete sharing prevents
  replacing them (and renaming their directory or any ancestor of it) until
  the driver and the DLL are loaded, and still lets `LoadLibraryExW` and the
  driver load open them (unit tests for the first part exist and have not
  run on Windows).
- `WinDivertShutdown` wakes a `WinDivertRecv` that is already blocked on a
  handle with no traffic. If it does not, the helper still ends, through
  the shutdown watchdog, up to 5 s later and with exit code 5 instead of 0.
- The 32-bit build starts the `netsh.exe` that `GetSystemDirectoryW` names,
  `C:\Windows\System32`; under WOW64 the file system redirector runs
  `C:\Windows\SysWOW64\netsh.exe` instead. The rules live in the firewall
  service, not in the process, so the 32-bit `netsh` is expected to manage
  them and `Sysnative` should not be needed. If its `advfirewall` context
  fails, the helper would start `%windir%\Sysnative\netsh.exe` when
  `IsWow64Process` says it runs under WOW64.
- A firewall rule whose program is a `\\?\X:\` path matches the running
  image; the image path comes from `GetModuleFileNameW`, which returns that
  form when the helper was started through it.
- `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` accepts the image
  directory when the helper was started through a `\\?\` path.
- That 120 s of linger is enough for late segments, compared with the
  Windows `TIME_WAIT` default.
- Every row of the [compatibility table](#compatibility).
