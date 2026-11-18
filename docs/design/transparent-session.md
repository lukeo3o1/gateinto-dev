# Design: transparent sessions on Windows

Status: design decided; steps 1 and 2 of the [Implementation
plan](#implementation-plan) are implemented (`Job::set_dscp_tag` in
`src/job.rs`, the packet core in `src/divert.rs` and `src/divert/`), and so is
step 3, the `divert` helper: its platform-independent part (the pipe
protocol, the engine loop, the helper sequence and the firewall command
lines) and its Windows bindings (`src/divert/windows.rs`, the hidden
`gateinto divert` subcommand). Nothing starts the helper yet.
`Job::set_dscp_tag`, the helper's Windows bindings and their tests have only
been type-checked from Linux until Windows CI runs them, and the helper has
never opened a WinDivert handle. The design rests on premises that have not been
verified: the evidence is two experiments on GitHub-hosted Windows Server
images ([Evidence](#evidence)), and nothing has been tried on a client
edition of Windows, unelevated, over IPv6, or next to a VPN or antivirus
product. Those premises are listed under [Needs
verification](#needs-verification). Names marked *(proposed)* do not exist in
the code yet; every other name refers to the code at the time of writing.

## Summary

A transparent session routes every outbound TCP connection of the processes
in a session's job object through the session's gateway, without depending on
the application honouring proxy settings. The session keeps its proxy
settings (`--proxy-server` for a browser, the proxy variables for a
terminal); transparent routing catches every connection that ignores them.
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
    layout (`windivert::Address`), compiled on Windows and in tests;
  - the Windows implementation of the seams (`src/divert/windows.rs`) and
    the hidden subcommand `gateinto divert` (`src/main.rs`), Windows only.

  Nothing starts the helper yet: the agent side is step 5.
- `windows-sys` 0.61.2 with `Win32_System_JobObjects`, enabled in
  `Cargo.toml`, defines the net rate control types; `Win32_System_IO`,
  `Win32_System_Pipes` and `Win32_System_SystemInformation` were added for
  the helper. `Win32_UI_Shell`
  (`ShellExecuteExW`) is not enabled.
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
  (`Verifications::offer`). There is no entry point for a connection
  accepted elsewhere, and none without a `CONNECT` head.
- `Shared::open_upstream` calls `routing::attempt` (`src/proxy/routing.rs`):
  on `Route::Gateway` it returns at once; on `Route::Mixed` it resolves the
  target and the gateway, connects directly unless an address matches a
  gateway address, and otherwise falls back to `pool.open`. `Authority`
  (`src/http.rs`) has `Host::Ipv4` and `Host::Ipv6` variants;
  `connect_request` writes `CONNECT {target}` with the literal.
- `SessionManager::start` (`src/sessions.rs`) binds the `Proxy` with
  `Proxy::bind_sharing` and moves it into a task running `run_until` with a
  close signal; `Session` keeps no handle to the proxy's `Shared`.
- Browser sessions (`Agent::start`, `src/agent.rs`): `Launcher::job` returns
  `browser_job()`, which on failure logs a warning and returns `None`; on
  `SpawnError::Job` the agent closes the session and starts the browser
  without a job, with `session_credentials` only. The browser gets
  `--proxy-server=http://<listen>` from `browser::browser_args`.
- Terminal sessions (`Agent::terminal`): `terminal::terminal_job` turns a job
  failure into an error with no fallback; `terminal::terminal_proxy` sets
  `LocalAuth::OS_USER` with the job; `terminal::terminal_environment` sets
  the proxy variables to the session's loopback listener.
- The agent is unelevated and per-user, started by `spawn_agent`
  (`src/main.rs`) or the `HKCU` `Run` value. The MSI installs
  `%LOCALAPPDATA%\Programs\Gateinto\gateinto.exe`, a directory the user can
  write. `lifecycle::windows::elevated` reads `TokenElevation`;
  `check_account` adds `ELEVATED_NOTE` when `setup` runs elevated. Nothing
  in Gateinto starts an elevated process.
- `ConfigFile` (`src/config.rs`) has `deny_unknown_fields` and the sections
  `gateways`, `device_key`, `limits`, `browser` and `terminal`.
- IPC (`src/ipc.rs`): `Request::Launch` carries `uri::LaunchRequest`, the
  type the `gateinto://` parser produces; `Request::Terminal` carries
  `TerminalRequest { gateway, route }`. `SessionInfo` (`ipc-types`) uses
  `serde(default)` without `deny_unknown_fields`.
- `gateinto status` (`status` in `src/main.rs`) prints Linux-only lines from
  `lifecycle::current_linux_status`; it prints no Windows capability lines.
- The test upstream fixture (`tests/fixture/`, `UpstreamProxy`) records
  every request head (`requests()`); `Behavior::Tunnel` connects to the
  `CONNECT` target itself.
- `.github/scripts/win7-imports.txt` lists every DLL import allowed in the
  experimental Windows 7 build of `gateinto.exe`; `shell32.dll` is not in
  it.

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

  `TransparentSection { dscp: Option<Dscp> }` *(proposed)*, with
  `deny_unknown_fields`; `Dscp` accepts 1 to 63 and defaults to
  `Dscp::DEFAULT` (43). An older Gateinto refuses a file with
  `[transparent]` (unknown section). The agent reads it once at start, like
  `[browser] executable`.
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

- The agent keeps one engine state *(proposed)* under a lock: `stopped`,
  `starting(g)` or `running(g)`. The generation `g` is a counter incremented
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
- Each transparent session has an `open` or `closing` mark *(proposed)*
  under its own lock. Every launch into the session's job holds that lock
  while it spawns and refuses when the mark is `closing`. The pipe-break
  handler takes the same lock, sets `closing`, and then terminates the job.
  So a spawn either finishes before the terminate, and the terminate kills
  its process, or sees `closing` and refuses.
- **Lock order.** In the code today, a terminal launch takes `launching`
  (`Inner::launching`, `src/agent.rs:484`), then `Inner::terminals`
  (`src/agent.rs:500`), which it holds through job creation,
  `SessionManager::start` and the spawn, then `Inner::sessions`; the comment
  at `src/agent.rs:497-499` states "launching, terminals, sessions". A
  browser launch takes `launching` (`src/agent.rs:414`) and holds
  `Inner::sessions` from `src/agent.rs:676` across `SessionManager::start`
  and the spawn. `Agent::close` and `Agent::close_all`
  (`src/agent.rs:839-871`) take `Inner::browsers` or `Inner::terminals`,
  release it, and then take `Inner::sessions`. The new locks are
  innermost: launching, terminals, sessions, engine state, session mark.
- **Lock scope of the handler.** It holds the engine lock only to check
  its generation, set `stopped` and take the snapshot, and each session's
  mark only to set `closing` and terminate that job. It releases both
  before it closes the sessions through the existing close paths, which
  take `Inner::browsers` or `Inner::terminals` and then `Inner::sessions`.
  It never waits for a lock of the existing order while holding a new one,
  so a launch that holds `terminals` or `sessions` while waiting for the
  engine lock cannot deadlock with it.

### Order of operations

**Decision: helper ready, then listener, then job tag, then registration,
then processes.**

For a transparent session request the agent:

0. Runs read-only pre-checks, which can refuse the request without side
   effects, so that a request that would fail anyway raises no UAC prompt.
   The authoritative checks under `launching` (and, for terminals, under
   `terminals`) stay as they are and run again.
   - **Rate limit.** Today `Agent::allow_launch`
     (`src/agent.rs:465-481`) locks `Inner::launches`, a
     `std::sync::Mutex` around `LaunchLimiter`, and calls
     `LaunchLimiter::allow`, which drops entries older than `launch_window`
     and, when fewer than `launches` remain, records the request and returns
     true. `Agent::launch` and `Agent::terminal` call it right after taking
     `launching` (`src/agent.rs:416`, `486`). `allow` consumes a slot, so the
     pre-check uses a read-only variant, `LaunchLimiter::would_allow`
     *(proposed)*, under the same mutex, which drops expired entries but
     records nothing; the check under `launching` still records the request.
   - **Platform (terminals).** `Agent::terminal` refuses when
     `Launcher::terminals()` is false (`src/agent.rs:491-495`); the
     pre-check asks the same.
   - **Capacity.** Browsers: `Agent::check_capacity` (`src/agent.rs:657-665`,
     called at `420`) compares `Inner::browsers` with
     `AgentLimits::max_browser_sessions`. Terminals: `Agent::terminal`
     compares `Inner::terminals` with `max_terminal_sessions` while holding
     `terminals` (`src/agent.rs:500-505`). The pre-check reads the same
     counts, taking each map's lock only for the read.
   - **Gateway.** Terminals: `Profiles::terminal_session(&gateway)`, which
     refuses a gateway that is not in the configuration file
     (`src/agent.rs:507`). Browsers: `Profiles::known()` and `link::resolve`
     with `Decision::Defer` (`src/agent.rs:421-423`), which reads only; a
     result other than `Resolution::Launch`, that is a request that would
     need a gateway confirmation, is refused for a transparent session,
     because the transparent mode is never set by a link.

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
   process handle, which may still be in its 5 s grace period holding the
   mutex, bounded by a timeout *(proposed: 10 s)*, and fails with a clear
   error if the old helper does not end. The start:
   1. reserves the listener port T: it binds a socket to `0.0.0.0:0` with
      `SO_EXCLUSIVEADDRUSE`, without listening. If the system hands out a
      port below 49152 (a customised dynamic range), it binds explicit ports
      in 49152 to 65535 instead, a bounded number of tries from a random
      start *(proposed)*. `SO_EXCLUSIVEADDRUSE` keeps every other socket off
      port T, which matters because the engine treats any captured packet
      with source port T as a listener reply;
   2. creates the [liveness pipe](#liveness-pipe) and starts the
      [helper](#the-divert-helper) with T, N, the pipe name and its own pid
      through `ShellExecuteExW`;
   3. waits for the helper's first line at most 60 s, measured from
      `ShellExecuteExW` returning, so time spent on the UAC prompt is not
      counted (whether the call blocks until the prompt is answered needs
      verification);
   4. on `ready`, starts listening on T and, under the engine lock, moves
      the state from `starting(g)` to `running(g)` only if it is still
      `starting(g)` with its own generation; otherwise its helper has
      stopped meanwhile, it closes its listener and the request fails. On
      any failure before that it sets `stopped`, again only from its own
      `starting(g)`. Listening only after the helper has added the
      firewall rule avoids Windows Firewall's "allow this app" prompt for
      `gateinto.exe`, which would create a rule for every port if the user
      accepted it (needs verification).
2. Creates the job, sets and reads back the tag.
3. Starts the session (`SessionManager::start`) and registers its job and
   adoption channel with the transparent listener under the engine lock,
   only if the state is `running(g)` then, recording that `g`.
4. Starts the browser or shell in the job under the session's mark.

Any failure closes what was opened and answers an error. There is no silent
downgrade to a proxy-mode session: the user asked for transparent routing,
and a proxy-mode session would send everything that ignores the proxy
settings directly. Messages name the cause: the helper's `error` code, the
helper's exit code when it ended without a line, a timeout, the tag that
could not be set, a system too old.

### The divert helper

**Decision: a separate elevated process, `gateinto divert`, a hidden
subcommand of the same executable, started on demand through UAC.**

The MSI is per-user, the agent runs unelevated, and there is no machine
service, so opening a WinDivert handle (which needs administrator rights and
loads a kernel driver) needs an elevated process. The agent starts it with
`ShellExecuteExW`, verb `runas`, `SEE_MASK_NOCLOSEPROCESS`, and keeps the
returned process handle.

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

  A panic anywhere between a successful `add` and the final `delete` is
  caught there: the handle closes while the stack unwinds, the rule is
  deleted, and the helper ends with exit code 5 like a fatal engine error.
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
  created. Two handles with overlapping filters would steal each
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
  normal networking; the driver unloads when the last handle closes, or at
  reboot. A fatal engine error (any receive error other than the shutdown)
  ends the helper the same way, without the grace period. The helper closes
  the handle before it deletes the rule, and releases the mutex only after
  that, because the next helper adds a rule of the same name.
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
  `PipeName::from_random`), one instance, `PIPE_ACCESS_DUPLEX`,
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients rejected, a server handle
  that is not inheritable, and a DACL that allows the agent's user and the
  Administrators group *(proposed, step 5)*. Duplex, because the helper
  opens the pipe for reading and writing and keeps a read pending; not
  inheritable, so that the agent's death breaks the pipe even while a
  process the agent started is still running.
- The helper opens the pipe with `SECURITY_SQOS_PRESENT |
  SECURITY_IDENTIFICATION`, so the pipe server can query the helper's
  identity but cannot act as the helper, and checks
  `GetNamedPipeServerProcessId` against `--agent-pid` before it opens the
  agent process with `SYNCHRONIZE`. It opens the pipe with
  `FILE_FLAG_OVERLAPPED` and no sharing: the reporter's writes wait for
  their own completion, while the liveness wait keeps a one-byte overlapped
  read pending and waits with `WaitForMultipleObjects` on that read's event
  and the agent process handle. It returns when the read completes (any
  byte, or an error such as a broken pipe) or the agent process ends, then
  cancels the read and waits for it. On a handle opened without
  `FILE_FLAG_OVERLAPPED`, Windows serializes I/O on the handle, so the
  pending read would block every counter line. The agent accepts
  exactly one client and checks
  `GetNamedPipeClientProcessId` against the pid of the process handle
  `ShellExecuteExW` returned.
- An agent that sees the helper process end drains the pipe before it
  reports a generic exit: exit code 4 means the helper wrote an `error` line
  just before it ended *(proposed, step 5)*.
- **Protocol.** The helper's first and only status line is either `ready` or
  `error <code>` with `<code>` from a fixed list (`ErrorCode`):
  `invalid-arguments`, `another-helper`, `firewall-rule`, `files-missing`,
  `digest-mismatch`, `driver-load <win32 error>`, `driver-version`. After
  `ready`, only counter lines follow: `counters`, then ` name=value` for the
  16 fields of `Counters` in their order and `receive_errors` and
  `send_errors`, each value a decimal `u64` without sign or leading zeros.
  The helper writes one every 10 s when a value changed since its last line
  (all zero before the first), and a last one when the engine loop ends
  while the agent is still there. These are the only data the agent reads
  from the elevated side. Lines are printable ASCII ending in `\n`, at most
  1024 bytes (`MAX_LINE_BYTES`). Anything else, including a second status
  line, a line after `error`, counters before `ready`, an empty line or the
  end of the stream inside a line, is a protocol error (`StatusReader`) and
  is treated as a broken pipe. The agent sends nothing; a byte from the
  agent means to the helper that the agent is gone.
- A helper that ends before it connected, or before its first line, is
  detected through the process handle from `ShellExecuteExW` and reported
  generically with its exit code. Whether the unelevated agent can wait on
  and query that handle for an elevated child needs verification.
- When the agent sees the pipe break, a protocol error, or the helper process
  end, it runs that helper's pipe-break handler with the helper's
  generation: if the state is still that generation's, engine state
  `stopped`, every transparent session of that generation marked `closing`
  and its job terminated, the sessions closed, that helper's listener
  closed (see [Engine state](#engine-state-and-session-registration)); in
  any other state it changes nothing. `status` then reports the engine as
  stopped; a new transparent session starts a new helper (a new generation)
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
agent over the pipe and into the agent's log at `debug` *(proposed)*.

### Transparent listener and attribution

**Decision: one agent-level listener on `0.0.0.0:T`, separate from
`proxy::Proxy`.**

- `TransparentListener` *(proposed)* is its own type. `Proxy::bind` keeps
  its loopback-only invariant (`Error::NonLoopbackListen`) unchanged.
- A non-loopback bind is unavoidable: the reflected packets are addressed to
  the NIC address L that the application used, and WinDivert cannot turn a
  non-loopback packet into a loopback one. The port is chosen as in [Order
  of operations](#order-of-operations), with `SO_EXCLUSIVEADDRUSE`.
- For an accepted connection with peer `R:p` and local address `L:T`, the
  agent reads both TCP tables, IPv4 and IPv6, as `os_user::lookup` does
  with `families`: a dual-stack IPv6 socket carrying IPv4 (Java, .NET)
  appears in the IPv6 table as `::ffff:L:p` to `::ffff:R`. Addresses are
  compared canonically. Candidate rows are those whose local end is `L:p`
  and whose remote address is R.
- Rows with pid 0, and rows whose owner is not in the job of a live
  transparent session, are discarded first; a `TIME_WAIT` row left by an
  earlier use of the port must not make two. For each remaining owner the
  process is opened, its SID must equal the agent's, and `IsProcessInJob`
  must be true for the job of exactly one live transparent session.
- Exactly one row must then remain. Its remote port is the original
  destination port. The tables are read again while the owner's handle is
  held (pid reuse), as `System::check` does. The lookup retries like
  `System::find` and runs in `spawn_blocking` under the handshake deadline.
- No row, more than one row, an owner outside every transparent job, an
  owner of another user, or a lookup error closes the connection without
  contacting any upstream.
- A local process that connects to the listener directly through L (or
  through loopback) is closed by the same checks: if it is outside every
  transparent job, by the job check; if it is inside one, its derived
  destination is `L:T` itself, which is refused.
- This one lookup gives both the session (and so its gateway and route) and
  the original destination `R:port`, so the helper needs no data channel to
  the agent. Taking the destination from the TCP tables is untested (the
  experiment used the engine's translation map); the fallback, if it proves
  unreliable, is a per-flow message from the helper on the pipe, which would
  widen what the agent parses from the elevated side.
- The matcher is a pure function over `Row` *(proposed
  `os_user::original`)*, next to `owner`, so it is tested on every platform.

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
`Shared`, so a new entry point is needed *(proposed)*:

- `Proxy::adopter() -> Adopter` before `run_until`; `Adopter` wraps an
  `mpsc` sender of `(TcpStream, Authority)`. `run_until` selects on the
  shutdown signal, the listener and the adoption receiver.
- **Tunnel limit.** An adopted stream takes a permit from the same
  `Shared::tunnels` semaphore (`Limits::max_tunnels`) with
  `try_acquire_owned`, exactly like an accepted connection, and holds it
  until its task ends. Without a permit it is closed at once (no `503`: the
  application speaks TLS, not HTTP), and it never takes a `rejects` permit.
- `Shared::adopt(stream, target)` *(proposed)* skips the `os_user` lookup
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
  its close signal; `run_until` leaves its loop, drops the listener and the
  adoption receiver, and `connections.shutdown()` aborts every task, adopted
  tunnels included, before the session's task ends. `Session` gains the
  adopter and its job *(proposed)*; the agent's registry of transparent
  sessions maps each job to its adopter and drops the entry when the session
  closes. A send to a closed receiver fails, and that stream is closed.
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
  `gateinto.exe` by an optional MSI feature *(proposed)*. They are never
  linked into `gateinto.exe` and never loaded by the agent or the GUI.
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
- The driver is installed and started by the first `WinDivertOpen` and
  unloads when the last handle closes, or at reboot.
- Without the files, or with a digest mismatch, Gateinto works as today;
  `status` and the error for a transparent request say which file is
  missing or differs.
- License: WinDivert is dual-licensed LGPL-3.0 or GPL-2.0. Gateinto loads an
  unmodified DLL dynamically and ships its license text and the exact
  upstream release next to it; Gateinto's own license is unchanged.

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

All *(proposed)*; the exact spelling is decided in step 5 of the
[Implementation plan](#implementation-plan).

- CLI: `gateinto session terminal --agent --transparent`. `--transparent`
  requires `--agent`.
- IPC: `terminal <gateway> route=<..> mode=transparent`; for browsers a new
  `mode=transparent` word on the IPC `launch` line that the `gateinto://`
  parser never produces and refuses. `Request::Launch` carries
  `uri::LaunchRequest`, the type links produce, so the mode is a separate
  field of the IPC request, not of `LaunchRequest`. An older agent answers
  `invalid request`; the CLI and GUI say the agent is too old.
- GUI: a "Transparent" option for Open terminal and Start browser, offered
  only when the agent reports transparent sessions as available.
- `SessionInfo` gains `transparent: bool`, serialized only when true;
  `session list` marks such sessions.
- `gateinto status` prints `transparent-sessions: available` or
  `unavailable: <reason>` (system too old, ARM64, WinDivert files missing or
  digest mismatch) and, from the agent, `transparent-engine: running` or
  `stopped` with the last helper error.
- Links never select a transparent session: a page must not be able to
  trigger a UAC prompt.

### Logging

**Decision: proxy-mode logging does not change.**

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
  pids or paths.

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
- **Residual leak window.** Between the helper dying and the agent killing
  the jobs, tagged packets go out directly (with DSCP N on the wire). A
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
| A local process outside the job connects to the listener. | Attribution requires an owner in a live transparent job; a process in a job that dials the listener derives `L:T` as destination, which is refused. |
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
| Older agent receiving `mode=transparent` | `invalid request`; CLI and GUI ask for an agent restart | Expected |

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

To add with step 4: `os_user::original` with exactly one row, no row, two
rows, pid 0, a `TIME_WAIT` row of another owner next to the client's row, a
wrong local address, and mapped rows (`::ffff:L:p` to `::ffff:R`) found in
the IPv6 table.

**(b) Windows unit tests:**

- `Job::set_dscp_tag` sets 43 and reads it back, keeps
  `KILL_ON_JOB_CLOSE`, and the last tag set wins (implemented, run only on
  Windows CI); values outside 1 to 63 are refused by `Dscp`.
- The agent's own-job check.

**Agent tests (all platforms, fake `Launcher` and a fake helper seam):**

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
dial 192.0.2.1 directly. `UpstreamProxy` already records request heads
(`requests()`); the only new fixture behaviour is a tunnel to a loopback
echo server whatever the target *(proposed)*. Cases:

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
7. **WinDivert distribution.** Optional component, loaded at runtime by the
   helper only, pinned version, SHA-256 digests checked through held
   handles, driver version checked after opening.
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
    `error <code>` from a fixed list, then only counter lines; anything else
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
4. **Session adoption and the transparent listener.** `Proxy::adopter`,
   `Shared::adopt`, `os_user::original`, `TransparentListener` with
   `SO_EXCLUSIVEADDRUSE` and the port range, the registry of transparent
   jobs, the engine state and session marks.
5. **Agent wiring.** On-demand helper with `ShellExecuteExW`, the order of
   operations, fail-closed handling, `[transparent]`, the CLI flag, the IPC
   mode, the GUI option, `SessionInfo::transparent` and the `status` lines;
   `Win32_UI_Shell` in `Cargo.toml` and `shell32.dll` in the Windows 7
   import allow-list.
6. **Packaging and user documentation.** The optional MSI feature with the
   WinDivert files and license, and the security model, threat model,
   security boundaries, install and compatibility pages.
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
  prompt (the 60 s timeout from its return depends on it), and whether a
  prompt raised by a background agent without a foreground window only
  flashes in the taskbar.
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
