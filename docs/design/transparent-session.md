# Design: transparent sessions on Windows

Status: design decided; implementation started. The decisions are listed in
[Decisions](#decisions). The evidence is two experiments on GitHub-hosted
Windows Server images ([Evidence](#evidence)); nothing has been tried on a
client edition of Windows, unelevated, over IPv6, or next to a VPN or
antivirus product. What must be checked first is under [Needs
verification](#needs-verification). Names marked *(proposed)* do not exist in
the code yet. Names in `src/divert.rs`, `src/divert/` and `Job::set_dscp_tag`
refer to unreviewed code in the working tree of
`claude/session-dscp-routing`; every other name refers to code on `master` at
5473b5f.

## Summary

A transparent session routes every outbound TCP connection of the processes
in a session's job object through the session's gateway, without depending on
the application honouring proxy settings. The session keeps its proxy
settings (`--proxy-server` for a browser, the proxy variables for a
terminal); transparent routing catches every connection that ignores them.
The agent tags the session's job with a DSCP value through
`SetInformationJobObject(JobObjectNetRateControlInformation)`;
Windows then marks every IPv4 and IPv6 packet those processes send, from the
first SYN on. A separate elevated helper, `gateinto divert` *(proposed)*,
holds one WinDivert handle that reflects tagged TCP packets to a listener of
the agent and drops every other tagged packet. For each connection the agent
accepts there, it finds the original connection in the system TCP table,
checks that its owner is in the job of a live transparent session, and hands
the connection to that session's proxy, which opens `CONNECT <ip>:<port>`
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
   |  TCP table: row L:p -> R:port, owner in the job of session S (else close)
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
  `JobObjectExtendedLimitInformation`; no other job information is set.
  `Job::active_processes` already reads job information with
  `QueryInformationJobObject`. `Job::handle` is `pub(crate)`. On Linux
  `Job::new` checks the systemd user scope prerequisites (`src/job/linux.rs`);
  elsewhere it returns `Unsupported`.
- `windows-sys` 0.61.2 with the `Win32_System_JobObjects` feature, already
  enabled in `Cargo.toml`, defines `JOBOBJECT_NET_RATE_CONTROL_INFORMATION`,
  `JOB_OBJECT_NET_RATE_CONTROL_ENABLE`, `JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`
  and `JobObjectNetRateControlInformation`. `Win32_UI_Shell`
  (`ShellExecuteExW`) and the Windows Firewall COM interfaces are not
  enabled.
- `os_user` (`src/proxy/os_user.rs`): `Row { local, remote, pid }`, `owner`
  (the row whose local end is the client's address and whose remote end is
  the listener, pid not 0), `lookup` over `Family::V4` and `Family::V6`
  (an IPv4 client also searches the IPv6 table), `Denial` and the `Owners`
  trait. The Windows backend (`src/proxy/os_user/windows.rs`) reads
  `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_CONNECTIONS` (`rows`,
  `table`), retries `LOOKUP_ATTEMPTS` (5) times `LOOKUP_DELAY` (5 ms) apart,
  opens the process with `PROCESS_QUERY_LIMITED_INFORMATION`, reads the
  table again while the handle is held (pid reuse), compares the token's SID
  with `EqualSid` and, when the session has a job, calls `IsProcessInJob`.
  `Authenticator::os_user` (`src/proxy/local_auth.rs`) runs the lookup in
  `spawn_blocking` under the connection's deadline.
- `Proxy::bind` (`src/proxy/mod.rs`) refuses a listen address that is not
  loopback (`Error::NonLoopbackListen`) and a tunnel limit above
  `MAX_TUNNELS`. `Proxy::run_until` owns the listener; per accepted
  connection it takes a permit of `Shared::tunnels` (`Limits::max_tunnels`,
  default 64) or answers `503` through the `rejects` semaphore.
  `Shared::handle` runs the `os_user` lookup, reads a `CONNECT` head
  (`read_head`, `parse_connect_request`), checks local authentication, opens
  the upstream with `Shared::open_upstream` under `handshake_timeout`
  (default 10 s), writes `HTTP/1.1 200 Connection Established`, and relays.
  There is no entry point for a connection accepted elsewhere, and none
  without a `CONNECT` head.
- `Shared::open_upstream` calls `routing::attempt` (`src/proxy/routing.rs`):
  on `Route::Mixed` it resolves the target and the gateway, connects directly
  unless an address matches a gateway address, and otherwise falls back to
  `pool.open`. `Authority` (`src/http.rs`) has `Host::Ipv4` and `Host::Ipv6`
  variants; `connect_request` writes `CONNECT {target}` with the literal.
- `SessionManager::start` (`src/sessions.rs`) binds the `Proxy` with
  `Proxy::bind_sharing` and moves it into a task running `run_until` with a
  close signal; `Session` keeps the listen address, `OpenTunnels`, the close
  sender and the task, but no handle to the proxy's `Shared`.
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
  `check_account` adds `ELEVATED_NOTE` ("the device key is still created for
  this Windows user") when `setup` runs elevated. Nothing in Gateinto starts
  an elevated process.
- `ConfigFile` (`src/config.rs`) has `deny_unknown_fields` and the sections
  `gateways`, `device_key`, `limits`, `browser` and `terminal`.
- IPC (`src/ipc.rs`): `Request::Launch` carries `uri::LaunchRequest`, the
  type the `gateinto://` parser produces; `Request::Terminal` carries
  `TerminalRequest { gateway, route }`. `SessionInfo` (`ipc-types`) uses
  `serde(default)` without `deny_unknown_fields`.
- `gateinto status` (`status` in `src/main.rs`) prints Linux-only lines from
  `lifecycle::current_linux_status`; it prints no Windows capability lines.
- The test upstream fixture (`tests/fixture/`, `UpstreamProxy`) answers
  `Behavior::Tunnel` by connecting to the `CONNECT` target itself.
- `.github/scripts/win7-imports.txt` lists every DLL import allowed in the
  experimental Windows 7 build of `gateinto.exe`; `shell32.dll` is not in
  it.

In the working tree, unreviewed (steps 1 and 2 of the [Implementation
plan](#implementation-plan)):

- `crate::divert` (`src/divert.rs`): `Dscp` (1 to 63, `Dscp::DEFAULT` 43,
  `InvalidDscp` otherwise) and `divert::filter(listener_port, Dscp)`, which
  writes the filter text below.
- `src/divert/engine.rs`: `Engine::new(listener_port, capacity,
  idle_timeout)`, `Engine::process(packet, Direction, now) -> Verdict`
  (`InjectInbound` or `Drop`) and `Engine::counters() -> Counters`.
  `src/divert/flows.rs`: the flow table, `LINGER` (120 s) and
  `DEFAULT_IDLE_TIMEOUT` (2 h 4 min). `src/divert/packet.rs`: parsing,
  `reflect`, `restore` and full checksum recomputation. All of it is
  platform-independent and has unit tests.
- `Job::set_dscp_tag(Dscp)` (`src/job.rs`, Windows): sets
  `JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`
  with the tag and `MaxBandwidth = 0`, reads it back with
  `QueryInformationJobObject` and fails when either flag or the tag differs.

## Evidence

Two experiments, run on branch `claude/dreamy-cerf-2f0b4c` (not on
`master`), on GitHub-hosted `windows-2022` (build 20348) and `windows-2025`
(build 26100), elevated, IPv4 only, one external destination, with
WinDivert 2.2.2. Small samples; evidence, not guarantees.

- **Experiment 1** (`experiments/job-dscp`, capture only): a job with
  `JobObjectNetRateControlInformation`
  (`JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`)
  marks every outbound packet of its processes, grandchildren included, from
  the first SYN or UDP datagram on, as seen at WinDivert's NETWORK layer;
  processes outside the job are not marked.
- **Experiment 2** (`experiments/job-dscp-route`, reflect engine
  `route.cpp`, a bridge listener and Gateinto's `Proxy` with
  `Route::Gateway`), identical verdicts on both images:
  - tagged sessions routed through the gateway 6 of 6 and, under load
    (30 concurrent), 40 of 40; no tagged packet and no tagged SYN on the NIC;
    untagged traffic went direct;
  - two sessions sharing DSCP 43 were attributed to the right session 12 of
    12 by an owner lookup at accept time (`GetExtendedTcpTable` and
    `IsProcessInJob`);
  - a foreign QoS-policy mark (DSCP 46) outside the job was ignored by an
    exact-match filter, and inside a DSCP 43 job the job tag won;
  - tagged UDP was contained (0 datagrams on the wire) while TCP still
    routed;
  - send errors, orphans, SYN retransmits and key collisions were all 0.
- **Overhead** in that setup: about +65 to +75 ms p50 sequential and +110 to
  +130 ms p50 in a 30-way burst, on top of about 410 to 450 ms direct. It
  included a helper process per connection for the owner lookup and a Python
  bridge with an authenticated `CONNECT` to a loopback proxy, so it is an
  upper bound, not a product measurement. Throughput was not measured.

Not covered by either: client SKUs (Windows 10 and 11), an unelevated
process setting the tag (runners are elevated), IPv6 (no IPv6 route on the
runners), domain-joined machines, VPN, antivirus and other WFP products,
nested jobs, browsers.

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
  `Dscp::DEFAULT` (43). An older
  Gateinto refuses a file with `[transparent]` (unknown section). The agent
  reads it once at start, like `[browser] executable`.
- Setting: `Job::set_dscp_tag(Dscp)` calls
  `SetInformationJobObject(JobObjectNetRateControlInformation)` with
  `ControlFlags = JOB_OBJECT_NET_RATE_CONTROL_ENABLE |
  JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG`, `DscpTag = N`, `MaxBandwidth = 0`,
  then reads it back with `QueryInformationJobObject`. The session does not
  start when the call fails or the read-back lacks either flag or reports
  another tag.
- Only one job in a nested job hierarchy may hold net rate control. If the
  agent itself, or the process that would start the session, already runs
  in a job with it, the call fails; the failure is reported with its Win32
  error code, never ignored.
- The agent refuses transparent sessions when its own process carries a
  net rate control tag (`QueryInformationJobObject` with a null handle
  queries the calling process's job) *(proposed)*: its own upstream
  connections would then be tagged, reflected to its own listener and loop.
- The job tag replaces any DSCP the application or a QoS policy sets
  (experiment 2: the job tag won over a DSCP 46 policy).

### Order of operations

**Decision: helper ready, then listener, then job tag, then processes.**

For a transparent session request the agent:

1. If no helper runs: reserves the listener port T by binding a socket to
   `0.0.0.0:0` without listening, creates the [liveness
   pipe](#liveness-pipe), starts the [helper](#the-divert-helper) with T, N,
   the pipe name and its own pid, and waits for `ready` at most 60 s,
   measured from `ShellExecuteExW` returning, so time spent on the UAC prompt
   is not counted. Then it starts listening on T. Listening only after the
   helper has added the firewall rule avoids
   Windows Firewall's "allow this app" prompt for `gateinto.exe`, which
   would create a rule for every port if the user accepted it *(needs
   verification)*.
2. Creates the job, sets and reads back the tag.
3. Starts the session (`SessionManager::start`) and registers its job and
   adoption channel with the transparent listener.
4. Starts the browser or shell in the job.

Any failure before step 4 closes what was opened and answers an error.
There is no silent downgrade to a proxy-mode session: the user asked for
transparent routing, and a proxy-mode session would send everything that
ignores the proxy setting directly. Messages name the cause: the UAC prompt
was declined, WinDivert is missing or its digest differs, the driver did not
load (with the Win32 error code), the tag could not be set, the system is
too old.

Once started, the helper stays up until the agent stops, so the user
approves one UAC prompt per agent run, not per session. With no
transparent session open it diverts nothing (no tagged packets) and drops
inbound packets to T.

### The divert helper

**Decision: a separate elevated process, `gateinto divert` *(proposed)*,
a hidden subcommand of the same executable, started on demand through UAC.**

The MSI is per-user, the agent runs unelevated, and there is no machine
service, so opening a WinDivert handle (which needs administrator rights and
loads a kernel driver) needs an elevated process. The agent starts it with
`ShellExecuteExW`, verb `runas`, `SEE_MASK_NOCLOSEPROCESS`, and keeps the
process handle.

- **Arguments:** `divert --port T --dscp N --pipe <name> --agent-pid <pid>`
  *(proposed)*, parsed strictly; nothing else. No secret is passed. The
  helper reads no configuration file, opens no device key, never connects
  to the agent's IPC endpoint and never calls `check_current_account`.
- **What it does:** removes stale firewall rules, adds the rule for T
  ([Firewall](#firewall)), verifies and loads WinDivert ([WinDivert
  distribution](#windivert-distribution)), opens one NETWORK-layer handle
  with the static filter, connects to the pipe, sends `ready`, and runs the
  engine loop. It never sees payload in plaintext beyond TCP headers it
  rewrites, never terminates TLS, holds no credential and no key. The mTLS
  key stays in the agent; this also matters when the UAC prompt is answered
  with a different administrator account, whose user cannot use the device
  key anyway.
- **Helper lifetime:** until the agent stops. One administrator approval per
  agent run, not per session.
- **One helper per machine**: the helper creates the named
  mutex `Global\Gateinto-divert` *(proposed)* and exits with an error if it
  exists. Two helpers with the same N would both match the tagged packets;
  the first handle would divert another agent's sessions to its own
  listener, where attribution fails and the connections are closed. A second
  agent (another `GATEINTO_INSTANCE`, or another Windows user on the same
  machine) therefore cannot start transparent sessions while one runs; its
  error says so. Per-instance code points are a possible later step.
- **Exit:** the helper exits when the pipe breaks, when the agent process
  (opened with `SYNCHRONIZE` from `--agent-pid`) ends, or on a fatal engine
  error. Closing the WinDivert handle restores normal networking; the
  driver unloads when the last handle closes, or at reboot.

#### Liveness pipe

- The agent creates a named pipe with a random name
  (`\\.\pipe\gateinto-divert-<128-bit hex>` *(proposed)*), one instance,
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients rejected, and a DACL that
  allows the agent's user and the Administrators group.
- The agent accepts exactly one client and checks
  `GetNamedPipeClientProcessId` against the helper's pid; the helper checks
  `GetNamedPipeServerProcessId` against `--agent-pid`.
- Messages are fixed, line-based and short: `ready` after `WinDivertOpen`
  succeeded, then periodic aggregate snapshots of the engine's `Counters`
  (integers only). These are the only data the agent reads from the elevated
  side; it parses them strictly and treats anything else as a broken pipe.
  The agent sends nothing; the elevated side parses no data from the
  unelevated side.
- When the agent sees the pipe break, an error line, or the helper process
  end, it closes every transparent session: it kills their jobs (`Process::
  kill`) and closes the sessions, then closes the transparent listener.
  `status` then reports the engine as stopped; a new transparent session
  starts a new helper and asks UAC again.

#### Engine

The engine reflects packets as WinDivert's `streamdump.c` does. The pure,
platform-independent core is `crate::divert` (`Engine`, the flow table,
`packet`, `filter`); a thin Windows-only loop *(proposed)* calls
`WinDivertRecv`, passes each packet to `Engine::process` with its
`Direction`, and calls `WinDivertSend` for `Verdict::InjectInbound`.
`Engine::process` does not check the DSCP itself: every outbound packet it
receives is tagged or comes from port T, because the filter selects
nothing else.

Filter (static, compiled once; `DSCP==N` written as the TOS or traffic
class range `4N` to `4N+3`, so the ECN bits may be anything):

```text
(outbound and !loopback and
   ((ip and ((ip.TOS >= 4N and ip.TOS <= 4N+3) or (tcp and tcp.SrcPort == T)))
    or (ipv6 and ipv6.TrafficClass >= 4N and ipv6.TrafficClass <= 4N+3)))
or (inbound and !loopback and tcp and tcp.DstPort == T)
```

Built by `divert::filter(T, Dscp)`. For N = 43 the range is
172 to 175. Loopback is excluded: local traffic stays local, and loopback
replies to a tagged client inherit the tag (experiment 2).

Rewrite:

| Packet | Action |
| --- | --- |
| outbound tagged IPv4 TCP `L:p -> R:port` | look up or create the flow; rewrite to `R:p -> L:T` (addresses swapped, destination port T, DSCP cleared, ECN kept), recompute IPv4 and TCP checksums in full, inject inbound |
| outbound IPv4 TCP from port T, `L:T -> R:p` | find the flow `(R, p)`; rewrite to `R:port -> L:p`, recompute checksums, inject inbound |

Checksums are recomputed over the whole packet, never adjusted
incrementally: with checksum offload the captured outbound packets may
carry a partial or no checksum.

Flow table:

- Key `(R, p)` (remote address, local port); value: remote port, the SYN's
  initial sequence number, FIN seen per direction, last activity, end time.
- A pure SYN (SYN without ACK) with no flow creates one; with the same
  sequence number it is a retransmit; with a new one, or on an ended flow, it
  replaces the flow (the local port was reused). A packet whose remote port
  differs from the flow's is a key collision, dropped and counted.
- A flow ends on RST in either direction, or once FIN has been seen in both
  directions; it then lingers for `LINGER` (120 s, the Windows default
  `TIME_WAIT`), so late ACKs and retransmitted FINs still match. Idle flows
  age out after `DEFAULT_IDLE_TIMEOUT` (2 h 4 min, the RFC 5382 minimum for
  established mappings) as a backstop. Expired flows are removed when looked
  up, and all of them when the table is full.
- Capacity 16384 flows, passed to `Engine::new` (the constant is
  *(proposed)*); a SYN that finds the table full is dropped and counted, and
  the client retransmits.

Dropped and counted, never injected:

- IPv4 fragments and malformed packets;
- non-SYN packets of unknown flows (orphans), and replies from port T
  without a flow;
- tagged IPv4 packets that are not TCP: UDP, QUIC, ICMP and others are
  contained;
- every tagged IPv6 packet: the first version does not translate IPv6, and
  applications are expected to fall back to IPv4 (needs verification; a RST
  in reply to a tagged IPv6 SYN may be needed to make that prompt);
- every inbound packet the filter selects, that is genuine inbound packets
  addressed to port T, so no other machine reaches the listener. This
  relies on WinDivert not re-diverting the handle's own
  injected inbound packets to the same handle (needs verification).

Counters (`divert::Counters`, aggregate integers): `captured`, `new_flows`,
`reflected`, `replies_restored`, `syn_retransmits`, and one per drop reason
(`orphans_dropped`, `key_collisions`, `unknown_replies_dropped`,
`fragments_dropped`, `malformed_dropped`, `table_full`, `contained_udp`,
`contained_other`, `contained_ipv6`, `inbound_dropped`). The Windows loop
adds send and receive errors *(proposed)*. They go to the agent over the
pipe and into the agent's log at `debug`.

### Transparent listener and attribution

**Decision: one agent-level listener on `0.0.0.0:T`, separate from
`proxy::Proxy`.**

- `TransparentListener` *(proposed)* is its own type. `Proxy::bind` keeps
  its loopback-only invariant (`Error::NonLoopbackListen`) unchanged.
- A non-loopback bind is unavoidable: the reflected packets are addressed to
  the NIC address L that the application used, and WinDivert cannot
  turn a non-loopback packet into a loopback one. The port is ephemeral and
  chosen by the agent.
- Protection does not rest on the bind address: the engine drops genuine
  inbound packets to T, and every accepted connection must pass the lookup
  below. A peer with a loopback address is closed at once, because
  reflected connections never come from loopback.
- For an accepted connection with peer `R:p` and local address `L:T`, the
  agent reads the IPv4 TCP table (`GetExtendedTcpTable`, the same `rows` as
  `os_user`) and keeps the rows whose local end is `L:p` and whose remote
  address is R. Exactly one row must remain; its remote port is the
  original destination port. The owner (pid not 0) is opened, the table is
  read again while the handle is held, its SID must equal the agent's, and
  `IsProcessInJob` must be true for the job of exactly one live transparent
  session. The lookup retries like `System::find` and runs in
  `spawn_blocking` under the handshake deadline.
- No row, more than one row, an owner outside every transparent job, an
  owner of another user, or a lookup error closes the connection without
  contacting any upstream. A derived destination equal to the listener
  (`L:T`) is closed too.
- This one lookup gives both the session (and so its gateway and route) and
  the original destination `R:port`. The helper needs no data channel to the
  agent and the agent trusts no data from the elevated side.
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
  clean end of stream.
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
- The helper loads them by absolute path from the installation directory
  after checking their SHA-256 digests against values pinned in the source
  for that release *(proposed)*. The installation directory is writable by
  the user, so the helper opens both files without write or delete sharing,
  hashes them through those handles and keeps the handles open until the
  driver is loaded and the DLL is mapped, so they cannot be swapped between
  the check and the load *(needs verification)*. `LoadLibraryExW` uses
  `LOAD_WITH_ALTERED_SEARCH_PATH` or an absolute path with
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`, never the default search order.
- The driver is installed and started by the first `WinDivertOpen` and
  unloads when the last handle closes, or at reboot.
- Without the files, or with a digest mismatch, Gateinto works as today;
  `status` and the error for a transparent request say which file is
  missing or differs.
- License: WinDivert is dual-licensed LGPL-3.0 or GPL-2.0. Gateinto loads an
  unmodified DLL dynamically and ships its license text and the exact
  upstream release next to it; Gateinto's own license is unchanged.

### Firewall

**Decision: the helper adds a scoped inbound allow rule for its lifetime.**

- At start the helper removes stale rules of a previous run (a fixed rule
  group, *proposed* `Gateinto transparent sessions`), then adds one inbound
  TCP allow rule for local port T and the program `gateinto.exe` (the
  helper's own image path) with `netsh advfirewall firewall add rule` and
  removes it on exit with `netsh advfirewall firewall delete rule`. `netsh`
  is started by absolute path under the system directory
  (`GetSystemDirectoryW`), never through `PATH`, and only its exit code is
  used; its output is not parsed. A failure is fatal for the helper. The
  Windows Firewall COM API (`INetFwPolicy2`) is the alternative if `netsh`
  proves unreliable; it would add `ole32.dll` and `oleaut32.dll` imports.
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
  digest mismatch, another helper running) and, from the agent,
  `transparent-engine: running` or `stopped`.
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
  aggregate data only: counters, booleans, Win32 error codes. No addresses,
  ports, pids or paths.

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
- **No LAN bypass.** Private and LAN destinations follow the session's route
  like any other target: through the gateway on `gateway`, direct from the
  agent on `mixed` unless they match a gateway address.
- **Processes outside the job are not covered**: services, COM servers,
  elevated children started through UAC, WSL 2 and containers, and requests
  handed to an already running process (inference).
- **QoS marking.** The job tag replaces the application's own DSCP marking.
  A QoS policy or application that uses the same code point outside a job
  has its packets diverted and closed while the helper runs.
- **Administrator approval** once per agent run.
- **Kernel driver.** Antivirus, anti-cheat and endpoint products may flag or
  block WinDivert; coexistence with VPN clients and other WFP callouts is
  unverified.
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
  attribution requires one of the agent's own jobs. It can also kill
  the agent, which closes the sessions, or the job's processes.
- **The elevated helper** runs code from `%LOCALAPPDATA%\Programs\Gateinto`,
  which the user can write. Malware of the user could replace
  `gateinto.exe` and wait for the user to approve the next UAC prompt. UAC
  is not a security boundary against code of the same administrator, but
  this design makes such prompts routine. `gateinto.exe` is not code-signed
  yet (CONTRIBUTING.md), so the prompt shows an unknown publisher. The
  helper's attack surface is kept small: strict arguments, no input from
  the pipe, no configuration, `netsh` by absolute path with fixed
  arguments, no network data other than packet headers it
  parses with bounds checks (fuzzed, see [Test plan](#test-plan)).
- **A kernel driver** from a third party is loaded with the user's approval.
  A vulnerability in it is a kernel vulnerability. The digest pins one
  release; updating it is a deliberate change.
- **The non-loopback listener.** Reachable over the network only if both the
  engine's inbound drop and the firewall fail; even then every connection
  must belong to a process in a live transparent job, otherwise it is
  closed before any upstream is contacted. When the helper is not running,
  the listener is closed.
- **No credentials** cross into the helper; it cannot open tunnels, read
  tunnel content beyond headers, or use the device key.
- **Two users on one machine.** The single helper diverts tagged packets of
  every user. Another user's job with the same tag is attributed to no
  session (different SID, not in any of our jobs) and closed.
- **Documentation changes required** with the implementation:
  [security model](../security-model.md#exposure-and-logs), which says that
  every session listens on loopback and that no other machine can reach a
  session, gains the transparent listener; [Routing
  scope](../security-model.md#routing-scope) gains the local DNS and IPv6
  and UDP limits; the threat model gains the rows below; `docs/install.md`
  gains the optional component and the UAC prompt.

Threat-model additions *(to be made with the implementation)*:

| Threat | Mitigation |
| --- | --- |
| A host on the network connects to the listener port. | The engine drops genuine inbound packets to T; attribution closes connections whose owner is not in a transparent job. |
| A local process outside the job connects to the listener. | Loopback peers are closed; attribution requires a live transparent job. |
| A local process uses a transparent session by tagging its own job with N. | None beyond `os_user`'s existing non-guarantee: attribution requires one of the agent's own jobs, so a foreign job is closed; code that joins or injects into the session's job is trusted. |
| The helper dies and tagged traffic leaks. | The pipe breaks and the agent kills every transparent job; the window between is documented. `MaxBandwidth` hardening needs verification. |
| A replaced `gateinto.exe` or WinDivert file gains elevation. | Digest check of WinDivert files with the handles held; nothing for `gateinto.exe` beyond UAC; documented residual risk. |
| A link triggers UAC prompts. | No link field selects a transparent session; the IPC mode word is not part of `LaunchRequest`. |
| The engine misparses a hostile packet. | Bounds-checked pure parser, unit and fuzz tests, drops on any malformed input. |

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
| Java, Node.js, `ssh`, PowerShell 5.1, `winget` in a transparent terminal | TCP routed by IP literal | Needs verification |
| Chrome and Edge in a transparent browser session | Through `--proxy-server` as today; connections that bypass it are routed if the tag reaches processes in Chrome's own nested sandbox jobs | Needs verification |
| QUIC, WebRTC UDP, application UDP DNS | Dropped; application fallback | Needs verification |
| IPv6-preferring applications | Dropped; fallback to IPv4 | Needs verification |
| Gateway policy keyed on host names | Sees IP literals | Needs verification against the production gateway |
| VPN clients, antivirus, anti-cheat, other WFP products | Unknown | Needs verification |
| QoS policies using DSCP N | Broken while the helper runs | Expected by design |
| Configuration file with `[transparent]` read by an older Gateinto | Refused (unknown section) | Expected, by `deny_unknown_fields` |
| Older agent receiving `mode=transparent` | `invalid request`; CLI and GUI ask for an agent restart | Expected |

## Test plan

TDD order: each item starts as a failing test. Logs and CI output stay
aggregate (counts, booleans, error codes); no addresses, ports, pids or
paths.

**(a) Packet core, every platform including Linux CI (`cargo test`):**

- IPv4 and TCP parsing: header lengths, options, total length, truncated
  and inconsistent packets, fragments (MF or offset), non-TCP protocols;
  IPv6 detection.
- Rewrite: outbound tagged SYN to the reflected form (addresses, ports,
  DSCP cleared, ECN kept), reply to the restored form, with full checksums
  checked by an independent verifier, including packets with zeroed or
  partial checksums.
- Flow table: creation by pure SYN, retransmit, replacement on a new
  sequence number or after the flow ended, key collision, orphan, reply
  without a flow, end on RST, end on FIN in both directions, linger, idle
  expiry, capacity.
- Drop classification for every reason, with counters.
- `divert::filter` for N = 1, 43 and 63 and a few ports; the text is the
  shape above.
- `os_user::original`: exactly one row, no row, two rows, pid 0, wrong local
  address, IPv6 rows ignored.
- A fuzz target for the engine's packet function in `fuzz/`.

**(b) Windows unit tests:**

- `Job::set_dscp_tag` sets 43 and reads it back; values outside 1 to 63 are
  refused by `Dscp`; a second tag in a nested job fails with an error, not
  silently.
- The agent's own-job check.

**Agent tests (all platforms, fake `Launcher` and a fake helper seam):**

- order of operations: no job is created before `ready`, no process before
  the tag is read back; each failure starts nothing and leaves no session;
- no fallback to proxy mode and, for browsers, no fallback without a job;
- pipe break closes every transparent session and the listener, and leaves
  proxy-mode sessions open;
- the helper is started once per agent run, and the 60 s start timeout
  runs from `ShellExecuteExW` returning;
- the session still gets its proxy settings (`--proxy-server`, proxy
  variables);
- an adopted stream takes a permit from the session's tunnel limit and is
  closed without one; closing the session aborts adopted tunnels; adopted
  tunnels log the target like proxy-mode tunnels and never the peer.

**(c) Windows CI integration (elevated hosted runner, proposed
`tests/transparent_windows.rs`, serialized):** a pinned WinDivert release
downloaded in the workflow and verified by SHA-256. No internet: the client
in a tagged job dials a TEST-NET-1 address (`192.0.2.0/24`, RFC 5737), so
the SYN never leaves the machine when the engine reflects it, and the
in-process TLS upstream fixture on loopback serves `CONNECT 192.0.2.1:443`.
The fixture's `Behavior::Tunnel` connects to the target itself, so the test
needs a behaviour that records the target and tunnels to a loopback echo
server *(proposed)*. Cases:

- routed: the fixture sees exactly one `CONNECT 192.0.2.1:443` and data
  round-trips;
- an untagged process is not routed: the fixture sees no `CONNECT`;
- a connection made directly to the listener port is closed and reaches no
  upstream;
- a foreign owner (a process in a job tagged with N that is not a session's
  job) is closed;
- stopping the helper closes the session, kills its job and removes the
  firewall rule (checked with `netsh`'s exit code);
- tagged UDP is contained (engine counter equals datagrams sent).

**(d) Type-check only from Linux:** the Windows-only code (job tag, helper,
WinDivert binding, firewall, `ShellExecuteExW`) with the recipe in
[compatibility.md](../compatibility.md#windows-type-check-from-linux), which
links and runs nothing.

**Manual checklist (Windows 10 and 11, results go to
`docs/verification.md`):** an unelevated agent with a UAC prompt (same and
different administrator account), Chrome and Edge in a transparent browser,
`ssh`, `git`, Java and `winget` in a transparent terminal, IPv6-capable
networks, a VPN client, Defender with "block all incoming connections",
the helper killed while tunnels are open.

## Decisions

1. **Scope.** Windows 10 1607 / Server 2016 or later, x86 and x64; opt-in
   per agent browser or terminal session; proxy-mode sessions unchanged.
2. **Mark.** One DSCP for all transparent sessions, default 43,
   configurable 1 to 63, set on the job and read back; failure is reported.
3. **Engine.** A separate elevated `gateinto divert` helper started on
   demand through UAC, one WinDivert NETWORK-layer handle with a static
   filter, packet reflection only, no plaintext, credentials or key.
4. **Listener.** One agent-level listener on `0.0.0.0:T`, a type separate
   from `proxy::Proxy`; attribution and the original destination come from
   one TCP-table lookup with `IsProcessInJob`; the stream is adopted by the
   session's proxy.
5. **Target naming.** `CONNECT <IP literal>:<port>`; SNI later.
6. **Fail closed.** Helper ready, listener, tag, processes; a liveness pipe;
   pipe break closes every transparent session; no downgrade to proxy mode;
   the residual window is documented.
7. **WinDivert distribution.** Optional component, loaded at runtime by the
   helper only, pinned version and SHA-256 digests.
8. **Firewall.** A scoped inbound rule for the helper's lifetime, added and
   removed with `netsh advfirewall firewall` by absolute path, exit code
   only; `INetFwPolicy2` as the alternative; stale rules removed at start;
   protection rests on the engine and attribution.
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
14. **Counters on the pipe.** The helper sends `ready` and aggregate counter
    snapshots; nothing else is read from the elevated side.
15. **Helper lifetime.** Until the agent stops: one approval per agent run.
16. **Configuration.** `[transparent] dscp` in the configuration file.
17. **Values.** Flow linger 120 s, 16384 flows, idle backstop 2 h 4 min,
    helper start timeout 60 s from `ShellExecuteExW` returning.
18. **Refinements.** Bind `0.0.0.0:0` first and listen only after `ready`
    and the firewall rule; `Proxy::adopter` and `Shared::adopt`;
    `os_user::original` matching the accepted socket's local address; no
    job-less browser fallback; the transparent mode is an IPC field a link
    cannot set; WinDivert digests checked through held handles; one helper
    per machine (`Global\Gateinto-divert`); the agent's own-job check.

## Implementation plan

Each step is one small pull request, test first: a failing test, the minimal
code to pass it, then a refactor.

1. **Job DSCP tag with read-back.** `Dscp`, `Job::set_dscp_tag` (in the
   working tree, unreviewed), the own-job check.
2. **Platform-independent packet core.** Parsing, rewrite, checksums, flow
   table, drop counters, `divert::filter` (in the working tree, unreviewed),
   the fuzz target.
3. **WinDivert runtime binding, engine loop, `divert` helper subcommand and
   liveness pipe.** Digest check with held handles, `LoadLibraryExW`,
   `WinDivertOpen`, the machine-wide mutex, counters on the pipe.
4. **Session adoption and the transparent listener.** `Proxy::adopter`,
   `Shared::adopt`, `os_user::original`, `TransparentListener`, the
   registry of transparent jobs.
5. **Agent wiring.** On-demand helper with `ShellExecuteExW`, the order of
   operations, fail-closed handling, `[transparent]`, the CLI flag, the IPC
   mode, the GUI option, `SessionInfo::transparent` and the `status` lines;
   `Win32_UI_Shell` in `Cargo.toml` and the Windows 7 import allow-list.
6. **Packaging, firewall rule and user documentation.** The optional MSI
   feature with the WinDivert files and license, the `netsh` firewall rule,
   and the
   security model, threat model, install and compatibility pages.
7. **Windows CI integration test** on an elevated runner.

## Needs verification

These are not open design questions; each has a decided answer or fallback
above and must be checked before it ships. Results go to
`docs/verification.md`.

- An unelevated process can set the job's net rate control tag (CI runners
  are elevated). If it cannot, the agent cannot tag jobs and the design
  needs the helper to do it, which this document does not cover.
- Behaviour on Windows 10 and 11 client editions, including Home.
- WinDivert does not re-divert a handle's own injected packets to that same
  handle, which the inbound-drop clause relies on.
- Injected inbound packets pass Windows Firewall with the scoped rule, also
  with "block all incoming connections" and on public networks.
- Listening only after the rule exists avoids the firewall's "allow this
  app" prompt.
- TCP-table rows are visible at accept time, including connections still in
  `SYN-SENT`.
- The production gateway accepts `CONNECT` to IP literals under its policy.
- Browsers' built-in DNS and QUIC fall back when tagged UDP is dropped.
- The tag reaches processes in nested jobs: Chrome's sandbox puts its
  processes in their own jobs; a terminal may already run in a job (Windows
  Terminal, CI agents). Whether the parent job's tag applies, and whether
  any of them already holds net rate control.
- The `MaxBandwidth` kill-switch hypothesis.
- Coexistence with VPN clients, antivirus, anti-cheat and other WFP
  products; driver loading with HVCI, Smart App Control and the vulnerable
  driver blocklist.
- IPv6 drop falls back to IPv4 promptly; otherwise a RST reply to tagged
  IPv6 SYNs.
- The i686 build under WOW64 with the x86 `WinDivert.dll` and the 64-bit
  driver.
- The pipe DACL when UAC is answered with a different administrator
  account.
- Holding the WinDivert files open without write or delete sharing prevents
  replacing them (and renaming their directory) until the driver and the
  DLL are loaded.
- Every row of the [compatibility table](#compatibility).
