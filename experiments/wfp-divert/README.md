# Native WFP attribution and WinDivert first-packet experiment

This is an independent, administrator-only Windows experiment. It does not change
Gateinto's production listener, authentication or routing. Run only in a disposable
Windows VM: it temporarily enables connection audits and WFP allow-event collection
and diverts traffic scoped to its controlled target.

The hypothesis is that holding packets at NETWORK gives native WFP notifications
time to identify the application before the packet is released or translated.
This is a testable hypothesis, not a conclusion that notifications must arrive in
time. Native callbacks and Security 5156 are tested independently. WinDivert
SOCKET/FLOW, IP Helper owner tables and PID polling are not attribution sources.

## Components

| File | Purpose |
| --- | --- |
| `native-events.cpp` | Native Subscribe2 and Security 5156; raw App ID/path, validity flags, tuples, event FILETIME, callback QPC, and raw Security XML. Native PID is null. |
| `packets.cpp` | NETWORK capture with bounded queues, first-packet buffering, generation-qualified control, pinned timeout-direct policy, and candidate TCP forward/reverse translation. |
| `run.py`, `test_run.py` | Correlate the selected native source, full device path and tuple; inject delayed/missing attribution; verify per-client evidence and final collector status. |
| `bridge.py` | Recover destination from the translated map, send credential-authenticated CONNECT to Gateinto, consume the HTTP response and relay TCP bytes with half-close. |
| `client.cpp` | Built twice as app-a.exe and app-b.exe; echo nonces and original socket tuples provide test ground truth, never ownership authority. |
| `positive_control.py` | A narrowly scoped blocked connection checks native drop-callback delivery. Drops are diagnostic only and cannot authorize proxying. |
| `../../examples/wfp_lab.rs` | Controlled echo endpoints, TLS CONNECT upstream and actual Gateinto proxy with session credentials and forced Gateway routing. |
| `build.ps1`, `ci.ps1` | Download official signed WinDivert, compile probes, back up/restore audit policy, run cases and retain evidence. |

The private fixture manifest contains throwaway credentials. Keep it outside the
artifact root in an ACL-restricted directory; never print or upload it. No real
gateway credentials or user application traffic are required.

## Run

GitHub workflow: `.github/workflows/wfp-divert-poc.yml`, on `windows-2022`.
It runs automatically for a PR changing these files; workflow_dispatch becomes
available once the workflow exists on the default branch.

In elevated PowerShell with MSVC, Rust and Python installed:

```powershell
cargo build --release --locked --example wfp_lab
experiments/wfp-divert/build.ps1 -OutDir C:\wfp-lab\bin
experiments/wfp-divert/ci.ps1 -Bin C:\wfp-lab\bin -OutDir C:\wfp-lab\results
```

The default scripts use RUNNER_TEMP on Actions. For local use supply both paths.
The results directory must be new and disposable. `ci.ps1` restricts its ACL and
restores the saved audit policy in finally. Native collection persists the old
BFE options before mutation, accepts a cooperative stop file, and restores only
when the current values still match this experiment's expected changes. On a
forced exit, use the persisted state as described below rather than assuming
destructors ran.

```powershell
C:\wfp-lab\bin\native-events.exe --restore-state C:\wfp-lab\results\CASE\bfe-state.json --out C:\wfp-lab\restore.jsonl
```

Do not run two collectors that modify BFE options concurrently. An external
configuration change causes guarded restoration to report an error rather than
overwrite it. Hard VM cancellation cannot promise finally blocks execute;
GitHub-hosted VMs are disposable, while a persistent local VM requires inspection
and restoration after interruption.

## Interpretation

The workflow tests TCP hold, both native attribution sources, a short injected
delay, skipped attribution, attribution later than the deadline, UDP multi-peer hold/direct,
TCP redirection, SYN retransmission and a conservative tuple-reuse rejection. It
also tests external TCP connect-only attribution and a temporary firewall-block
positive control. The rule is removed in finally. PASS_RESTRICTED_CASE
requires client echo success, native evidence for each expected confirmed flow,
accepted packet decisions, no B proxy packets, correct bridge count and gateway
CONNECT destination/count, successful collector exit, and no collector error or
overflow. Issuing a proxy command or accepting a local socket alone cannot pass.

Local evidence includes raw native/packet JSONL, decision/control logs, translation and
bridge logs, gateway requests, target payload hex and client nonces/tuples. New
Actions artifacts and console summaries retain only aggregate counts and relative
latency statistics. Raw local files, XML, paths, PIDs, endpoints and per-flow
timestamps are excluded from those uploads. Historical runs retain the artifacts
they originally generated. Driver
load failure is a failed environment probe, not an attribution result. A failed
redirect with successful hold is a redirection failure, not proof native WFP
attribution is impossible.

The initial topology is **same-host IPv4**, including loopback delivery. The
gateway still receives a real TLS CONNECT through Gateinto, but this does not
qualify external-address routing, a real restricted service, production mTLS
identity or desktop Windows 10/11. Gateinto is embedded in the fixture process;
its outgoing target traffic is attributed to that process and must remain direct.
Packet capture of the gateway's own TLS endpoint is outside the target filter.

The loopback NAT layout and alias reservation passed the limited Windows TCP case
in [run 42278267576](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42278267576).
Three selected-app connections reached the gateway and three other-app connections
stayed direct. Outbound injection was required for the local-to-local path.
Holding a tuple is not a socket-identity oracle: the correlator accepts only fresh
unique test sockets within a bounded timestamp window. Native events have no
packet-correlatable generation cookie. Same tuples are never recycled during a
capture process; tombstones and alias reservations remain until exit, bounded at
4096 entries. Ambiguous reuse of an already translated TCP tuple is dropped.
This deliberately avoids claiming production-safe tuple reuse or reclamation.
Active translated sessions must finish before stopping the collector.

UDP currently supports hold and unchanged reinjection **only**. It cannot proxy
UDP through Gateinto. The filter captures both fixture ports and tests one socket
against both. A 1 s hold missed late second-peer controls; 2 s passed the twelve
tuple case. SYN retransmission passed; deliberate full-tuple reuse was safely
rejected but disrupted B, reported CHARACTERIZED_REUSE_REJECTION rather than a
connectivity pass. External TCP connect-only attribution is observation, not a
transparent external relay test. Queue stress, historic-event replay on real
reused sockets, general map reclamation, IPv6, fragmentation, external controlled
target NAT and desktop Windows remain pending.

Local model/helper and fixture tests are separate from Windows runtime results.
See [the review](../../docs/windows-per-app-feasibility.md) and
[execution record](../../docs/windows-per-app-review-log.md) for the evidence
boundary and the full qualification matrix.
