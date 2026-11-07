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
| `native-events.cpp` | Native WFP net events (`--wfp-api subscribe2`, `subscribe3`, `subscribe4` or `poll`) and Security 5156; raw App ID/path, validity flags, tuples, event FILETIME, callback QPC, ABI/raw allow fields, and raw Security XML. Native PID is null. |
| `ale-endpoints.cpp` | Separate native WFP live-endpoint shadow probe; exact app ID/tuple/endpoint ID and complete query interval, with no fabricated event time or routing authority. |
| `packets.cpp` | NETWORK capture with bounded queues, first-packet buffering, generation-qualified control, pinned timeout-direct policy, and candidate TCP forward/reverse translation. |
| `inproc.cpp` | Single-process `inproc` engine: WinDivert NETWORK capture/reinject, on-demand native WFP stored-event lookup, generation match, TCP redirect translation and post-hoc leak check in one native process. Portable match and metric helpers are unit-tested (`g++ -std=c++17 -Wall -Wextra inproc.cpp`). |
| `run.py`, `test_run.py` | Correlate the selected native source, full device path and tuple; inject delayed/missing attribution; verify per-client evidence and final collector status. |
| `bridge.py` | Recover destination from the translated map, send credential-authenticated CONNECT to Gateinto, consume the HTTP response and relay TCP bytes with half-close. |
| `client.cpp` | Built twice as app-a.exe and app-b.exe; echo nonces and original socket tuples provide test ground truth, never ownership authority. |
| `../../examples/wfp_lab.rs` | Controlled echo endpoints, TLS CONNECT upstream and actual Gateinto proxy with session credentials and forced Gateway routing. |
| `build.ps1`, `ci.ps1` | Download official signed WinDivert, compile probes, back up/restore audit policy, run cases and retain evidence. |

The private fixture manifest contains throwaway credentials. Keep it outside the
artifact root in an ACL-restricted directory; never print or upload it. No real
gateway credentials or user application traffic are required.

## Run

GitHub workflow: `.github/workflows/wfp-divert-poc.yml`, independently on
`windows-2022` and `windows-2025`.
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
delay, skipped attribution, attribution later than the deadline, UDP hold/direct,
and TCP redirection including a skip-all negative control. PASS_RESTRICTED_CASE
requires client echo success, native evidence for each expected confirmed flow,
accepted packet decisions, no B proxy packets, correct bridge count and gateway
CONNECT destination/count, successful collector exit, and no collector error or
overflow. Issuing a proxy command or accepting a local socket alone cannot pass.
A `--source wfp` case whose native summary reports `wfp_count` 0 ends as
INCONCLUSIVE_NO_NATIVE_EVENTS instead of passing, because its negative controls
never exercised WFP attribution. Raw callbacks with zero usable target ownership
similarly give INCONCLUSIVE_NO_USABLE_NATIVE_EVENTS. The summary also reports every subscription
callback by type (`wfp_raw_count`, `wfp_type_counts`) and the stored net events
enumerated for the collector window (`wfp_enum_total`, `wfp_enum_type_counts`,
up to 200 `wfp_enum` CLASSIFY_ALLOW lines).
On `wfp_enum` lines `recv_qpc` and `receipt_filetime` are the enumeration time;
`event_filetime` is the event's own timestamp. Enumeration failures appear as
`wfp_enum_error` lines and `wfp_enum_errors`, never as collector errors, and
enumeration stops after about 2 s or 64 batches. Only the first 5 `wfp_enum_error`
lines are written; `wfp_enum_errors` counts all of them. `wfp_enum_truncated` is
true only when a limit stopped enumeration and a one-entry probe then found an
unread event or failed.

`--wfp-api` selects how the collector obtains WFP CLASSIFY_ALLOW events, all
reported as `kind:"wfp"` and validated identically. `subscribe2` uses
FwpmNetEventSubscribe2/FWPM_NET_EVENT3, `subscribe4` uses
FwpmNetEventSubscribe4/FWPM_NET_EVENT5 (Windows 10 1809+), and `poll`
enumerates only CLASSIFY_ALLOW stored net events (an `FWPM_CONDITION_NET_EVENT_TYPE`
enum condition), waiting `--poll-interval-ms` (default 5) on a high-resolution
waitable timer between polls, over a window that starts `--poll-overlap-ms`
(default 300) before the previous poll end, deduplicated on timestamp, tuple and
app ID. A polled event's `recv_qpc` is when the poll observed it, so
`notification_minus_capture_ms` includes polling latency. The summary reports
`wfp_api`, `wfp_polls`, `wfp_polls_with_new_events`, poll thread start/stop QPC,
total, mean and max poll duration, total wait and maximum wait overshoot,
`wfp_poll_timer` (`high_resolution`, or `sleep_for` when that timer is
unavailable), `wfp_poll_errors` (capped `wfp_poll_error` lines, not collector
errors) and `wfp_poll_missed`: CLASSIFY_ALLOW events in the final enumeration
minus unique polled events, including events stored after the last poll. It is
null when not polling or when the final enumeration was truncated or had errors,
and negative if stored events were evicted before it. A poll case whose summary
reports `wfp_polls` 0 ends as FAIL. Poll mode additionally runs the retransmit
and reuse scenarios and repeats the TCP hold and redirect cases for stability.

`subscribe3` uses FwpmNetEventSubscribe3/FWPM_NET_EVENT4. Subscription records
preserve raw direction/BOOL/profile fields and callback sequence, while ready
records report structure sizes/offsets. Subscribe3/4 additionally emit diagnostic
`wfp_enum5` records for the same window as Enum3. These records never authorize a
packet. The comparison cases use `--callback-drain-ms 1500` to retain callbacks
after normal collection, which does not make a late callback meet a hold deadline.

Evidence includes raw native/packet JSONL, decision/control logs, translation and
bridge logs, gateway requests, target payload hex and client nonces/tuples. Driver
load failure is a failed environment probe, not an attribution result. A failed
redirect with successful hold is a redirection failure, not proof native WFP
attribution is impossible.

The initial topology is **same-host IPv4**, including loopback delivery. The
gateway still receives a real TLS CONNECT through Gateinto, but this does not
qualify external-address routing, a real restricted service, production mTLS
identity or desktop Windows 10/11. Gateinto is embedded in the fixture process;
its outgoing target traffic is attributed to that process and must remain direct.
Packet capture of the gateway's own TLS endpoint is outside the target filter.

The NAT layout and alias reservation are candidates requiring Windows execution.
Holding a tuple is not a socket-identity oracle: the correlator accepts only fresh
unique test sockets within a bounded timestamp window. Native events have no
packet-correlatable generation cookie. Same tuples are never recycled during a
capture process; tombstones and alias reservations remain until exit, bounded at
4096 entries. Ambiguous reuse of an already translated TCP tuple is dropped.
This deliberately avoids claiming production-safe tuple reuse or reclamation.
Active translated sessions must finish before stopping the collector.

UDP currently supports hold and unchanged reinjection **only**. It cannot proxy
UDP through Gateinto. Split poll-mode CI covers two destinations on one UDP socket,
SYN retransmission and conservative rejection of deliberate TCP tuple reuse.
The in-process cases use fresh tuples and one UDP destination. Queue stress, safe
tuple reclamation, late historic-event replay against real reused sockets, IPv6,
fragmentation, external target routing and desktop Windows remain pending.

Local model/helper and fixture tests are separate from Windows runtime results.
See [the review](../../docs/windows-per-app-feasibility.md) and
[execution record](../../docs/windows-per-app-review-log.md) for the evidence
boundary and the full qualification matrix.

## In-process engine (`--engine inproc`)

`inproc.exe` collapses the split `native-events.exe` + `packets.exe` + `run.py`
control-file pipeline into one native process. It removes the file and
control-file hops and the sleep-quantized 2 ms packet loop: a blocking
`WinDivertRecv` receive thread feeds a worker that waits on a condition variable
until the nearest pending-flow deadline or retry, and a high-resolution waitable
timer is used for the native collector's own timing elsewhere.

When a new flow's first packet is held, the engine enumerates stored net events
on demand with an `FWPM_NET_EVENT_ENUM_TEMPLATE0` filtered to net event type
`CLASSIFY_ALLOW`, the IP protocol, the pending local ports (attempted as repeated
`FWPM_CONDITION_IP_LOCAL_PORT` conditions, batched across flows pending at the
same moment) and a tight `[capture − window, now]` time window. If a condition
key is rejected at runtime the filter falls back to protocol-only, then type-only,
then time-window-only, and the filter actually used is reported in the summary as
`enum_filter`; `enum_filter_fallback` records preserve the rejected level and error.
Lookups retry with a 0, 1, 2, 4, 8 ms backoff until the hold deadline. Enumeration
errors, incomplete enumeration and cleanup failures discard the result and fail
the case, with `lookup_errors` and `bfe_errors` in the summary.

An ownership-based decision requires the match in the portable, unit-tested
`inproc::match_generation` to accept an event: exact tuple,
all required native header validity flags, a nonempty full app path, outbound
direction, layer `ALE_AUTH_CONNECT` (48/50), and an `event_filetime`
inside a configurable window (`--window-before-ms`, `--window-after-ms`) around
the first-packet capture time converted through the QPC/FILETIME anchor. The
newest qualifying event in that window is selected only when all qualifying
events name the same app. The internal packet generation does not appear in the
WFP event and cannot prove socket identity or safe tuple reuse. Once decided,
packets are translated and forwarded straight from the worker. Each accepted
match emits `ownership` with tuple, generation, app path and native event time.

Decision QPC is sampled after enumeration and alias reservation; a match cannot
authorize proxy/drop after the capture-based deadline. Synchronous BFE RPC still
blocks the worker, so the hold value is a decision budget, not a hard upper bound
on actual packet delay in inline mode. The receive backlog is not yet bounded in
this engine. `--lookup-mode async` moves enumeration to a dedicated thread with
one bounded request/result handoff; the packet worker continues to service packets
and deadlines. Results must still match the requested tuple/capture/generation and
current deadline. Joining that thread cannot cancel an active synchronous RPC.

`--filter-cache on|off` compares learned unsupported-filter patterns against the
uncached baseline. The cache separates protocol and single/multiple port shapes
and never stores ownership answers. Generic invalid-parameter and transient errors
are not learned. Per-phase create/enum/destroy/process elapsed metrics and
query-thread CPU samples expose actual costs; caller CPU excludes BFE service work.

The selected app's UDP to the QUIC port (`--quic-port`) is dropped and counted
once attributed; other UDP is released direct. Flows released direct on a
timeout or missing event are released direct. TCP flows are re-checked for a
bounded period (`--leak-ms`); a flow later shown to be the selected app is counted
as `leaked` and, with `--send-rst`, receives checked RST injections in both
directions. `rst_count` counts successful pairs; whether the socket terminated
requires client-observed reset evidence. Reset cannot undo bytes already sent.
Gateinto's gateway TLS destination stays outside the target filter; fixture
sockets to the controlled target are captured and must be attributed direct.

`engine-summary.json` reports: first-packet decision latency p50/p95/max; lookup
calls total, per flow and duration; per-packet added latency (capture to
successful reinjection, including the WinDivert receive queue) for held,
decided-direct and decided-proxy classes; `unattributed`,
`leaked` and `rst_count`; `quic_drops`; whether a non-selected client was
disrupted; and the `enum_filter` and window in effect. Lookup totals include the
post-timeout checks; per-flow lookup counts cover the pending decision phase.

PASS requires per-client attempted tuple and protocol, generation-matched native
ownership with the exact expected app path, the expected decision within its
deadline, and a successful client echo (or an evidenced selected QUIC drop).
Unexpected timeout, leak, RST or non-selected proxy/drop/reset fails a normal case.

`ci.ps1` runs the engine in `hold-inproc-tcp`, `hold-inproc-udp`,
`redirect-inproc`, `hold-inproc-tcp-repeat`, `redirect-inproc-repeat`,
`leakcheck-inproc` (TCP redirect, 100 ms hold and 250 ms selected-app attribution
delay via `--delay-ms`, with `--send-rst --expect-leak`),
`concurrency-inproc` (50 parallel clients split app-a/app-b, checking no
wrong-app redirection and all CONNECTs correct) and `quic-inproc` (selected
app UDP/QUIC drop). The existing poll and subscription cases are kept for
comparison. In leakcheck, selected clients keep their TCP socket open after echo
and must observe WSAECONNRESET after a logged timeout, late native ownership,
leak and successful bidirectional RST. Other-app clients must still echo normally.
The delay changes when selected ownership is consumed, preserving native timestamps.

The original in-process Windows run had measurement and coverage gaps; see
[the evidence audit](../../docs/evidence/wfp-divert-run-42348888370.md).
The repaired timing, UDP/QUIC and live-reset cases await Windows execution.

Additional CI cases compare cache-off inline, cache-on inline, and cache-on async
lookup, including concurrency, UDP, QUIC and deterministic leak/reset checks.
`--ale-probe` adds a standalone native WFP endpoint sampler to separate shadow
cases. Every controlled client's exact app/tuple must be observed in a complete
query interval between capture and decision, or the shadow case is inconclusive.
The sampler does not supply routing authority, event timestamps or packet-visible
socket identity. Keep its extra BFE load outside the performance A/B comparison.
See [the low-latency research](../../docs/windows-per-app-low-latency.md) for the
design, official API references, qualification limits and comparison criteria.
