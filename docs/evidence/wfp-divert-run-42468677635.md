# Scoped WFP snapshots and live ALE endpoint controls

Measured 2026-11-08 in [run 42468677635](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635),
including both completed Windows 2022 attempts and the original Windows 2025 attempt.
Source head: `7398bf4577174570cc6c15a09a3c32f72e2f25c9`.
Actions checkout: `e3bd9e498ac8c4bcab262a73a12e79ea1c3a95cb`, the generated merge
with base `28d6827`. Its source tree matches the reviewed head.

Destination filtering reduces unnecessary stored-event work, but a rerun
fails to reproduce a reliable latency gain. Combined with a 5 ms pre-capture window,
it reduced returned event rows by 91.1–98.6% versus legacy 500 ms across the six
paired rounds. All twenty-four 50-client comparisons passed native ownership
and routing checks. Yet Windows 2022 rerun first-decision p95 reached 441.613 ms
with combined filtering versus 48.316 ms for that round's baseline.
Fresh snapshot creation consumed 96.0–99.8% of combined-query elapsed work.

Keep destination scope and the 5 ms window as optional experiments. Neither is
established as a faster or more reliable default. Async lookup remains useful
for separating packet processing from synchronous BFE work, but does not bound
the cost of an individual RPC. The executable's default scope remains legacy.

## Retained evidence and environment

The [aggregate record](wfp-divert-run-42468677635-aggregate.json) retains all
case statuses, focused numeric metrics and public build metadata. Downloaded
artifact summaries matched the projected console summaries for all 71 cases
in each of the three completed matrices. New Git evidence and uploaded artifacts
contain counts and relative durations; private ownership paths, tuples, process/endpoint identities, absolute
timestamps and copied app-ID bytes are excluded.

| OS | Image | Original job | Original artifact |
| --- | --- | --- | --- |
| Server 2022, build 20348 | win22, 20261101.353.1 | [128694060927](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/job/128694060927) | [13612434046](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/artifacts/13612434046) |
| Server 2025, build 26100 | win25-vs2026, 20261103.298.1 | [128694061145](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/job/128694061145) | [13612702696](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/artifacts/13612702696) |
| Server 2022, attempt 2 | win22, 20261101.353.1 | [128694940212](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/job/128694940212) | [13613345112](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677635/artifacts/13613345112) |

All three artifacts contain exactly aggregate-evidence.json, ci-summary.json,
environment.json and driver-manifest.json. Official WinDivert 2.2.2 driver
signatures validated; archive/driver hashes agree across completed jobs and are retained
in the aggregate record. The topology remains one host and IPv4. Ordinary external
connect-only controls do not establish transparent external routing.

## Paired snapshot comparison

All profiles use async lookup and capability caching. Each round starts fifty
clients, split evenly between the selected and nonselected applications.
Twenty-five fixture connections add direct native flows: first-decision and
held-packet distributions cover 75 flows, not only the fifty original clients.

| Profile | Native condition scope | Pre-capture window |
| --- | --- | ---: |
| baseline | Legacy type/protocol/local-port attempts with explicit fallback | 500 ms |
| narrow | Same legacy scope | 5 ms |
| destination | Distinct AND conditions common to all covered subjects | 500 ms |
| combined | Same destination scope | 5 ms |

Round 1 runs baseline, narrow, destination, combined; round 2 reverses that order.
Successful destination queries used type, protocol, remote address and remote
port, adding a local port only for a common local port. All destination
comparisons had zero filter rejections. Legacy comparisons each learned one
unsupported multi-port shape and used their broader fallback. Exact app,
full tuple, layer/direction, generation, capture time and real deadline checks
remain required after every query.

All twenty-four cases had fifty successful client echoes, twenty-five gateway
CONNECTs, twenty-five proxy and fifty direct flows, and zero lookup/BFE errors,
unattributed flows, leaks, resets or nonselected disruption. These are finite
restricted cases, not a proof about arbitrary traffic.

All latency and elapsed values in the tables are milliseconds. Returned rows
count records across queries and can include repeated history; they are not
unique connections.

### Server 2022, attempt 1

| Profile / round | Query p50 | First decision p50 / p95 | Decided-direct p95 | Returned rows | Enum total |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline-r1 | 16.380 | 30.019 / 41.678 | 4.249 | 2228 | 16.414 |
| narrow-r1 | 14.601 | 27.038 / 34.488 | 3.110 | 714 | 6.655 |
| destination-r1 | 14.270 | 24.471 / 35.060 | 3.993 | 527 | 10.682 |
| combined-r1 | 14.091 | 25.946 / 34.732 | 5.001 | 163 | 2.815 |
| combined-r2 | 14.094 | 24.754 / 33.404 | 2.495 | 188 | 4.344 |
| destination-r2 | 14.202 | 24.624 / 37.684 | 4.793 | 584 | 6.199 |
| narrow-r2 | 14.930 | 26.858 / 35.343 | 7.832 | 746 | 7.201 |
| baseline-r2 | 23.040 | 39.990 / 57.636 | 8.282 | 4859 | 38.207 |

### Server 2025, attempt 1

| Profile / round | Query p50 | First decision p50 / p95 | Decided-direct p95 | Returned rows | Enum total |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline-r1 | 20.059 | 35.692 / 52.876 | 4.566 | 2200 | 18.086 |
| narrow-r1 | 18.584 | 32.116 / 44.329 | 4.279 | 663 | 7.841 |
| destination-r1 | 17.162 | 31.461 / 42.327 | 3.523 | 666 | 7.881 |
| combined-r1 | 16.090 | 30.906 / 40.155 | 3.490 | 195 | 3.890 |
| combined-r2 | 16.781 | 30.744 / 46.575 | 4.928 | 173 | 3.818 |
| destination-r2 | 17.772 | 31.738 / 42.494 | 3.614 | 678 | 7.817 |
| narrow-r2 | 16.817 | 29.262 / 42.007 | 7.212 | 746 | 8.385 |
| baseline-r2 | 22.923 | 40.623 / 52.923 | 11.108 | 3837 | 35.397 |

Combined queries in attempt 1 returned 163/188 rows versus 2228/4859 on Server 2022, and
195/173 versus 2200/3837 on Server 2025. Total enum elapsed work fell
78.5–89.2%. Successful snapshot creation still averaged 13.47–13.65 ms per
combined query on Server 2022 and 15.85–16.87 ms on Server 2025. Reusing an
exhausted enumerator cannot receive newly logged events, so it cannot remove
that cost while preserving fresh-flow coverage.

The latency tradeoffs matter: Server 2022 attempt 1 round 1 decided-direct p95 increased
from 4.249 to 5.001 ms with combined filtering. Server 2025 round 2 first-decision
p95 was 46.575 ms combined versus 42.494 ms with destination/500 ms.
Two ordered rounds on shared runners do not isolate all scheduling, launch or
event-history effects. Caller-thread CPU samples remain coarse and exclude the
BFE service; zero sampled ticks are not zero CPU work.

### Server 2022, attempt 2

| Profile / round | Query p50 | First decision p50 / p95 | Decided-direct p95 | Returned rows | Enum total |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline-r1 | 15.481 | 28.531 / 38.227 | 4.147 | 1883 | 12.662 |
| narrow-r1 | 12.156 | 23.076 / 32.453 | 2.797 | 756 | 9.809 |
| destination-r1 | 11.690 | 26.100 / 102.880 | 4.320 | 556 | 4.888 |
| combined-r1 | 12.953 | 68.177 / 134.668 | 8.806 | 78 | 0.798 |
| combined-r2 | 78.794 | 73.454 / 441.613 | 8.891 | 77 | 0.740 |
| destination-r2 | 11.722 | 22.295 / 30.494 | 3.169 | 613 | 5.763 |
| narrow-r2 | 12.022 | 21.589 / 29.950 | 2.660 | 703 | 6.248 |
| baseline-r2 | 19.945 | 34.978 / 48.316 | 3.484 | 5406 | 32.607 |

The rerun retains reduced enumeration volume but overturns the apparent speed
advantage. Combined round 2 returned only 77 rows versus 5406 baseline rows,
yet first-decision p95 increased from 48.316 to 441.613 ms.
Its four create calls total 549.792 ms, with a maximum of 235.106 ms;
total query busy time is 550.920 ms. Combined round 1 reaches 134.668 ms
first-decision p95. Destination/500 ms also regresses in round 1:
102.880 ms versus 38.227 ms baseline, before improving in round 2.

Across all completed comparisons, combined returned rows fall 91.1–98.6%
and total enum work falls 78.5–97.7%. Fresh-create variability can overwhelm
those savings. The aggregates do not establish why those RPCs stalled,
or that the filter caused the stalls. Fewer query calls can reflect longer
blocking calls and larger accumulated batches; they are not automatically
evidence of better efficiency. No profile is promoted to a faster default.

## Live ALE endpoint control

TCP and UDP controls execute before any WinDivert case. Each original client
completes its echo, then keeps its socket open for 500 ms. A qualifying ALE query
must start and finish inside that actual post-echo live interval. Independent
stored-event polling must confirm the exact original application and fresh tuple.
No packet collector or in-process engine is launched in these controls.

| OS / attempt / protocol | Native references | Live ALE original-app matches | System-only clients / shared-ID groups | Mean / max complete query |
| --- | ---: | ---: | ---: | ---: |
| 2022 / 1 / TCP | 6/6 | 6/6 | 0 / 0 | 1.124 / 3.607 ms |
| 2022 / 1 / UDP | 6/6 | 6/6 | 0 / 0 | 1.565 / 4.184 ms |
| 2025 / 1 / TCP | 6/6 | 6/6 | 0 / 0 | 1.671 / 5.950 ms |
| 2025 / 1 / UDP | 6/6 | 6/6 | 0 / 0 | 2.335 / 5.164 ms |
| 2022 / 2 / TCP | 6/6 | 6/6 | 0 / 0 | 1.947 / 46.642 ms |
| 2022 / 2 / UDP | 6/6 | 6/6 | 0 / 0 | 1.960 / 25.406 ms |

All six controls report OBSERVED_ALE_ORIGINAL_APP, clean native polling, complete
ALE queries, no truncation and no cleanup failure. Compiler metadata reports
x64, 64-bit pointers and a 104-byte endpoint structure with matching
compiler-reported SDK field offsets on both hosts.

The two held-packet ALE shadow cases in each completed matrix remain
INCONCLUSIVE_ALE_ENDPOINT_PROBE, with zero qualifying original-app observations
while held. Their routing subcases still complete using stored net events.
The new aggregate does not expose the underlying endpoint paths or per-client
intervals, so it does not establish that diversion causes a System identity.
The controls change both lifecycle and interception state.

The new result demonstrates that ALE can identify live established original
sockets in this topology. It does not establish pre-first-packet availability,
packet-to-socket generation binding, atomic snapshots, or safe close/reuse.
The query means above are not first-packet admission latency and cannot be used
as evidence for replacing the current ownership gate. The 46.642 ms maximum
also rules out treating a low mean as a hard query-latency bound.

## Correctness and remaining failures

- All 27 non-shadow in-process cases pass in each completed matrix, including
  all eight new snapshot comparisons and the three scoped UDP/leak/QUIC cases.
- All eleven split polling cases in each completed matrix reach their expected
  pass or characterized reuse-rejection status. General tuple reuse remains unqualified.
- Each scoped leak control proves three deliberate selected timeouts,
  three late ownership matches, three successful bidirectional reset pairs
  and client-observed reset, with the other clients still echoing. Reset cannot
  undo bytes already sent directly.
- Scoped QUIC controls drop three selected clients and preserve three nonselected
  echoes; their three expected failed client exits are not a case failure.
  UDP forwarding through Gateinto remains unimplemented.
- Subscribe2/3 drain cases still have zero raw callbacks. Subscribe4 receives
  allow callbacks but supplies no qualified ownership for these cases.
  No newly qualified subscription route was found.
- The 1000 ms Security UDP case still fails. The 2000 ms case succeeds.
- Each matrix's native-drop control sees a blocked client and one callback,
  but zero recognized native drops. Unknown event types remain unqualified;
  matching a path and port alone cannot establish a documented drop.
- Standard [repository CI](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42468677636)
  and the model job pass. The PoC Windows jobs remain red because the matrix
  intentionally includes the unqualified alternatives above.

The standalone native-control job in attempt 1 (128694061196), its attempt 2
job (128694940430), and Windows 2025 attempt 2 (128694940509) failed downloading
the official driver archive with HTTP 504 before native compilation or traffic
experiments. Each contributes zero cases. These infrastructure failures do not
replace the complete original jobs and artifacts.

Local validation includes 62 Python tests with the loopback protocol test enabled,
five independently reviewed native helper suites with warnings treated as errors,
Windows x64 object compilation before publication, and PowerShell parsing.
Windows runtime results above additionally prove the actual MSVC builds and
resolved scripts on both OS images.

## Decision

Keep the existing async/cached baseline and compare destination scope, narrow
windows and ALE as experiments. No faster default is established by this run.
Any production decision still needs client Windows builds, external
routing with direct access denied, sustained load and clock-change coverage,
bounded backlogs/RPC cancellation, and safe lifecycle/reuse validation.
