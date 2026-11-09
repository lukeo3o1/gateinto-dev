# WFP latency comparison: run 42356168781

Date: 2026-11-07. Tested commit: `804e0040aeed53f2d78402a1f492ce7bdb6ef644`.
[Workflow run](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781).

| Runner | Actual OS/image | Windows job | Retained artifact |
| --- | --- | --- | --- |
| windows-2022 | Server 2022, build 20348; image 20261101.353.1 | [128354614502](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781/job/128354614502) | [13567134235](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781/artifacts/13567134235) |
| windows-2025 | Server 2025, build 26100; windows-2025-vs2026 image 20261103.298.1 | [128354614630](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781/job/128354614630) | [13567712508](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781/artifacts/13567712508) |

Source: decoded job logs, per-case result JSON, native callback/Enum3/Enum5
records, ALE records and final engine summaries. The workflow's model job and
standard repository CI passed. Both Windows PoC jobs concluded failure because
subscription comparisons, the 1000 ms Security UDP case and the two ALE shadow
cases did not pass. This is a per-case experiment report, not a green-job claim.

A preceding attempt, run 42355949237 at `58e2f80`, stopped at MSVC compilation:
the ALE SDK dependency required NTSTATUS before fwpsu.h. Including winternl.h
fixed the build on both runners; that first attempt produced no runtime findings.

## Finding: async lookup protects decided traffic

Each concurrency case launches 50 clients (25 selected A, 25 B), with 25 additional
fixture target sockets. All 75 flows have expected native decisions, 25 proxy
decisions and 25 correct gateway CONNECTs; no unexpected timeout/leak/RST or
wrong-app redirect was reported.

Values are milliseconds; distributions use the helper's nearest-rank percentiles.

| OS | Case | First-decision p50 / p95 | Decided-direct packet added latency p50 / p95 | Completed queries | Create calls | Cache hits |
| --- | --- | --- | --- | --- | --- | --- |
| 2022 | concurrency-inproc-cacheoff | 26.397 / 33.038 | 3.547 / 18.228 | 8 | 15 | 0 |
| 2022 | concurrency-inproc | 24.465 / 33.624 | 3.863 / 17.260 | 10 | 11 | 7 |
| 2022 | concurrency-inproc-async | 24.873 / 34.672 | 1.686 / 2.683 | 9 | 10 | 6 |
| 2025 | concurrency-inproc-cacheoff | 35.740 / 59.655 | 7.950 / 28.151 | 12 | 23 | 0 |
| 2025 | concurrency-inproc | 39.521 / 77.874 | 8.214 / 32.901 | 11 | 12 | 8 |
| 2025 | concurrency-inproc-async | 37.836 / 56.844 | 2.438 / 12.043 | 13 | 14 | 11 |

For cache-on inline versus async, decided-direct p95 fell from 17.260 to 2.683 ms
on Server 2022 (about 6.4 times lower) and from 32.901 to 12.043 ms on Server 2025
(about 2.7 times lower). Added packet latency is capture Timestamp through checked
successful reinjection. These classes include non-selected clients and direct
fixture sockets; they are not an end-to-end application RTT measure.

First-decision latency did not improve consistently. The Server 2022 concurrency
p50 was 24.465 ms inline versus 24.873 ms async, while Server 2025 was 39.521 versus
37.836 ms. Small redirect repetitions also vary in both directions. Async is
supported here as isolation from blocking lookup, not a universal faster
first-packet attribution claim.

The cached variants avoid repeated rejected-filter create attempts, but this
single sequential comparison does not establish lower total CPU or consistent
latency improvement from caching alone. Do not pool these observations across OS,
cases, fixture load or shadow-probe runs.

## Finding: creation dominates query elapsed time

| OS | Case | Query busy total ms | Create total ms | Enum total ms | Destroy total ms | Process total ms | Create share of query elapsed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2022 | concurrency-inproc | 129.825 | 116.261 | 9.249 | 0.194 | 3.892 | 89.6% |
| 2022 | concurrency-inproc-async | 126.810 | 109.185 | 12.971 | 0.203 | 4.204 | 86.1% |
| 2025 | concurrency-inproc | 184.997 | 157.217 | 19.206 | 0.476 | 6.470 | 85.0% |
| 2025 | concurrency-inproc-async | 256.582 | 211.221 | 32.101 | 0.554 | 10.807 | 82.3% |

Most elapsed time is in FwpmNetEventCreateEnumHandle0, including failed filter
attempts and fresh snapshot construction/RPC, rather than copying returned rows.
The API call is measured as a unit; this experiment does not split server-side
work from RPC scheduling or transport overhead.

GetThreadTimes samples were valid but often 0 or multiples of 15.625 ms in these
short cases. Zero is accounting granularity, not proof that lookup consumes no
CPU. The metric covers the calling query thread and excludes BFE service CPU.

## Coverage and reliability checks

Every non-shadow in-process case passed on each OS: 16/16 per runner. This includes
real UDP hold, selected QUIC drop with non-selected UDP echo, TCP redirect,
repetition, concurrency and deterministic late-attribution reset.

| OS | Case | Status | Unattributed / leaked / reset pairs | QUIC dropped flows | Gateway CONNECTs |
| --- | --- | --- | --- | --- | --- |
| 2022 | hold-inproc-tcp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2022 | hold-inproc-udp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2022 | redirect-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2022 | hold-inproc-tcp-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2022 | redirect-inproc-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2022 | leakcheck-inproc | PASS_RESTRICTED_CASE | 3 / 3 / 3 | 0 | 0 |
| 2022 | concurrency-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2022 | quic-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 3 | 0 |
| 2022 | concurrency-inproc-cacheoff | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2022 | hold-inproc-async-tcp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2022 | hold-inproc-async-udp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2022 | redirect-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2022 | redirect-inproc-async-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2022 | concurrency-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2022 | leakcheck-inproc-async | PASS_RESTRICTED_CASE | 3 / 3 / 3 | 0 | 0 |
| 2022 | quic-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 3 | 0 |
| 2025 | hold-inproc-tcp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2025 | hold-inproc-udp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2025 | redirect-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2025 | hold-inproc-tcp-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2025 | redirect-inproc-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2025 | leakcheck-inproc | PASS_RESTRICTED_CASE | 3 / 3 / 3 | 0 | 0 |
| 2025 | concurrency-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2025 | quic-inproc | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 3 | 0 |
| 2025 | concurrency-inproc-cacheoff | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2025 | hold-inproc-async-tcp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2025 | hold-inproc-async-udp | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 0 |
| 2025 | redirect-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2025 | redirect-inproc-async-repeat | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 3 |
| 2025 | concurrency-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 0 | 25 |
| 2025 | leakcheck-inproc-async | PASS_RESTRICTED_CASE | 3 / 3 / 3 | 0 | 0 |
| 2025 | quic-inproc-async | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 3 | 0 |

Each leakcheck deliberately delays selected ownership past the 100 ms hold.
The three A clients time out direct, are identified later, receive checked RST
pairs and individually report WSAECONNRESET; the B clients still echo. This proves
the exercised post-hoc termination path. It does not prevent the intentionally
leaked bytes. Native lookup, worker and BFE cleanup errors were zero in these cases.

All 11 split poll cases on each OS again reached their expected status (10 pass,
one characterized conservative tuple-reuse rejection). That rejection remains
intentional application disruption, not production-safe reuse.

## Subscription result: version-dependent representation, still late

With a 2000 ms hold and 1500 ms post-collection drain:

| OS | Subscribe2 raw callbacks / stored events | Subscribe3 raw callbacks / stored events | Subscribe4 raw callbacks / stored events |
| --- | --- | --- | --- |
| 2022 | 0 / 26 | 0 / 61 | 25 / 25 |
| 2025 | 0 / 26 | 0 / 34 | 24 / 24 |

Controlled layer-48 Subscribe4 callback samples arrived about 997–1001 ms after
occurrence on Server 2022 and 995–1006 ms on Server 2025. This remains unsuitable
for a short hold even if its direction representation is resolved.

The new raw fields narrow the earlier field-read hypothesis. For the same event
identity, callback EVENT5 and stored Enum5 agree, while Enum3 returns another
direction/loopback representation. One Server 2022 exact identity (FILETIME
is a decimal string to preserve all 64 bits):

```json
{"event_filetime":"134385142798605584","local_ip":"127.0.0.1","local_port":63514,"remote_ip":"127.0.0.1","remote_port":63511,"protocol":6,"app_path":"\\device\\harddiskvolume6\\a\\_temp\\wfp-divert-bin\\app-a.exe","layer_id":48,"filter_id":79701,"callback5_direction_raw":14593,"callback5_is_loopback_raw":1,"enum5_direction_raw":14593,"enum5_is_loopback_raw":1,"enum3_direction_raw":0,"enum3_is_loopback_raw":0}
```

Consequently, an ABI/memory-corruption explanation is not established. The observed
version-dependent representation needs semantic clarification. The current
validator deliberately leaves values outside documented FWP_DIRECTION 0/1
unusable; no guessed normalization was used to authorize packets. Raw callbacks
without usable target ownership now make negative controls inconclusive.

## ALE endpoint shadow: available, but not original-app ownership

Both runners resolved the native exports, completed 6–7 queries per shadow case,
and reported zero native errors/truncation. Query totals were 16.1–22.1 ms for
6 TCP queries and 17.5 ms for 6–7 UDP queries. These short, mixed warm/cold samples
must not be treated as an independent speed benchmark.

All four shadow cases were inconclusive. Returned controlled tuples had appId
`System`, failing the exact original app path checks. The TCP records also repeated
one endpoint ID across different client tuples. For example:

```jsonl
{"os":"2022","endpoint_id":772,"local_ip":"127.0.0.1","local_port":64157,"remote_ip":"127.0.0.1","remote_port":64154,"protocol":6,"app_path":"System"}
{"os":"2022","endpoint_id":772,"local_ip":"127.0.0.1","local_port":64158,"remote_ip":"127.0.0.1","remote_port":64154,"protocol":6,"app_path":"System"}
{"os":"2025","endpoint_id":518,"local_ip":"127.0.0.1","local_port":58066,"remote_ip":"127.0.0.1","remote_port":58063,"protocol":6,"app_path":"System"}
```

The probe was never routing authority. The cause of these app/identity observations
is not established; the next isolation checks would be a no-diversion control and
external-address topology, rather than treating System as the selected app or
relaxing identity checks.

## Decision

Prefer asynchronous, bounded, batched stored-event lookup as the next experimental
baseline because it reduced already-decided packet stalls while preserving the
tested authority and control checks. Keep measuring fresh snapshot creation and
filter capability results; a faster first-decision source is not yet proven.
Subscriptions and live endpoint enumeration do not currently replace the polled
source under this topology and validator.

These are finite, same-host IPv4, Server 2022/2025 observations. Desktop Windows,
external routing, production tuple reuse, receive-backlog bounds, RPC cancellation,
long-lived load and UDP forwarding remain unqualified.
