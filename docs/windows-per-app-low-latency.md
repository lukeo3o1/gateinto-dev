# Lower-latency Windows application ownership research

Updated: 2026-11-09. Experiment: PR #95; latest measured source `c1ea56e`.

The latest [actual routing comparison](evidence/wfp-socket-routing-run-42678849531.md)
completes all 732 expected client responses on Server 2022/2025. Seventeen of
eighteen cases pass: one SOCKET burst remains failed for four conflicting native
application references. All four SOCKET short cases pass, with selected-app
attempt-to-echo p50 of 23.41–32.35 ms versus 42.93–57.42 ms for WFP. This is
application latency through the real proxy, not an observation offset.

Keep WFP as the default. A passing Server 2025 burst is slightly slower for
selected traffic with SOCKET, the independent audit conflict is unresolved, and
the conservative quarantine policy rejects retransmitted initial SYNs. Ordinary
loss/reuse behavior remains unqualified. The earlier
[observation-only run](evidence/wfp-socket-run-42497668177.md) established fast
identity readiness but did not itself qualify routing; first-packet buffering
is still required.

Earlier [stored-event comparisons](evidence/wfp-divert-run-42468677635.md) show fewer
returned rows with destination filtering, but no repeatable latency improvement.
Attempt 1 passed all 27 non-shadow in-process cases per OS on Server 2022/2025,
including eight scoped-snapshot cases. The completed Server 2022 rerun also passed
all eight snapshot cases, yet destination first-decision latency regressed sharply.
Fresh snapshot creation remains both dominant and variable. Keep destination/500
ms and destination/5 ms optional experiments; retain the legacy/500 ms default.

Separate post-echo ALE controls found the original application for all six TCP
and all six UDP clients per OS. Held-first-packet shadow cases still had zero
qualifying observations. Neither established-socket query speed nor this control
qualifies ALE for admission decisions. The existing TCP feasibility conclusion
stays restricted to the runs in [the evidence review](windows-per-app-feasibility.md).

## What is established

The earlier [asynchronous comparison](evidence/wfp-divert-run-42356168781.md)
reduced 50-client decided-direct p95 from 17.3 to 2.7 ms on Server 2022 and from
32.9 to 12.0 ms on Server 2025. First-decision latency did not consistently improve;
all 16 non-shadow in-process cases passed per OS. Its ALE shadow observations
returned System rather than the original app. Those findings remain specific to
that revision and topology.

The split poll implementation measured about 7.1–9.5 ms mean elapsed enumeration
cost. In-process lookup included roughly 14–20 ms calls in the inspected run.
Those are elapsed RPC/query measurements, not CPU measurements. The original
in-process first-decision metric omitted enumeration; complete small TCP traces
reconstruct to p50 about 25.7–33.1 ms. See the
[audit and retained QPC excerpts](evidence/wfp-divert-run-42348888370.md).

That run does not demonstrate an in-process speedup. It also shows a structural
problem: a single worker waited for BFE enumeration while already-decided packets
and other pending-flow deadlines waited behind it.

## Measured WinDivert SOCKET observation

[Run 42497668177](evidence/wfp-socket-run-42497668177.md), source `2dd799e`, used
separate SOCKET and NETWORK SNIFF/RECV_ONLY handles, with native stored-event
polling as an independent reference. Two broad CONNECT controls and six scoped
TCP/UDP cases covered 500 ms live holds, short sequential clients and 50-process
bursts. All eight cases passed on each OS: 204 clients per OS, 408 total, with
no missing/mismatched identities, ambiguity or reported collector errors.

Short sequential cases each used 40 fresh clients. These p50 values compare
userspace image-identity readiness and native poll receipt with the same first
observed NETWORK capture, in milliseconds:

| OS | Transport | Image identity ready − capture | Native poll receipt − capture |
| --- | --- | --- | --- |
| Server 2022 | TCP | 0.0919 | 21.4347 |
| Server 2022 | UDP | 0.1011 | 20.8902 |
| Server 2025 | TCP | 0.0989 | 27.8970 |
| Server 2025 | UDP | 0.1204 | 27.4197 |

These are observation-time differences, not API-call durations or end-to-end
routing latency. Kernel event time, userspace receipt and image readiness remain
separate. Image readiness preceded capture for only 21/408 clients: 12 Server
2022 TCP-burst clients and nine Server 2025 TCP-burst clients. The source is a
promising event-driven alternative for the next controlled routing experiment;
no packet admission, blocking, reinjection or proxy routing was tested here.

The [initial run 42496744881](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881)
had 384 successful echo/native/packet matches but no SOCKET observations. Its
SOCKET filter incorrectly included `ip`, which the pinned WinDivert 2.2.2 DLL
evaluates from a parsed packet header absent at SOCKET. A Windows DLL self-test
reproduced that false predicate and accepted the corrected scoped and broad
CONNECT predicates; the corrected run then delivered all controlled events.

Clients explicitly bound IPv4 loopback tuples and the harness retained child
process handles for creation-time ground truth. This does not qualify auto-bind,
immediate process-object reclamation, arbitrary PID/tuple reuse, external routing,
IPv6, desktop Windows or sustained load. Driver queue loss is not observable.
The native WFP Subscribe2/3/4 findings remain unchanged. This observation run
used no SOCKET routing authority; later opt-in TCP routing is evaluated
separately below.

## Measured SOCKET TCP routing

[Run 42678849531](evidence/wfp-socket-routing-run-42678849531.md), source
`c1ea56e`, compares the default async/cache-on WFP source and opt-in SOCKET in two
balanced rounds per OS. Each short case has forty sequential clients; each
burst synchronizes fifty already-bound clients. Independent native WFP auditing
uses the same 100 ms interval and 1100 ms drain for both sources. The audit checks
the original app before the first normal routing decision/reinjection; SOCKET's
own kernel event must separately precede packet capture.

Passing short cases, WFP / SOCKET attempt-to-echo milliseconds:

| OS / round | Selected p50 | Selected p95 | Direct p50 | Direct p95 |
| --- | --- | --- | --- | --- |
| 2022 / 1 | 57.4168 / 26.1028 | 139.3655 / 38.3779 | 12.5764 / 0.8930 | 78.6986 / 1.0796 |
| 2022 / 2 | 48.5204 / 25.0134 | 134.7347 / 38.8287 | 16.1023 / 0.8675 | 83.9237 / 1.0000 |
| 2025 / 1 | 42.9262 / 32.3464 | 58.7536 / 40.3279 | 12.6868 / 1.2807 | 14.3782 / 1.4680 |
| 2025 / 2 | 44.2453 / 23.4123 | 58.2128 / 38.2215 | 13.4206 / 1.3701 | 15.9060 / 1.6536 |

These client clocks exclude process launch and barrier waiting, but include
local attempt-record flush, TCP and proxy/fixture work. No percentile pooling is
used. Source decision distributions also include fixture flows, so they must not
be read as one observation per original client.

The passing Server 2025 burst round 2 is a counterexample to uniform speedup:
selected p50/p95 becomes 146.7643/173.0354 ms with SOCKET versus
143.6290/168.0692 ms with WFP, while direct improves. Server 2025 burst round 1
echoes all fifty clients and matches all SOCKET process attestations, but four
tuples have additional different-app native candidates in the audit window.
That case stays failed and is excluded from qualified timing comparisons. The
aggregate cannot identify those other applications or their provenance.

The implementation first failed on
[all SOCKET routing cases](evidence/wfp-socket-routing-run-42613174975.md).
[Diagnostics](evidence/wfp-socket-routing-run-42672188645.md) established later
System CONNECT metadata during own successful injection. Pinning the earlier
owner and quarantining later, previously unbound endpoints repaired the burst
path without a PID whitelist. A
[following run](evidence/wfp-socket-routing-run-42674843682.md) still had short
failures and roughly one-second identity-ready-to-apply tails. The deterministic
lost-notification repair now publishes under the consumer's wait mutex; current
short maxima are 0.0467–0.0730 ms for that offset, without periodic polling.
All failed runs and the slow passing short case remain evidence.

Both delayed-identity controls verify timeout-direct, six selected late leaks
and six client-observed resets in total. Reset cannot undo those bytes or turn
an already direct flow into proxy. Query count zero excludes only native WFP
routing snapshot work; reference collection and process-image queries still cost
work. No total-system CPU reduction, kernel-loss bound or production guarantee
is established. Standard CI, model and observation jobs pass; the broader PoC
is red, including the unresolved new audit case.

## Measured scoped snapshots

Run 42468677635 attempt 1 compared four async/cache-on profiles in two rounds,
reversing profile order in the second round. Each used 50 TCP redirect clients;
all eight cases passed per OS with the existing ownership, echo and CONNECT checks.
Attempt 2 repeated the Server 2022 matrix. First-packet decision p95, in milliseconds:

| Scope | Pre-capture window | Server 2022, attempt 1 rounds 1 / 2 | Server 2025, attempt 1 rounds 1 / 2 | Server 2022, attempt 2 rounds 1 / 2 |
| --- | --- | --- | --- | --- |
| Legacy | 500 ms | 41.68 / 57.64 | 52.88 / 52.92 | 38.23 / 48.32 |
| Legacy | 5 ms | 34.49 / 35.34 | 44.33 / 42.01 | 32.45 / 29.95 |
| Destination | 500 ms | 35.06 / 37.68 | 42.33 / 42.49 | 102.88 / 30.49 |
| Destination | 5 ms | 34.73 / 33.40 | 40.15 / 46.58 | 134.67 / 441.61 |

In attempt 1, destination/5 ms returned 91–96% fewer stored-event rows than the corresponding
legacy/500 ms cases. Creation still consumed about 97% of combined-profile phase
elapsed time, averaging 13.5–16.9 ms per create call. Filtering removes decoding
work but does not remove the fresh-snapshot requirement. Improvements did not cover
every packet tail: Server 2022 round 1 decided-direct p95 rose from 4.25 to 5.00 ms.
These are two same-host rounds, without a total-system CPU or production claim.

The completed Server 2022 rerun changed the performance conclusion. Legacy/500 ms
first-decision p95 was 38.23/48.32 ms; destination/500 ms reached 102.88 ms in round
1, while destination/5 ms reached 134.67/441.61 ms across its rounds. One create
call took 235.11 ms, and create time occupied 549.79 ms of 550.92 ms query busy
time in the combined second round. Returned rows were again lower, by 96–99%
for the combined profile, and all eight snapshot cases passed their functional
checks. Reducing returned rows does not control this RPC tail.

Neither destination profile is established as faster or more reliable. Keep both
optional and retain legacy/500 ms as the implemented default. A 5 ms window also
needs clock, load and event-availability qualification. Attempt 2 on Server 2025
failed its dependency download with HTTP 504 and produced no traffic result.

## Implemented comparisons

| Variant | Implementation and intended benefit | Evidence boundary |
| --- | --- | --- |
| Inline, cache off | `--lookup-mode inline --filter-cache off`; freshly enumerate on the packet worker, preserving the corrected decision clock. | Baseline call counts, phase cost, held/direct/proxy latency. |
| Inline, cache on | Skip only previously rejected filter capability patterns within the same collector, separating protocol and single/multiple local-port conditions. | Rejection codes, cache hits and actual reduction in create calls. Generic INVALID_PARAMETER is deliberately not cached. |
| Async, cache on | One lookup thread and at most one queued/running/completed request; packet worker can forward decided packets and expire holds while lookup runs. Exact-tuple indexing avoids rescanning every returned event for every flow. | Compare latency tails and caller CPU with the same TCP/UDP, 50-client, delayed-evidence, QUIC and reset cases. Handoff can add first-decision latency. |
| Destination scope | `--enum-scope destination` emits unique, ANDed condition keys for values shared by pending subjects; broader fallbacks retain exact software validation. | Compare with legacy scope at both 500 ms and experimental 5 ms pre-capture windows. Two reversed-order rounds have executed; sustained-load and clock qualification remain open. |
| ALE endpoint shadow | Query native live endpoint properties while packets are held; report full tuple, appId and endpointId without using them for routing. | Export availability, correct app paths/tuples, complete query intervals before release, per-phase cost and UDP coverage. |
| Live ALE control | `--engine endpoint-control --client-hold-ms 500` compares post-echo live sockets with native stored-event references before any packet interception. | Correct original-app observations in established TCP/UDP sockets do not prove held-first-packet availability. |
| SOCKET observation | SNIFF/RECV_ONLY SOCKET CONNECT metadata plus generation-checked image queries, compared with an independent NETWORK observer and native WFP reference. | All controlled cases passed; userspace identity usually followed capture. Buffered routing and production lifecycle coverage remain untested. |

The capability cache stores rejected query patterns, never ownership answers.
Fresh net-event enumerators remain necessary: Microsoft's
[Enum0 remarks](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventenum0)
state that an enumerator returns events logged before its creation. Keeping one
exhausted handle would miss subsequent flows.

Async results retain each requested tuple, capture QPC and internal generation.
Incomplete/error snapshots are discarded. The packet worker revalidates the exact
subject and the real current deadline before committing any action. Busy queries
suppress retry wakeups while preserving actual deadlines and packet/result
notifications, avoiding a zero-wait retry loop. Shutdown joins the lookup thread
before closing its BFE session or restoring global options.

These mechanisms do not make synchronous RPC cancellable. Limits checked between
calls cannot interrupt a single blocked call; shutdown still depends on that call
returning. The receive backlog and production-safe socket reuse remain unqualified.

## A distinct native source: live ALE endpoints

Microsoft documents user-mode
[FwpsAleEndpointEnum0](https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointenum0)
in `fwpsu.h` / `Fwpuclnt.lib`. Its
[endpoint properties](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0)
contain application ID, IPv4/IPv6 tuple, protocol and endpoint ID. This is a
native WFP source rather than an IP Helper or PID-table lookup. The
[enumeration template](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_enum_template0)
can restrict subnet, port and protocol.

`ale-endpoints.cpp` dynamically resolves the documented exports, queries a
controlled IPv4 target and deep-copies data before freeing native arrays. It emits
endpoint records only after enumeration and destruction finish successfully.
Failed, truncated or over-budget queries publish no endpoint evidence. A bounded
output limit fails explicitly rather than dropping records silently.

`--ale-probe` runs it beside selected in-process TCP/UDP cases. The report requires
each controlled client to have one exact native app/tuple/endpoint identity in a
complete query whose entire measured interval is after capture and before the
packet decision. Ambiguity, missing data, API failure or observations only after
release produce `INCONCLUSIVE_ALE_ENDPOINT_PROBE`. Routing still uses net events;
the report explicitly says `routing_authority: false`.

The separate live control runs before any WinDivert case and launches neither
packet engine. Both apps echo and keep fresh sockets open for 500 ms, with the
complete ALE query confined to the post-echo interval. In run 42468677635 attempt
1, each TCP/UDP case on each OS had six clean native references and six exact
original-app ALE matches, with no System app or shared-endpoint groups. Both
Server 2022 controls repeated that result in attempt 2.

| Established-socket ALE mean query time | TCP | UDP |
| --- | --- | --- |
| Server 2022, attempt 1 | 1.12 ms | 1.57 ms |
| Server 2025, attempt 1 | 1.67 ms | 2.34 ms |
| Server 2022, attempt 2 | 1.95 ms | 1.96 ms |

These are complete query costs, not first-packet admission latency. The two
held-first-packet shadow cases per OS remained inconclusive, with zero qualifying
observations while held. The live control changes both socket lifecycle and
interception, so it does not establish that WinDivert caused the earlier anomaly.
Copied raw endpoint diagnostics remain local. Published layout sizes and offsets
are compiler metadata; no guessed identity normalization is used.

Endpoint properties provide no event timestamp, direction or packet-visible
endpoint ID. Complete enumeration is not a documented atomic snapshot, and an
endpoint ID alone cannot bind a held packet to a socket generation. TCP availability
before connection completion, unconnected UDP remote tuples, close/reuse and
client Windows builds all need runtime evidence. These gaps must be resolved before
considering this source for admission decisions.

## Subscription investigation

The source-level Subscribe2/3/4 callback pairings use EVENT3/4/5 respectively.
Raw records now retain direction and BOOL integers, profiles, layer/filter IDs,
callback sequence and entry QPC. Ready records include pointer width and structure
sizes/offsets; subscription start/stop are retained. Subscribe3/4 also enumerate
the same stored-event window through Enum3 and Enum5 for identity/field comparison.
Enum5 records are diagnostic and cannot authorize a packet.

New comparison cases allow 1500 ms callback drain after normal collection, with a
2000 ms packet hold. Drain affects diagnostic completeness after the test traffic;
it cannot retrospectively make a late event meet a packet deadline. Unknown
direction values remain unusable rather than being reinterpreted as undocumented
direction codes.

The documented
[engine options](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ne-fwpmtypes-fwpm_engine_option)
contain no callback batching/flush interval. PACKET_QUEUING concerns inbound/forward
IPsec load distribution. Subscription flags are
[unused](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_subscription0).
There is no documented knob here that establishes a low-latency delivery bound.

## Measurements and acceptance

The workflow compares Windows Server 2022 and 2025 independently. Neither is
desktop Windows 10/11. New Actions artifacts and Git evidence contain aggregate
case counts, status and relative latency statistics only. Request identities,
raw paths/tuples and original capture/decision QPC remain in restricted local
evidence. Historical artifacts retain what their original runs published.

Evaluate each OS and case separately:

- Keep the per-client native authority, exact tuple/path, no wrong-app redirect,
  correct CONNECT and echo/reset/drop checks. Raw callbacks without usable target
  ownership cannot make a negative control pass.
- Compare first-decision and held/direct/proxy latency distributions, not just
  enumeration duration. A faster query is insufficient if handoff or packet queues
  worsen tail latency.
- Inspect create/enum/destroy/process elapsed time, returned-event count, cache
  rejection/hit counts, query backpressure and stale/incomplete results.
- Query-thread `GetThreadTimes` measures only the caller's kernel/user CPU. It
  excludes BFE service CPU, packet worker and bridge CPU; elapsed `busy_share` is
  query occupancy, not total-system CPU utilization.
- Keep ALE shadow cases separate from performance A/B comparisons because the
  extra sampler adds BFE load. Its observed latency is query receipt time rather
  than event occurrence time.

Timeout-direct remains a leak tradeoff: an unknown selected connection can be
released before attribution, and a later reset cannot undo transmitted bytes.
Dropping all unknown traffic would affect other apps. Faster observation alone
does not prove either zero leakage or universal noninterference.

Local helper checks and the Server 2022/2025 comparisons have executed. The
[snapshot report](evidence/wfp-divert-run-42468677635.md) separates both completed
Server 2022 attempts from the Server 2025 rerun's infrastructure failure.
The [SOCKET observation report](evidence/wfp-socket-run-42497668177.md) records
both successful observation jobs; the
[routing report](evidence/wfp-socket-routing-run-42678849531.md) retains seventeen
passing cases and one unresolved native audit conflict. Standard CI and the
model job passed. The remaining Windows experiment jobs stay red for that audit,
subscription cases, short-hold Security
UDP, unrecognized native-drop callbacks and first-packet ALE shadows. Fresh
snapshot creation remains the main measured query cost. No CPU saving, safe
production reuse or general first-packet delivery bound has been established.
