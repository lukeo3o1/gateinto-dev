# Lower-latency native WFP ownership research

Date: 2026-11-07. Experiment baseline: PR #95, head `e3336bd`.

The strongest next candidates are asynchronous stored-event lookup with measured
filter capability caching, and a separate live ALE endpoint probe. Neither has
new Windows runtime results yet. The existing TCP feasibility conclusion remains
restricted to the runs in [the evidence review](windows-per-app-feasibility.md).

## What is established

The split poll implementation measured about 7.1–9.5 ms mean elapsed enumeration
cost. In-process lookup included roughly 14–20 ms calls in the inspected run.
Those are elapsed RPC/query measurements, not CPU measurements. The original
in-process first-decision metric omitted enumeration; complete small TCP traces
reconstruct to p50 about 25.7–33.1 ms. See the
[audit and retained QPC excerpts](evidence/wfp-divert-run-42348888370.md).

That run does not demonstrate an in-process speedup. It also shows a structural
problem: a single worker waited for BFE enumeration while already-decided packets
and other pending-flow deadlines waited behind it.

## Prepared comparisons

| Variant | Implementation and intended benefit | Evidence still required |
| --- | --- | --- |
| Inline, cache off | `--lookup-mode inline --filter-cache off`; freshly enumerate on the packet worker, preserving the corrected decision clock. | Baseline call counts, phase cost, held/direct/proxy latency. |
| Inline, cache on | Skip only previously rejected filter capability patterns within the same collector, separating protocol and single/multiple local-port conditions. | Rejection codes, cache hits and actual reduction in create calls. Generic INVALID_PARAMETER is deliberately not cached. |
| Async, cache on | One lookup thread and at most one queued/running/completed request; packet worker can forward decided packets and expire holds while lookup runs. Exact-tuple indexing avoids rescanning every returned event for every flow. | Compare latency tails and caller CPU with the same TCP/UDP, 50-client, delayed-evidence, QUIC and reset cases. Handoff can add first-decision latency. |
| ALE endpoint shadow | Query native live endpoint properties while packets are held; report full tuple, appId and endpointId without using them for routing. | Export availability, correct app paths/tuples, complete query intervals before release, per-phase cost and UDP coverage. |

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
desktop Windows 10/11. Separate artifacts preserve case status, source evidence,
request IDs, original capture/decision QPC and complete native metrics.

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

Current checks are local Python/portable-model tests and Windows object compilation.
New runtime speed, resource-use or reliability claims require the prepared CI
comparisons to execute and retain their evidence.
