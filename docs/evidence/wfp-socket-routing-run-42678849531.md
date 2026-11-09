# SOCKET routing after wakeup synchronization

Measured 2026-11-09 in [run 42678849531](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678849531),
source `c1ea56e7561c78b4e348d790f1894cf1cff00231`, Actions merge
`31cf48c50ea5f30d7a3baf1e2976e989eabf4636`, source tree
`234807a3a5b3b59e9ade687d3cc79c526df1c405`.
The [aggregate record](wfp-socket-routing-run-42678849531-aggregate.json)
retains every case, including the failed audit and slower passing comparison.

All 732 controlled clients complete their expected responses: 720 normal nonce
echoes and twelve fault-control clients, including six checked selected resets.
Seventeen of eighteen cases pass all checks. Server 2025 SOCKET burst round 1
remains failed because four client tuples have conflicting native application
candidates. Native WFP remains the default; this is an opt-in research prototype.

All four SOCKET sequential cases pass: 160/160 client echoes, exact PID/path/
creation/generation/deadline attestation and independent native references.
Selected-app attempt-to-echo p50 is 23.4123–32.3464 ms across those cases versus
42.9262–57.4168 ms for WFP. Burst performance is not uniformly better: the passing
Server 2025 round 2 selected p50/p95 is slightly worse with SOCKET.

## Exact jobs, artifacts and checks

| OS | Routing job | Outcome | Artifact | Digest |
| --- | --- | --- | --- | --- |
| Server 2022, build 20348 | [129367578763](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678849531/job/129367578763) | Success, 9/9 cases | [13700889085](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678849531/artifacts/13700889085) | `sha256:675ad977131034875e43e2dcea41dbec858d0593b67ff9a18725edd9185bf571` |
| Server 2025, build 26100 | [129367578984](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678849531/job/129367578984) | Failure, 8/9 cases | [13702002047](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678849531/artifacts/13702002047) | `sha256:0cbc0514294e18d101a7a3e1c9760faad5d27c4ec2fd7487c04127aa541796dc` |

Both downloaded ZIPs contain exactly aggregate-evidence.json, ci-summary.json,
environment.json and driver-manifest.json. All eighteen projected case summaries
exactly match the corresponding console aggregate. New evidence contains only
fixed labels, counts, relative durations and public build metadata; no actual
process IDs, image paths, endpoint IDs, tuples, absolute clocks or credentials.

Both official signed WinDivert 2.2.2 MSVC builds, the actual-DLL helpers, model
job and both unchanged SOCKET observation jobs pass. Standard
[CI run 42678848871](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42678848871)
passes all eight jobs, including WOW64 and both installer variants. The prior
WOW64 TLS certificate failure did not recur; no production Rust files changed.
The broader PoC remains red for its older unqualified comparisons and the one
new native-audit conflict case described here.

Local checks pass 132 Python tests with real PowerShell and loopback networking,
portable native helpers with `-Werror`, the deterministic lost-notification
regression, Windows x64 COFF compilation, PowerShell parsing and separate review.
The COFF check uses Clang 19 with the SDK's documented STL compatibility override;
the actual MSVC runs are the definitive Windows compiler checks.

## Compared behavior

Each OS runs two rounds, reversing source/profile order in round 2. Each short
case launches twenty fresh selected/other-app pairs sequentially. Each burst
releases fifty already-bound, ready clients from a shared start barrier.
Selected clients must use the translating bridge and real authenticated
Gateinto CONNECT path; the other app stays direct. Passing cases verify exact
CONNECT destination/count, nonce echo and nonselected negative controls.

Both sources run the same separate native WFP reference collector at 100 ms,
with a 1100 ms post-engine drain. It starts before the engine and restores BFE
options only after the engine finishes restoration. This is equal experimental
background load, not a claim about uninstrumented production CPU cost.

The native audit upper bound is the first exact generation's normal proxy/direct
decision, sampled before flush and first reinjection. Drops, later decisions and
echo cannot create or extend that boundary. Full original image path, tuple,
outbound layer 48, attempt lower bound and measured clock uncertainty remain
required. It is a pre-reinjection audit, not proof that the stored-event timestamp
precedes NETWORK capture. The separate SOCKET routing attestation still requires
its kernel CONNECT event no later than the captured first packet.

## Complete outcome

| Case group | Server 2022 | Server 2025 |
| --- | --- | --- |
| WFP sequential, rounds 1/2 | Both pass, 80/80 echoes/references | Both pass, 80/80 echoes/references |
| SOCKET sequential, rounds 1/2 | Both pass, 80/80 echoes/references | Both pass, 80/80 echoes/references |
| WFP bursts, rounds 1/2 | Both pass, 100/100 echoes/references | Both pass, 100/100 echoes/references |
| SOCKET bursts, rounds 1/2 | Both pass, 100/100 echoes/references | 100/100 echoes; round 1 audit 46/50 unambiguous and fails; round 2 passes |
| SOCKET delayed ownership | Pass, 6/6 expected clients, 3 selected resets | Pass, 6/6 expected clients, 3 selected resets |

All 372 SOCKET clients, including the fault controls, have expected process
identity attestation. Normal SOCKET cases report no unattributed, leaked or
reset flows; routing snapshot create/enum/destroy work is zero. The fault cases
each deliberately report three timeout-direct flows, three late leaks and three
checked resets. Both nonselected triplets echo without reset. A late identity
never turns an already direct connection into a proxy connection.

## Application latency

Values below are milliseconds, WFP / SOCKET. They measure client attempt to nonce
echo after bind/barrier release, before local attempt-record flush and connect.
They include that logging, TCP/proxy/fixture work, exclude process launch and
barrier waiting, and are not ownership API durations. Percentiles remain per
case; no percentile pooling or cross-run average is used.

| OS | Round | Profile | Selected p50 | Selected p95 | Direct p50 | Direct p95 |
| --- | --- | --- | --- | --- | --- | --- |
| 2022 | 1 | Short | 57.4168 / 26.1028 | 139.3655 / 38.3779 | 12.5764 / 0.8930 | 78.6986 / 1.0796 |
| 2022 | 2 | Short | 48.5204 / 25.0134 | 134.7347 / 38.8287 | 16.1023 / 0.8675 | 83.9237 / 1.0000 |
| 2025 | 1 | Short | 42.9262 / 32.3464 | 58.7536 / 40.3279 | 12.6868 / 1.2807 | 14.3782 / 1.4680 |
| 2025 | 2 | Short | 44.2453 / 23.4123 | 58.2128 / 38.2215 | 13.4206 / 1.3701 | 15.9060 / 1.6536 |
| 2022 | 1 | Burst | 325.8109 / 88.0036 | 328.5526 / 92.5776 | 57.9705 / 18.8086 | 63.0664 / 28.5830 |
| 2022 | 2 | Burst | 274.4236 / 90.8609 | 291.5138 / 94.6229 | 36.1848 / 18.8184 | 40.0914 / 28.7100 |
| 2025 | 2 | Burst | 143.6290 / 146.7643 | 168.0692 / 173.0354 | 67.4262 / 33.6220 | 74.4488 / 52.6759 |

The last passing row is a retained regression for selected traffic, despite
lower direct latency. Removing native routing queries does not guarantee lower
end-to-end application latency under every concurrent workload.

The failed Server 2025 burst round 1 is excluded from qualified comparisons.
Its raw aggregates remain: selected p50/p95 is 114.2151/173.1202 ms versus WFP
141.1520/165.5741 ms, and direct p50/p95 is 38.5261/45.0096 versus
48.7074/54.0991 ms. Successful echoes and favorable medians cannot make its
failed audit pass.

## Wakeup repair and prior failures

The [preceding pinned-owner run](wfp-socket-routing-run-42674843682.md) had
sub-millisecond median image readiness but near-one-second application offsets,
three failed SOCKET short cases and a passing short case with 1034.7 ms maximum
client latency. The producer could notify between the consumer's predicate
check and entry into wait because publication did not hold the wait mutex.

The live revision publisher now holds that same Engine mutex while publishing,
then notifies after unlocking. A deterministic regression fails with the old lockless publisher
and passes with the repair. NETWORK overflow poisoning moves outside the Engine
mutex to avoid lock inversion, while receive errors immediately block further
SOCKET sends. Quarantine, owner and SYN checks remain unchanged; no periodic
polling workaround is used.

In the four current SOCKET short cases, median identity-ready to engine-apply
offset is 0.0163–0.0403 ms and maximum is 0.0467–0.0730 ms. First-decision maximum
is 0.6164–1.3990 ms. These populations include fixture connections (sixty engine
flows per case), so they are separate from the forty original client samples.
The earlier one-second stall does not recur in these samples. Short selected
client maximum is now 38.8974–41.8730 ms.

The [initial routing failure](wfp-socket-routing-run-42613174975.md) and
[post-injection conflict diagnostics](wfp-socket-routing-run-42672188645.md)
remain evidence. Later different endpoints are quarantined only after a known
successful own injection start and never replace the original proof. There is
no process-ID whitelist. Each normal case uses one distinct quarantined endpoint
across its later target-tuple observations, without registering it as an
authoritative original endpoint.

## Unresolved native-audit conflict

Server 2025 burst round 1 has 50/50 client echoes and complete original SOCKET
PID/path/creation/deadline attestations. Native polling has an original-app
candidate for every client, but four client tuples also have otherwise-qualified
complete outbound layer-48 events with a different app path inside the audited
window. The audit therefore reports 46/50 unambiguous matches and remains FAIL.
These are four affected client tuples, not a measured count of conflicting
records. No exact other process, path or endpoint is published.

The aggregate cannot identify that other application, establish stale or
reinjected provenance, or determine whether clock uncertainty overlaps a boundary.
It does not prove that an original client was routed as another app, and the
independent audit is not discarded. The later gateway-count validation is not
reached for that failed case, so it receives no complete-case qualification.
Further provenance evidence is required before claiming the ambiguity resolved.

## Limits and recommendation

Keep native WFP as the default. SOCKET is a faster controlled short-connection
prototype in these samples, with one unresolved independent audit and a slower
passing selected burst comparison. It still buffers the first packet. Direct
other-app traffic also pays that first decision, although the measured delay is
much lower in the short cases.

The conservative policy rejects initial SYNs after quarantine, including valid
retransmissions with the same sequence number. Ordinary packet-loss and reuse
behavior is therefore unqualified. NETWORK packets have no SOCKET endpoint
cookie, and kernel queue loss is not exposed. Missing lifecycle events, arbitrary
PID/tuple reuse, immediate process reclamation, desktop Windows, external
routing, sustained load and UDP forwarding remain unqualified. Retained child
handles and fresh IPv4 loopback tuples limit these results.

Timeout-direct remains a leak tradeoff: selected bytes reach the target before
the later reset in the controls. Query count zero measures routing snapshot work
only; independent audit, process-image queries, queueing, proxy and BFE service
CPU are separate costs. No total-system CPU saving or production guarantee is
established.
