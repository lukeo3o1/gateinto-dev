# SOCKET routing conflict diagnostics

Measured 2026-11-09 in [run 42672188645](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42672188645),
source `59b3cf97df7a5dc4106534d3910001d147847727`, Actions merge
`59ea3fa66daf13a711a8eb5e25bf482ed871c3ce`. This retry has exactly the same tree
as diagnostic source `66142594102f10f1752ba038297fa7070852c580`:
`fcdbd9429d4718baada2bdfe1cf31a26ec7677a2`.
The [aggregate record](wfp-socket-routing-run-42672188645-aggregate.json)
retains all nine Server 2022 cases. Server 2025 did not start in this run.

The diagnostic run identifies post-injection metadata conflicts that prevent
successful SOCKET routing. It does not qualify routed SOCKET performance.
The [initial failed comparison](wfp-socket-routing-run-42613174975.md) remains
part of the evidence.

## Execution and infrastructure

Server 2022 routing job [129348780147](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42672188645/job/129348780147)
produced artifact [13699791082](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42672188645/artifacts/13699791082),
digest `sha256:96c1d7d60c31cfcc2e5ac00cea731326a5631e5537b289b7a8d0a8f3e242237c`.
The downloaded ZIP contains only the four allowlisted aggregate/build JSON files;
all nine case summaries exactly match the projected console aggregate.

The first diagnostic [run 42671669007](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42671669007)
failed before creating any jobs or artifacts. GitHub's run annotation reports
`Internal server error`, correlation ID
`d4a27cee-3283-43d7-ab54-212e0c611c96`. Its retry API returned
`This workflow run cannot be retried`. An identical-tree commit triggered this
new run. It executed the two Server 2022 experiment jobs but also reported an
internal server error, correlation ID `597216d4-2f99-43aa-93c3-dff73bd0daff`;
the other matrix jobs, including Server 2025 routing, never appeared.

The parallel standard workflow's Windows release build, WOW64 tests and
quickstart jobs passed, but its overall result is also failure. This partial
infrastructure execution does not qualify the missing jobs.

## Changes under test

CONNECT conflicts remain strict. The source now accepts TCP CLOSE independently
of remote address/port and correlates bounded endpoint tombstones, avoids
repeatedly retrying terminal rejected leak watches, and exposes only fixed
diagnostic count labels. The independent collector de-duplicates full allow
payloads, including layer and direction, while preserving exact-event suppression.
The reference collector still polls at 1000 ms and retains the same strict
attempt-to-first-capture event-time boundary. Final enumeration is diagnostic
only and cannot make a missing polled reference pass.

## SOCKET result

Both fifty-client bursts fail: no clients echo. Each reports 25 proxy and 50
direct engine decisions, including fixture flows. Each receives the expected
75 original usable identities plus 50 additional CONNECT observations.

For every one of those 50 additional observations, in both rounds:

- The endpoint and process differ from the original proof, with no parent link.
- The process category is System and the image identity is unusable.
- The kernel event occurs after the first packet capture and after this engine
  started a known successful forward injection.

None has a kernel event time after injection completion; receipt occurs after
completion for 34/50 and 35/50 respectively. The event can therefore arise while
the send API is still running. A handler must not interpret receipt before send
completion as proof that the send failed or that a different app owned the
earlier captured SYN.

The conflict classifier records one different-endpoint collision and 49
cross-tuple endpoint collisions. This is consistent with a shared extra endpoint,
but the aggregate does not establish its cardinality. A follow-up must keep
quarantined identities out of the authoritative endpoint-to-tuple map while
still rejecting identities already bound to another original tuple.
Forward guards reject 613 and 606 packets
as ambiguous; reverse guards match 75 packets in each round. These checks
explain the failed echoes without treating engine decision counts as routing
success. No PID whitelist or relaxed conflict policy was used in this run.

The delayed-identity case also fails: six clients have no successful echo/reset,
three selected flows time out direct, and no late leak/reset is verified. Three
extra events have known forward-injection context; three are received before
that success context has been recorded. Serializing validation, injection and
success recording is needed to avoid this race in any proposed quarantine.

CLOSE reception is now observable, but the counted closures in the burst cases
refer to unknown endpoints. Absence of a matching original closure is not proof
of endpoint liveness. General lifecycle/reuse safety remains unqualified.

## Independent WFP reference result

The two WFP bursts pass, with 100/100 client echoes and independent references.
Sequential WFP routing echoes all 80 clients, while the independent audit matches
35/40 and 37/40. Every missing audit result is `no_polled_tuple`; none fails due
to image path, layer, direction, a clock boundary or conflicting application.
The engine itself saw a valid stored-event proof for every client.

Full-payload de-duplication therefore does not resolve this coverage gap. No
missing reference is recovered by the emitted final-enumeration diagnostics.
That export is capped at 200 records, so this does not prove absence from the
complete final snapshot. Accumulated poll counts and final snapshot counts
describe different populations; their signed difference (`wfp_poll_missed`) is
not a kernel-loss or missing-client counter.

The next equally instrumented comparison will poll the independent reference
every 100 ms for both ownership sources. It retains exact matching, the strict
event-time boundary and the same 1100 ms drain. It must demonstrate complete
coverage rather than assuming the faster audit fixes the gap. This extra audit
load is experimental background work and prevents a total-system CPU saving
claim from routing-query counts alone.

## Proposed bounded follow-up

The evidence supports testing a narrow policy: pin the validated pre-capture
identity to its original TCP generation; quarantine a different, previously
unbound endpoint observed strictly after capture and successful own-send start;
never replace the original proof or grant a new generation from that event.
Send success must be recorded before the receiver can apply such a candidate.
Earlier-occurring late receipts, same-endpoint changes, known endpoint reuse,
original closure, new SYN generations and detected loss remain strict failures.

This policy is proposed here, not measured by this run. NETWORK has no SOCKET
endpoint cookie and kernel queue loss is unobservable. Even successful fresh
IPv4 loopback samples would not qualify arbitrary reuse, missing lifecycle
events, desktop Windows, external routing, sustained load or UDP forwarding.
