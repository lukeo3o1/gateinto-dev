# SOCKET routing with pinned original ownership

Measured 2026-11-09 in [run 42674843682](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42674843682),
source `acbb20bd00cfbc7292b4b6e4604a3d0c779b5fa2`, tree
`0284803a76206a2775a58033e4bca76a1371a774`.
The [aggregate record](wfp-socket-routing-run-42674843682-aggregate.json)
retains all eighteen case results and exact checkout merges.

Four SOCKET burst cases now pass: all 200 original clients echo with correct
selected-app proxying, nonselected direct routing, exact process attestation
and independent native references. Both delayed-identity controls also pass.
Sequential short connections remain unreliable: three of four SOCKET short
cases fail, and the passing case has a large tail-latency outlier. This is
partial success, not a general routing or reliability qualification.

## Jobs and artifacts

| OS | Routing job | Artifact | Digest |
| --- | --- | --- | --- |
| Server 2022 | [129353327274](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42674843682/job/129353327274) | [13699627628](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42674843682/artifacts/13699627628) | `sha256:d327757de1dc9d127f5200bf5e67220112b15b028ca45be3b350088341c52146` |
| Server 2025 | [129353327784](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42674843682/job/129353327784) | [13699048940](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42674843682/artifacts/13699048940) | `sha256:b3f635099499bfd16cab72d1982aa87cb6bf283d5497ee948d7ed53bccdf738e` |

Both downloaded artifacts contain the four aggregate/build JSON files only.
All nine summaries per OS exactly match the corresponding projected console
aggregate. Actual process IDs, paths, endpoints, tuples, absolute clocks and
credentials are excluded.

## Policy under test

The validated pre-capture SOCKET owner is pinned to its original TCP generation.
A later different endpoint is quarantined only after a known successful own
forward injection began; it never supplies replacement ownership. Receiver
application is serialized with send validation and success recording. Already
tracked original endpoints, earlier-occurring late receipts, same-endpoint
changes, original closures, known loss and new initial SYNs remain strict.
There is no System PID whitelist. This conservative policy also rejects SYN
retransmissions after quarantine, including the same initial sequence number;
ordinary lossy-network behavior remains unqualified.

Both sources use a 100 ms independent native reference poll and the same
1100 ms drain. In this run the reference still requires event occurrence no
later than first NETWORK capture, subject to the measured clock uncertainty.
The native WFP routing default is unchanged.

## End-to-end results

| Case | Server 2022 | Server 2025 |
| --- | --- | --- |
| WFP sequential round 1 | Pass, 40/40 echoes/references | Pass, 40/40 echoes/references |
| SOCKET sequential round 1 | Fail, 37/40 clients succeed | Pass, 40/40 echoes/references; slow tail |
| WFP bursts, both rounds | Both pass, 100/100 echoes/references | Both pass, 100/100 echoes/references |
| SOCKET bursts, both rounds | Both pass, 100/100 echoes/references | Both pass, 100/100 echoes/references |
| SOCKET sequential round 2 | Fail, 39/40 clients succeed | Fail, 38/40 clients succeed |
| WFP sequential round 2 | Pass, 40/40 echoes/references | 40/40 echoes, audit 35/40; fail |
| SOCKET delayed-identity | Pass, all 6 clients; 3 checked selected resets | Pass, all 6 clients; 3 checked selected resets |

Fourteen of eighteen cases pass. No failed short case is used to form a routed
speed comparison. The burst checks cover selected image/PID/creation identity,
generation, admission deadline, authenticated CONNECT destination/count, nonce
echo, independent native references and nonselected negative controls.

Every passing burst quarantines exactly 50 later CONNECT observations in 50
tuple/endpoint pairs, with one distinct quarantined endpoint per case. It skips
those metadata image lookups, keeps all 75 original engine-flow identities and
reports zero routing snapshot queries. Original endpoint CLOSE observations are
now present, including 75 per burst. These finite counts do not establish a
global endpoint identity or absence of kernel queue loss.

## Passing burst latency

Actual client attempt-to-echo latency in milliseconds, WFP / SOCKET. The clock
starts after bind and cohort release but before local attempt-record flush and
connect. It excludes process launch and barrier waiting, includes that logging
overhead and the real proxy/fixture work, and is not an ownership API duration.

| OS | Round | Selected p50 | Selected p95 | Direct p50 | Direct p95 |
| --- | --- | --- | --- | --- | --- |
| 2022 | 1 | 110.6284 / 86.6162 | 162.3221 / 110.8851 | 42.0887 / 20.5007 | 48.2911 / 29.2595 |
| 2022 | 2 | 130.9284 / 91.3950 | 134.3425 / 104.1972 | 37.2262 / 24.1909 | 43.3410 / 28.2467 |
| 2025 | 1 | 189.8013 / 146.1938 | 223.8411 / 169.7847 | 66.9859 / 33.5048 | 72.0062 / 53.4713 |
| 2025 | 2 | 195.2314 / 139.8917 | 222.3867 / 160.7106 | 64.2184 / 40.8059 | 78.4932 / 47.4173 |

The retained Server 2025 sequential round 1 must also be considered: selected
client p50 improves from 64.2158 to 34.8002 ms, but p95 regresses from 79.2269 to
636.6433 ms and the SOCKET maximum is 1034.6969 ms. Thus the passing burst
improvement is insufficient to claim uniformly faster service.

## Remaining short-connection defect

Median original event-to-image-ready latency is roughly 0.15–0.2 ms, while some identity-ready
to engine-application offsets approach 1 second. Maximum offsets are 1008.21 and
886.747 ms in the failed Server 2022 cases, 999.546 ms in the passing Server 2025
short case and 960.959 ms in its failed round 2. Unknown flows hit the hold
deadline, and subsequent strict conflict/reuse controls disrupt some clients.

The condition-variable notification path publishes its atomic version without
the mutex held by the consumer's check-and-wait sequence. A publication between
that predicate check and entry into wait can be lost until the pending deadline.
A following revision must repair that handoff with the same wait mutex, audit
lock ordering and retain known-loss blocking; periodic polling is not the tested
solution. This run does not measure that repair.

## Native audit timing

The faster audit recovers every original engine event in the polled stream for
both WFP sequential rounds. Server 2025 round 2 still fails the pre-capture
time boundary for five records: their converted occurrence offsets are
0.011–0.0164 ms after capture, with measured anchor uncertainty 0.0063 ms.
This is distinct from the earlier `no_polled_tuple` coverage gap.

The next audit will use the first exact tuple/generation normal routing decision
as its upper bound. That decision is sampled and logged before flush and first
reinjection, preserving a causal pre-reinjection reference while removing the
unsupported assumption that the stored-event timestamp must precede NETWORK
capture. Drops, later decisions, echo results and wrong applications cannot
extend the boundary. The separate SOCKET admission proof still requires its
kernel CONNECT event no later than the captured first packet.

## Delayed-identity control and checks

Both controls deliberately release three selected flows direct after about
100 ms. They echo before six total late selected resets complete around
250 ms. Every selected reset is checked by the client, and all six nonselected
clients echo without reset. This demonstrates the policy's leak tradeoff; reset
cannot undo already transmitted bytes and never turns a direct flow into proxy.

Both signed-driver MSVC builds, model checks and SOCKET observation jobs pass.
The dedicated routing jobs remain red for the short cases above. Standard CI
has a separate WOW64 failure in `check_upstream_selects_a_gateway_by_name`:
`TLS handshake failed: invalid peer certificate: UnknownIssuer`; its other
executed checks pass, and installer checks are skipped. That failure is retained
rather than reporting standard CI as green. The broader PoC also retains its
older unqualified cases.

Source scope remains fresh IPv4 loopback sessions, retained child handles,
finite Server samples and instrumented reference load. Arbitrary reuse,
packet-loss/retransmission behavior, missing lifecycle events, desktop Windows,
external routing, sustained load and UDP forwarding remain unqualified. Snapshot
query count zero is not a total-system CPU saving measurement.
