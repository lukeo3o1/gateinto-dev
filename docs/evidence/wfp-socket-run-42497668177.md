# WinDivert SOCKET ownership and first-packet observation

Measured 2026-11-08 in [run 42497668177](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668177),
source `2dd799ecd9c0ecd256c429999a4e8273f7d33f76`, Actions merge
`22d85298b5508388fdcaece3606351fb9e2057eb`.
The [aggregate record](wfp-socket-run-42497668177-aggregate.json) retains the corrected
results and the earlier failed probe-filter run.

SOCKET is a promising alternative to stored-event polling in these controlled
observations. All 408 clients across both operating systems had matching SOCKET
PIDs, usable exact image paths, verified process creation times, independent
native WFP references, first observed NETWORK packets and successful echoes.
All sixteen observation cases passed.

For sequential short connections, image identity became available about
0.09–0.12 ms after first observed capture at p50, versus roughly 21–28 ms for
native polling receipt in the same cases. This is identity availability relative
to packet capture, not an API-call duration or end-to-end proxy latency.

Full image identity was ready before capture for only 21/408 clients.
This does not remove the need to buffer a first packet. No packet blocking,
injection, proxy redirection or SOCKET-based admission was exercised.

## Exact jobs and artifacts

| Run / source | OS / image | Job | Artifact |
| --- | --- | --- | --- |
| Corrected 42497668177 / `2dd799e` | Server 2022 build 20348, win22 20261101.353.1 | [128783417462](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668177/job/128783417462) | [13624032130](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668177/artifacts/13624032130) |
| Corrected 42497668177 / `2dd799e` | Server 2025 build 26100, win25-vs2026 20261103.298.1 | [128783417147](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668177/job/128783417147) | [13624570241](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668177/artifacts/13624570241) |
| Initial 42496744881 / `c8f3241` | Server 2022 build 20348 | [128780608516](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881/job/128780608516) | [13623613284](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881/artifacts/13623613284) |
| Initial 42496744881 / `c8f3241` | Server 2025 build 26100 | [128780608572](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881/job/128780608572) | [13623826315](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881/artifacts/13623826315) |

All four downloaded artifacts contain only aggregate-evidence.json,
ci-summary.json, environment.json and driver-manifest.json. Each downloaded
case summary exactly matched its projected console counterpart: six initial
cases and eight corrected cases per OS. Both corrected jobs validated the
official WinDivert 2.2.2 signature, compiled the native programs with MSVC,
passed the actual-DLL helper tests and completed all observation cases.

New evidence contains fixed labels, counts, relative durations and public build
metadata. Actual PIDs, image paths, endpoint identities, IP/port tuples, process
creation times, absolute QPC values and fixture credentials are excluded.
Kernel queue loss is explicitly unobservable, not reported as zero.

## Initial probe defect and control

The initial run had 192/192 successful clients, native references and first
observed NETWORK matches on each OS, but zero SOCKET receives. All twelve cases
correctly remained INCONCLUSIVE_SOCKET_PROBE. No SOCKET timing could be derived.

The probe's scoped SOCKET expression began with `ip`. In the pinned
[shared filter evaluator](https://github.com/basil00/WinDivert/blob/v2.2.2/dll/windivert_shared.c#L1194),
that field tests whether a parsed IPv4 packet header exists. The
[driver's SOCKET evaluation path](https://github.com/basil00/WinDivert/blob/v2.2.2/sys/windivert.c#L5607)
supplies socket metadata without that header. The documented field-support
table therefore did not describe the predicate's effective behavior on this path.

The correction removes `ip` from SOCKET scope while retaining protocol,
remote address/port and exact software tuple validation. NETWORK retains its
IPv4 packet predicate. The Windows self-test calls the shipped DLL on a synthetic
SOCKET address and verifies all three results:

- Historical `ip and <target scope>`: false.
- Corrected protocol/address/port scope: true.
- Broad `event == CONNECT`: true.

Two broad CONNECT controls additionally verify real event delivery. Non-target
events are discarded before process lookup or record output. Five unrelated
events in the 2022 TCP control were counted and discarded; no unrelated event
details were published. The initial zero-event result is a probe-filter defect,
not evidence that SOCKET is unavailable on these Windows versions.

## Controlled traffic and matching

Both SOCKET and NETWORK handles use SNIFF and RECV_ONLY. They open before any
controlled client, and do not hold or alter packets. Native stored-event polling
runs concurrently as an independent attribution reference.

Each OS runs:

| Cases | Filter | Clients per case | Client behavior |
| --- | --- | ---: | --- |
| tcp-control / udp-control | Broad CONNECT with software target validation | 6 | Three fresh A/B pairs, 500 ms post-echo hold |
| tcp-live / udp-live | Corrected target scope | 6 | Three fresh A/B pairs, 500 ms post-echo hold |
| tcp-short / udp-short | Corrected target scope | 40 | Twenty fresh A/B pairs, sequential, immediate completion |
| tcp-burst / udp-burst | Corrected target scope | 50 | Fifty fresh processes, alternating A/B, launched without waiting for prior completion |

The burst count describes clients launched without serial waiting; it does not
establish fifty simultaneous connect calls.

Every client explicitly binds an IPv4 loopback endpoint before connect/sendto,
giving an attempted full tuple before the first packet. The harness retains child
process handles for independent creation-time evidence. This does not exercise
immediate process-object reclamation or worst-case PID reuse.

Matching requires the exact attempted tuple, expected client PID, fresh SOCKET
CONNECT time, valid capture/receipt ordering, independent layer-48 outbound
native application path and successful nonce echo. A usable image path additionally
needs the expected DOS path, matching process creation time, a valid native
generation guard and a consistent path-ready clock. Actual ready and summary
records must confirm the requested filter profile.

Across all corrected cases: 408/408 for each coverage check, zero missing or
conflicting identities, zero invalid timing and zero reported userspace
queue/output errors. The observation pass does not assert production-safe reuse,
zero kernel event loss, or routing correctness.

## Identity availability

All values below are milliseconds relative to the first observed qualifying
NETWORK capture: an outbound initial TCP SYN or UDP datagram. Native polling
receipt is measured on those same controlled connections. A positive value means
the information became available after capture.

### Server 2022

| Case | Clients | App path ready minus capture p50 / p95 / max | Native poll receipt minus capture p50 / p95 |
| --- | ---: | ---: | ---: |
| tcp-control | 6 | 0.0906 / 0.1589 / 0.1589 | 9.8939 / 11.8078 |
| udp-control | 6 | 0.1194 / 0.1383 / 0.1383 | 11.4311 / 22.1184 |
| tcp-live | 6 | 0.0730 / 0.1444 / 0.1444 | 14.2893 / 24.3102 |
| udp-live | 6 | 0.1328 / 0.1433 / 0.1433 | 19.3300 / 29.0826 |
| tcp-short | 40 | 0.0919 / 0.1196 / 0.1240 | 21.4347 / 31.7520 |
| udp-short | 40 | 0.1011 / 0.1201 / 0.1221 | 20.8902 / 28.4572 |
| tcp-burst | 50 | 0.0868 / 0.2666 / 0.3840 | 28.1502 / 36.7738 |
| udp-burst | 50 | 0.1104 / 0.2678 / 0.2962 | 26.7106 / 35.1434 |

### Server 2025

| Case | Clients | App path ready minus capture p50 / p95 / max | Native poll receipt minus capture p50 / p95 |
| --- | ---: | ---: | ---: |
| tcp-control | 6 | 0.0992 / 0.1820 / 0.1820 | 10.1391 / 16.6777 |
| udp-control | 6 | 0.1174 / 0.1646 / 0.1646 | 16.3618 / 21.8163 |
| tcp-live | 6 | 0.1019 / 0.1485 / 0.1485 | 19.8113 / 30.7780 |
| udp-live | 6 | 0.1116 / 0.1523 / 0.1523 | 16.8019 / 41.2953 |
| tcp-short | 40 | 0.0989 / 0.1376 / 0.1969 | 27.8970 / 37.6099 |
| udp-short | 40 | 0.1204 / 0.1574 / 0.1680 | 27.4197 / 37.0232 |
| tcp-burst | 50 | 0.0949 / 0.1669 / 0.3136 | 36.5862 / 60.6010 |
| udp-burst | 50 | 0.1481 / 0.3280 / 0.3552 | 34.5579 / 68.5014 |

The maximum path-ready offset across these cases was 0.3840 ms. These are finite
samples with concurrent native polling and controlled process launches. They are
not a hard bound, sustained-load proof, or a measured reduction in routed
application response time. No total-system CPU saving was established.

## Kernel event, userspace receipt and full path readiness

| Observation before first observed NETWORK capture | Server 2022 | Server 2025 | Combined |
| --- | ---: | ---: | ---: |
| SOCKET kernel event timestamp | 204/204 | 204/204 | 408/408 |
| SOCKET event received with PID | 187/204 | 181/204 | 368/408 |
| Exact image identity ready | 12/204 | 9/204 | 21/408 |

Image identity was ready before the first NETWORK receipt for 40/204 clients on
2022 and 29/204 on 2025, or 69/408 combined. Capture and receipt are different
reference points; the evaluator minimizes each independently.

An early kernel event timestamp cannot be treated as early userspace identity.
Most full-path observations arrive after both capture and receipt. A subsequent
routing experiment must hold pending packets until a valid identity result,
then apply the chosen rule. This run does not test that handoff or its additional
latency, failure policy, cancellation or backpressure.

## Verification and limits

The model job, both dedicated SOCKET jobs and
[standard repository CI](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42497668204)
pass. The broader PoC workflow remains red for the older subscription, native-drop
and ALE shadow comparisons; this does not make its successful SOCKET jobs a
routing qualification.

Local validation includes all 98 Python tests with PowerShell retry tests and the
loopback protocol test enabled, portable native tests with warnings as errors,
Windows x64 object compilation, actual PowerShell parsing and independent review.
The Windows jobs additionally execute the shipped-DLL address and filter tests.

Still unqualified: auto-bound sockets, external adapters, desktop Windows,
IPv6, shared or delegated sockets, immediate process reclamation, live PID/tuple
reuse, consumer overload, sustained load and clock changes. Existing native-WFP
routing behavior remains unchanged.

SOCKET now warrants a controlled first-packet buffering and routing comparison.
The evidence supports earlier usable identity in this topology; it does not yet
establish a faster, reliable production takeover.
