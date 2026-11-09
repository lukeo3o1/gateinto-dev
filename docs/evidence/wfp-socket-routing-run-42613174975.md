# Initial WinDivert SOCKET TCP routing comparison

Measured 2026-11-09 in [run 42613174975](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42613174975),
source `38fa3a5dc90b00d3c6da4b188478f20e9b57f75d`, Actions merge
`5b26a5b6faae8658280122c687c5ed1714b56e33`.
The [aggregate record](wfp-socket-routing-run-42613174975-aggregate.json)
retains every case, including failures.

Both dedicated routing jobs failed. SOCKET observation remained successful, but
this implementation did not complete correct end-to-end SOCKET routing. Its
ownership-decision timings cannot support a routed performance comparison.

## Exact jobs and artifacts

| OS | Routing job | Artifact | Digest |
| --- | --- | --- | --- |
| Server 2022 | [129146557250](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42613174975/job/129146557250) | [13671133235](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42613174975/artifacts/13671133235) | `sha256:e26ffd94d0b690fe8a8f86bc71da99f1cd3788066d4970f733ae5a4a0045b87b` |
| Server 2025 | [129146557321](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42613174975/job/129146557321) | [13672280045](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42613174975/artifacts/13672280045) | `sha256:f0646f99d668e7493e0c85c9d15c796461b443cf93cd60cf12012085bd2b386c` |

Both downloaded ZIPs contain exactly aggregate-evidence.json, ci-summary.json,
environment.json and driver-manifest.json. All nine projected summaries per OS
exactly match the corresponding console aggregate. No raw identities, tuples,
absolute clocks or fixture credentials are published.

## Controlled cases and outcome

Each OS compares native WFP and SOCKET ownership in two rounds, reversing the
profile order in the second round. Short cases use forty sequential clients;
bursts release fifty clients from a shared barrier after every client has bound
and reported readiness. The selected app must traverse authenticated CONNECT
through the real Gateinto proxy; the other app must echo directly. An independent
native WFP collector audits every original client at a 1000 ms poll interval.
The final case delays SOCKET ownership beyond the hold deadline and checks the
existing timeout-direct, late leak-detection and reset policy.

| Case group | Server 2022 | Server 2025 |
| --- | --- | --- |
| WFP burst, rounds 1 and 2 | Both pass; 100/100 echoes and independent references | Both pass; 100/100 echoes and independent references |
| WFP sequential, rounds 1 and 2 | 80/80 echoes; audit matches 37/40 and 39/40; both fail audit | 80/80 echoes; audit matches 37/40 and 38/40; both fail audit |
| SOCKET burst, rounds 1 and 2 | 0/100 echoes; both fail client attestation | 0/100 echoes; both fail client attestation |
| SOCKET sequential, rounds 1 and 2 | Both fail during client execution | Both fail during client execution |
| SOCKET delayed-identity control | 0/6 successful clients; no verified late reset | 0/6 successful clients; no verified late reset |

Each SOCKET burst reports 25 proxy decisions and 50 direct decisions, including
the fixture's target connections, with zero native WFP routing queries. These
are engine decisions, not successful tunnels. The engine reports no known queue,
history, output or receiver error, but the end-to-end client checks correctly
reject the run. Engine health alone therefore cannot establish routing success.

The bursts receive 125 CONNECT observations for 75 tuple histories: 75 usable
identities and 50 missing identities. Already-decided direct packet counts are
near zero, and no scoped CLOSE observations arrive. The delayed case repeatedly
reports ambiguous history, with no verified leak detection or reset. These are
diagnostic facts; the aggregate record does not identify the extra events'
processes or endpoints and cannot prove their cause.

## Follow-up investigation

The pinned driver has both endpoint-closure notifications with full remote
metadata and resource-release notifications with zero remote address/port.
A CLOSE filter that requires the target remote tuple misses the latter. A
separate broad CLOSE arm must correlate endpoint IDs against bounded history.
See [WinDivert v2.2.2 driver source](https://github.com/basil00/WinDivert/blob/v2.2.2/sys/windivert.c).

Native collector de-duplication also used the event header without the allow
payload's layer, direction and filter identity. Distinct allow events sharing
header fields could collapse. This is a collector defect to repair, but the
present aggregate does not prove it caused all missing sequential references.
The strict audit's event-time boundary also needs explicit diagnostics.

The extra CONNECT observations may be associated with reinjection losing socket
context. Aggregate conflict and timing diagnostics are required before changing
ownership selection; ordinary reauthorization must not be assumed because the
pinned CONNECT callout explicitly excludes that flag. Detected lifecycle
conflicts and loss remain failures. Future results must retain this failed run.

## Validation and limits

Both official-driver MSVC builds passed. Standard repository CI, the model job
and both unchanged SOCKET observation jobs passed. The wider PoC workflow is
red, including these newly failed routing jobs and its older unqualified cases.
Local validation passed 122 Python checks with actual PowerShell and loopback
networking, portable native helpers with `-Werror`, PowerShell parsing and an
independent implementation review. Windows x64 COFF cross-compilation also
passed with Clang 19 and the SDK's documented STL compatibility override; actual
MSVC builds are the definitive compiler check.

The experiment uses fresh IPv4 loopback tuples, retained child-process handles
and finite Server samples. It does not qualify arbitrary tuple/PID reuse,
immediate process reclamation, desktop Windows, external routing, sustained
load or UDP forwarding. NETWORK has no SOCKET endpoint cookie, kernel queue
loss is unobservable, and timeout-direct can leak before a later reset.
