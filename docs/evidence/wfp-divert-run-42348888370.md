# WFP divert run 42348888370: in-process evidence audit

Source: https://github.com/lukeo3o1/gateinto-dev/actions/runs/42348888370
Windows job: https://github.com/lukeo3o1/gateinto-dev/actions/runs/42348888370/job/128332553899
Head: `e3336bd9a361dde7b3ea3c5c68d98b41a0a814db`
Inspected: 2026-11-07 through the GitHub connector's decoded job log.
Topology: windows-2022, build 20348, same-host IPv4, controlled loopback endpoints.

These are observations from the existing run, before the validation repairs.
No new Windows run was performed during this follow-up. Production code is unchanged.

## Result and timing correction

The model job passed; the Windows job failed. All 11 split poll cases again reached
their expected statuses (10 PASS_RESTRICTED_CASE and one CHARACTERIZED_REUSE_REJECTION).
Subscribe2, Subscribe4 and the 1000 ms Security UDP comparison failures remain.
QUIC adds a new failure: the in-process helper exits before readiness with
`redirect mode requires --listener-port`.

Seven in-process cases reported PASS_RESTRICTED_CASE, but their validator was too
weak to support all the corresponding claims. In particular, the first-packet
decision distribution used `now` sampled before blocking WFP enumeration.
The JSONL decision log sampled QPC after enumeration, making the discrepancy
directly measurable in the existing run.

| Case | Original reported status | Original decision p50 ms | Reconstructed logged decision p50 ms | Logged decision count | Original held-packet latency p50 ms |
| --- | --- | --- | --- | --- | --- |
| hold-inproc-tcp | PASS_RESTRICTED_CASE | 11.950 | 33.112 | 6 | 33.097 |
| hold-inproc-udp | PASS_RESTRICTED_CASE | 10.264 | 26.181 | 6 | 26.186 |
| redirect-inproc | PASS_RESTRICTED_CASE | 11.253 | 25.726 | 9 | 25.721 |
| hold-inproc-tcp-repeat | PASS_RESTRICTED_CASE | 10.404 | 25.951 | 6 | 25.980 |
| redirect-inproc-repeat | PASS_RESTRICTED_CASE | 10.533 | 25.760 | 9 | 25.730 |
| leakcheck-inproc | PASS_RESTRICTED_CASE | 9.877 | 24.936 | 6 | 24.947 |
| concurrency-inproc | PASS_RESTRICTED_CASE | 14.736 | 32.510 | 26 | 34.527 |
| quic-inproc | FAIL | — | — | — | — |

Reconstruction uses `(decision.qpc - decision.generation) * 1000 / 10000000` and
the nearest-rank percentile used by the helper. In this head, `generation` is
the first packet's WinDivert capture Timestamp. Small cases include all decisions;
concurrency includes only 26 of 75 decisions because CI prints only the first
40 packet-log records, including translation records. Its reconstructed p50 is
a partial sample, not a corrected full-run percentile.

The old held/direct/proxy latency distributions start at `WinDivertRecv` return,
despite the README saying capture-to-reinject, and sample before the send.
They also need remeasurement. Neither the original decision summary nor these
limited observations demonstrate that in-process lookup is faster than the
split poll design.

Selected raw decision records, retaining both QPC values:

```jsonl
{"case":"hold-inproc-tcp","protocol":6,"generation":11169632169,"qpc":11169799488,"action":"direct","reason":"selected"}
{"case":"hold-inproc-tcp","protocol":6,"generation":11169644057,"qpc":11170007285,"action":"direct","reason":"other_app"}
{"case":"hold-inproc-tcp","protocol":6,"generation":11169652786,"qpc":11170010992,"action":"direct","reason":"selected"}
{"case":"hold-inproc-tcp","protocol":6,"generation":11169683099,"qpc":11170014844,"action":"direct","reason":"other_app"}
{"case":"hold-inproc-tcp","protocol":6,"generation":11169685645,"qpc":11170016762,"action":"direct","reason":"selected"}
{"case":"hold-inproc-tcp","protocol":6,"generation":11169690054,"qpc":11170018469,"action":"direct","reason":"other_app"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185376114,"qpc":11185523901,"action":"direct","reason":"selected"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185384086,"qpc":11185669958,"action":"direct","reason":"other_app"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185401189,"qpc":11185673099,"action":"direct","reason":"selected"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185427869,"qpc":11185677227,"action":"direct","reason":"other_app"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185429868,"qpc":11185679179,"action":"direct","reason":"selected"}
{"case":"leakcheck-inproc","protocol":6,"generation":11185431866,"qpc":11185681937,"action":"direct","reason":"other_app"}
```

For example, the leak case's decisions occur 14.779–28.587 ms after capture;
five of six exceed the configured 15 ms hold. The stale clock allowed ownership
decisions after that deadline.

## Coverage gaps found in the executed source

- `hold-inproc-udp` launched TCP clients. Its logged decisions have protocol 6;
  it provides no in-process UDP evidence.
- `leakcheck-inproc` used hold mode and reported `unattributed=0`,
  `leaked=0`, `rst_count=0`. It did not exercise late attribution or connection
  termination, despite reporting PASS.
- QUIC stopped before capture; its failed startup says nothing about UDP dropping.
- Hold/UDP pass checks did not require native ownership for each client. The helper
  did not emit per-flow ownership evidence for independent checking.
- Enumeration failures could silently return no or partial evidence. Partial
  results cannot establish that another app's conflicting event was absent.
- RST counters incremented without checking injection success; only the remote
  direction was injected. No client-observed reset was required.
- BFE restoration could overwrite a concurrent global configuration change and
  report an error only after the recorded successful result.

The 50-client redirect case reported 25 proxy decisions and 25 correct gateway
CONNECTs with successful clients. It is useful restricted TCP evidence, but the
weaker attribution validation and partial printed traces prevent treating it as
a production noninterference or latency guarantee.

## Repairs prepared for the next Windows run

The working tree now uses post-query/commit QPC, rejects late ownership decisions,
and measures capture through checked reinjection. Enumeration requires validity
flags and an app path, discards partial/error results, and reports lookup failures.
Guarded BFE restoration runs before final success is emitted.

In-process UDP/QUIC client plans use UDP and include selected/non-selected controls.
Every client must have matching tuple, generation, exact native app path and
effective decision evidence. The leak case uses TCP redirect with 100 ms hold and
a 250 ms selected-app evidence delay; the client keeps its connection open after
echo and must observe WSAECONNRESET after timeout, late ownership and checked
bidirectional RST injection. Post-reset drop logs must reference the same recorded
selected-flow generation; the engine still pins the tuple, so reuse is unqualified.

These changes have local model/helper and Windows object-compilation checks.
The repaired UDP, QUIC, deadline and live-reset paths still require Windows execution.
The single worker still blocks on synchronous BFE RPC, so the hold setting remains
a decision budget, not a guaranteed upper bound on actual packet release latency.
Native tuple reuse, unbounded receive backlog and long-lived operation remain
unqualified.

## Subscribe4 investigation boundary

The source-level API pairing matches Microsoft's definitions:
[CALLBACK4](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nc-fwpmu-fwpm_net_event_callback4)
takes
[FWPM_NET_EVENT5](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event5),
whose classifyAllow member is FWPM_NET_EVENT_CLASSIFY_ALLOW0, as in EVENT3.
The observed unknown direction is unresolved; a structure/version mismatch has
not been established. A focused next diagnostic should compare raw direction,
BOOL/profile fields and identical event identities from callback, Enum3 and Enum5.
