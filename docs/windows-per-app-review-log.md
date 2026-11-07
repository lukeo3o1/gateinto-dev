# Windows per-app review execution record

Date: 2026-11-06. Baseline: `ec5f13dbfdf1a43dc91174d29bc6510add7dfca9`.

This records review activity, PoC preparation and, in the last section, the Windows runtime runs that were inspected. Only that section contains Windows runtime measurements.

| Check actually performed | Observation |
| --- | --- |
| `uname -a` in `/workspace` | Linux `3298dfc373c1`, kernel `6.18.57`, x86_64 GNU/Linux. |
| `git status --short` before changes | Empty; source tree clean. |
| `git rev-parse HEAD` | Baseline SHA above. |
| Read `AGENTS.md` | English repository artifacts; separate developer/reviewer required. Independent read-only reviewer used. |
| Read Cargo manifest, proxy entry/relay/routing/authentication, Windows owner lookup, HTTP CONNECT protocol and architecture | Explicit TCP CONNECT only; IP Helper owner table; no native WFP or WinDivert implementation, no UDP tunnel. See main report for source locations. |
| `command -v wine`, `command -v powershell`, `command -v pwsh` | No executable path returned. No Windows host was supplied. |
| Microsoft Learn / official WinDivert documentation | Reviewed through web tool. Direct reqrypt open returned 502; maintainer's versioned GitHub documentation was available. |
| Attempted `curl` of official GitHub WinDivert docs/example through inherited proxy | Failed: curl error 7, could not connect to proxy port 8080. No source downloaded by that command. This did not prevent web-based document review. |
| Initial review changes | Documentation only during the initial review. The subsequent independent PoC is recorded below. |
| Documentation verification | `git diff --check` returned success; explicit Python checks of both new files passed for trailing whitespace, final newline and relative local links (new files are untracked, so the explicit checks cover them). |
| Independent review | Reviewer found no major factual or evidence-labeling blocker; corrected local-auth source reference and distinguished callback receipt from decision readiness when comparing packet timestamps. |

Windows execution results at the initial review (superseded in part by the last section):

```text
driver_load: NOT RUN
native_wfp_subscription: NOT RUN
security_5156_subscription: NOT RUN
normal_win32_allow_event_coverage: NOT RUN
tcp_syn_vs_event_delivery: NOT RUN
udp_first_datagram_vs_event_delivery: NOT RUN
mapping_retransmit_close_reuse: NOT RUN
ownership_delay_skip_injection: NOT RUN
transparent_local_tcp_accept: NOT RUN
original_destination_recovery: NOT RUN
gateinto_upstream_connect_via_transparent_adapter: NOT RUN
return_to_original_socket: NOT RUN
other_app_noninterference: NOT RUN
upstream_self_exclusion: NOT RUN
udp_end_to_end: NOT RUN
```

No latency numbers, packet counts, success rates or Windows traces existed at the initial review. The main report contains the full pending qualification matrix and required evidence bundle.

## Follow-up PoC preparation

The first-packet-hold hypothesis is now implemented under `experiments/wfp-divert`
with a Windows Actions workflow and `examples/wfp_lab.rs`. Production proxy code
is unchanged. Native WFP/5156 and WinDivert packet sources remain separate.

Actually performed locally: Python attribution and bridge tests (11 passed with
local networking permission), native-event helper tests, packet decision tests, Windows x64 COFF
object compilation of both probes, and three Rust fixture tests plus Clippy
(with local networking permission). These verify model logic, source compilation
and explicit CONNECT echo only. Windows driver loading and transparent NAT are
still pending execution. Full cross-linking was not established because the
supplied libc++ bitcode and local linker versions differ; Actions uses MSVC.

Independent review corrected cleanup to stop collectors cooperatively and retain
BFE recovery state, excluded private credentials from artifacts, required
per-client effective decisions and upstream CONNECT evidence, and made final
collector errors/overflow fail a case. See the PoC README for current restrictions.

## Windows runtime runs

Inspected 2026-11-07 from GitHub Actions job logs. All jobs ran on `windows-2022`, OS build 10.0.20348, single host, IPv4, controlled loopback endpoints, plus an external connect-only case to `api.github.com:443`. Every job concluded failure because Subscribe2 and Subscribe4 cases fail, and in run 42340194216 also `hold-security-udp`; results below are per case.

| Run | Head | Job | What was measured |
| --- | --- | --- | --- |
| 42280670136 | `a46493b` | 128108481754 | Subscribe2: 0 callbacks of any type in every case; `collect_after=1`, `keywords_after=16`. Enum3: 6–72 stored CLASSIFY_ALLOW events per case, correct app path, full outbound tuple, layer 48; `event_filetime` about 0.03–0.09 ms before first packet capture. |
| 42282264784 | `ae22135` | 128114004376 | Subscribe4: callbacks equal to the enumeration total, received about 1004 ms after the event (batched). `FWPM_NET_EVENT5` classifyAllow read direction unknown and `is_loopback` true, contradicting Enum3 (outbound, false); unusable. Poll (5 ms `sleep_for`, 1 s overlap, unfiltered): 7/7 cases, notification−capture 20–46 ms. |
| 42340194216 | `edba304` | 128305938309 | Poll (high-resolution waitable timer, 5 ms wait, CLASSIFY_ALLOW enum filter, 300 ms overlap): 11/11 poll cases reached pass status. Summary in [evidence/wfp-divert-run-42340194216.md](evidence/wfp-divert-run-42340194216.md). |

Status for the restricted topology above, replacing the matching initial-review lines:

```text
driver_load: PASS (official signed WinDivert, windows-2022)
native_wfp_subscription: RUN, NOT USABLE (Subscribe2 no callbacks; Subscribe4 late and inconsistent fields)
native_wfp_stored_event_poll: PASS_RESTRICTED (Enum3, 11/11 cases in 42340194216)
security_5156_subscription: PASS_RESTRICTED except UDP at 1000 ms hold (about 330-1024 ms; TCP hold, redirect with 3 gateway CONNECTs, retransmit, external and UDP at 2000 ms hold passed)
normal_win32_allow_event_coverage: PASS_RESTRICTED (TCP and UDP, build 20348 only)
tcp_syn_vs_event_delivery: MEASURED (poll observation after capture; poll p50 10.4-25.6 ms)
udp_first_datagram_vs_event_delivery: MEASURED (within hold; attribution only)
mapping_retransmit_close_reuse: PARTIAL (retransmit pass; reuse characterized rejection; close not qualified)
ownership_delay_skip_injection: PARTIAL (delayed, too-late, missing)
transparent_local_tcp_accept: PASS_RESTRICTED
original_destination_recovery: PASS_RESTRICTED
gateinto_upstream_connect_via_transparent_adapter: PASS_RESTRICTED (local CONNECT fixture)
return_to_original_socket: PASS_RESTRICTED
other_app_noninterference: PASS_RESTRICTED (redirect PASS criterion)
upstream_self_exclusion: PASS_RESTRICTED (single host, gateway outside target filter)
udp_end_to_end: NOT RUN (UDP forwarding unimplemented)
```

Conclusions are limited to this runner and topology. TCP first-packet hold works with polled native WFP stored net events as the ownership source; subscription delivery is not usable there. UDP attribution timing works under hold, but UDP end to end stays "cannot guarantee". Still unqualified: Windows 10/11 client SKUs, other builds, external routing beyond the connect-only case, load and stress, polling cost at scale, longer-lived collectors, and the Subscribe4 field-read anomaly (possibly a structure or version mismatch, not root-caused).

Figures for runs 42280670136 and 42282264784 are from the summary of their job logs; their head SHAs and job IDs were confirmed with `gh run view`. Run 42340194216 figures were re-extracted from its job log and retained in `docs/evidence`.

## In-process follow-up audit and validation repairs

Inspected 2026-11-07: [run 42348888370](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42348888370),
head `e3336bd9a361dde7b3ea3c5c68d98b41a0a814db`, Windows job 128332553899.
Read PR #95 metadata, comments, changed filenames, checks and decoded Windows job
log through the GitHub connector. The full findings and raw decision excerpts are
in [evidence/wfp-divert-run-42348888370.md](evidence/wfp-divert-run-42348888370.md).

The 11 split poll cases again reached their expected statuses. The new in-process
TCP cases produced echo/CONNECT evidence, including 25 CONNECTs for 50 clients,
but their decision summaries omitted blocking enumeration time. Recalculated
complete small TCP hold/redirect traces have decision p50 25.7–33.1 ms; the
concurrency excerpt is incomplete and cannot correct the full-run percentile.
The nominal UDP case used TCP clients, QUIC failed before readiness, and leakcheck
passed with no timeout/leak/RST. Those three cases do not qualify the named paths.

Prepared on local branch `research/wfp-inproc-validation`, in the isolated worktree
`/workspace/gateinto-wfp-research`; the original checkout was clean and unchanged.
Changes affect only experiment code, its workflow and documentation:

- Corrected the decision clock/deadline and capture-to-successful-send metrics;
  discarded incomplete/error enumeration results; required native validity flags
  and app path; restored BFE options with guards before final success.
- Corrected UDP/QUIC client plans and required each client's native ownership,
  tuple, generation, protocol, decision and echo/drop evidence.
- Replaced vacuous leakcheck with 100 ms hold / 250 ms selected-app evidence delay,
  TCP redirect, checked bidirectional RST and a live client that must observe reset.
  Added selected generation-qualified post-reset drop validation.
- Retained native/client evidence on validation failures and printed ownership
  and filter-fallback diagnostics in bounded CI excerpts.

Actual local verification, Linux x86_64, kernel 6.18.57:

| Check | Result and boundary |
| --- | --- |
| Python failing-first regression checks | Covered missing native authority, actual UDP protocol, selected QUIC/non-selected echo, leak/reset trace and selected post-reset enforcement; initially failed before the relevant changes. |
| `python3 -m unittest discover -s experiments/wfp-divert -p 'test_*.py' -v` | 37 passed with loopback socket permission, including bridge response/early-data/half-close. Sandboxed execution alone skips that bridge test. |
| Native-event, packet-state, in-process and client-state portable self-tests, `g++ -std=c++17 -Wall -Wextra` | Passed. Added deadline boundary, incomplete/empty ownership and BFE concurrent-change checks; these are model/helper checks. |
| Windows x64 object compilation of `inproc.cpp` and `client.cpp` | Passed with official LLVM-MinGW 20261104 and Microsoft's WFP headers from win32metadata, plus official WinDivert v2.2.2 header, all downloaded into `/tmp`. This is a compile check, not MSVC linking or driver execution. |
| Separate read-only reviewer | Reviewed the completed code and documentation. Required a larger hold for the other-app control and validation of legitimate post-reset drops; fixes applied. |
| `git diff --check` | Passed. |

No new Windows runtime run, push, PR comment or merge was performed. Repaired
timings, strict late-decision rejection, real in-process UDP/QUIC, live reset and
Windows cleanup remain pending the next Actions run. Synchronous BFE RPC can
still delay the worker past a hold deadline; the patch rejects late authorization
but does not provide a hard release-time bound or bounded receive backlog.

Subscribe4's source-level CALLBACK4/EVENT5 pairing matches Microsoft's API
declarations. The unknown-direction anomaly remains unresolved; no ABI/version
mismatch was established. A further runtime diagnostic should correlate raw
classifyAllow fields from identical callback/Enum3/Enum5 events.

## Lower-latency research follow-up

The next implementation compares inline lookup with filter capability caching
off/on and asynchronous lookup with the same ownership/decision checks. The
background executor owns one immutable request/result at a time, tags subjects
with tuple/capture/generation, discards failed or stale results and joins before
BFE cleanup. Past retry times cannot spin the worker while a query is active.
Queries report create/enum/destroy/process elapsed time, call/event counts,
backpressure, cache activity and query-thread CPU. These CPU samples exclude BFE
service and other process/thread work.

A separate `ale-endpoints.cpp` shadow probe uses documented native WFP
FwpsAleEndpoint APIs to inspect live appId/tuple/endpointId while packets are held.
It neither changes routing nor invents event timestamps or socket generations.
The harness requires complete, unique matching observations inside the hold
interval; unavailable, partial, late or ambiguous observations are inconclusive.
The extra sampler cases are excluded from normal performance comparisons.

Subscribe3 is added alongside Subscribe2/4, with 1500 ms diagnostic drain cases,
raw allow fields/ABI metadata and Enum3/Enum5 comparison over the same time window.
Unknown direction stays unusable. Raw callbacks without usable target ownership
can no longer make WFP negative controls pass.

The prepared Windows matrix covers Server 2022 and 2025 separately. The in-process
harness now waits for cooperative collector exit on failure and invokes the
persisted guarded BFE restoration after forced or failed engine exit. No live
Windows performance improvement is asserted by these implementation changes.

Local verification: 46 Python tests passed with loopback permission, including
new red-first authority, shadow snapshot, mode-selection and cleanup regressions;
all five portable native helper programs passed. Four changed Windows programs
(`native-events`, `inproc`, `ale-endpoints`, `client`) have x64 object-compilation
checks with LLVM-MinGW and official API headers. PowerShell 7.5.4 parsed both
Windows scripts, and documentation whitespace/local-link checks passed.
Native event snapshots cap individual app-ID copies at 64 KiB and total copied
app-ID bytes per request at 8 MiB, discarding the entire result on overflow.
Development and review use
separate agents under AGENTS.md. See
[the low-latency research](windows-per-app-low-latency.md) for exact mechanisms,
official references, remaining reliability limits and benchmark acceptance.

## Executed comparison on Server 2022 and 2025

Published implementation `58e2f80` to the existing draft PR #95. Its first
Windows matrix, run 42355949237, failed at the ALE probe's MSVC SDK include
dependency and did not execute traffic. The one-line winternl.h correction in
`804e004` built on both operating systems. That commit's
[run 42356168781](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42356168781)
executed both matrices; standard repository CI and the model job passed.

The Windows jobs are red because subscription comparisons, Security UDP at the
short hold and ALE shadow alternatives fail or are inconclusive. Per case, all
16 non-shadow in-process cases passed on each OS, and all 11 split poll cases
reached expected statuses. Deterministic leak cases now prove three selected
timeouts, three later ownership matches, three checked RST pairs and three
client-observed resets, with non-selected echo controls.

Async reduced the 50-client decided-direct added-latency p95 from 17.260 to
2.683 ms on build 20348 and from 32.901 to 12.043 ms on build 26100. First-decision
latency was mixed. Fresh snapshot creation, including rejected filter attempts,
occupied about 82–90% of elapsed query work in the cache-on concurrency cases.
Caller CPU sampling was too coarse for a CPU-efficiency conclusion and excludes
the BFE service.

Subscribe2/3 still delivered zero raw callbacks after the longer drain. Subscribe4
delivered stored events about one second late. Exact callback/Enum5 identities
agree on raw direction/loopback fields, while Enum3 differs; undocumented
normalization was not used for authority. The ALE API completed without errors
but returned System rather than the original app, and repeated endpoint IDs
across tuples. All four shadow cases correctly stayed inconclusive.

The complete tables, exact jobs/artifacts, native field examples, compile repair
and evidence boundaries are retained in
[evidence/wfp-divert-run-42356168781.md](evidence/wfp-divert-run-42356168781.md).
This extends the restricted runtime evidence; it does not qualify desktop
Windows, external routing, sustained load, safe reuse or UDP forwarding.
