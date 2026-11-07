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
tcp_syn_vs_event_delivery: MEASURED (event after capture; poll p50 10.4-25.6 ms)
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

Figures for runs 42280670136 and 42282264784 are from the summary of their job logs; their head SHAs and job IDs were confirmed with `gh run view`. Run 42340194216 figures were re-extracted from its job log, and only it has an excerpt in `docs/evidence`.
