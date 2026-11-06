# Windows per-app review execution record

Date: 2026-11-06. Baseline: `ec5f13dbfdf1a43dc91174d29bc6510add7dfca9`.

This records review activity and subsequent PoC preparation, not Windows runtime measurements.

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

Windows execution results:

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
