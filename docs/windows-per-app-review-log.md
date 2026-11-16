# Windows per-app review execution record

Initial review: 2026-11-06; Windows evidence incorporated 2026-11-07. Source baseline: `ec5f13dbfdf1a43dc91174d29bc6510add7dfca9`.

This records the initial source review and the subsequent Windows Actions measurements. The initial NOT RUN block is historical and is superseded by the measured results below.

| Check actually performed | Observation |
| --- | --- |
| `uname -a` in the workspace | Linux kernel `6.18.57`, x86_64 GNU/Linux. |
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

Initial Windows status, before the Actions experiment existed:

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

Actually performed locally: Python attribution, bridge and diagnostic-control tests (16 passed with
local networking permission), native-event helper tests, packet decision tests, Windows x64 COFF
object compilation of both probes, and three Rust fixture tests plus Clippy
(with local networking permission). These verify model logic, source compilation
and explicit CONNECT echo only. Actual Windows results are below. Full local cross-linking was not established because the
supplied libc++ bitcode and local linker versions differ; Actions uses MSVC.

Independent review corrected cleanup to stop collectors cooperatively and retain
BFE recovery state, excluded private credentials from artifacts, required
per-client effective decisions and upstream CONNECT evidence, and made final
collector errors/overflow fail a case. See the PoC README for current restrictions.

## Measured Windows execution

The successful limited TCP result is in [Actions run 42278267576](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42278267576), head `e2990fa13365ca666644ae8797a2f11e2904fe25`, on `windows-2022` (Windows Server 2022, build 20348; runner image 20261101.353.1). The job compiled the fixture and native programs with MSVC and loaded official signed WinDivert 2.2.2. The overall job failed because its coverage cases include failures listed below. The per-case summaries are [preserved as aggregate JSON](evidence/wfp-divert-run-42278267576-aggregate.json).

| Case | Result |
| --- | --- |
| Native Subscribe2 normal allow | No allow observations for tested local TCP/UDP or external TCP, despite successful setup. Not a usable ownership source in these runs. |
| 5156 local TCP hold | PASS: six full tuples; all notifications after SYN capture; 414.23–418.47 ms in this run. |
| 5156 local TCP redirect | PASS: three selected-app CONNECT tunnels, three other-app direct connections, six successful nonce echoes, three correct gateway CONNECTs; clean collector summary. |
| TCP SYN retransmission | PASS: same sequence and generation after injected first-SYN drop; three selected-app CONNECTs, six successful clients. |
| Reset-close and exact tuple reuse | CHARACTERIZED_REUSE_REJECTION: A worked; B successfully bound the same tuple and emitted a new SYN, which was rejected. B was disrupted. This is not a connectivity pass. |
| 5156 UDP multi-peer, 1 s hold | FAIL ownership deadline: twelve direct echoes but only six accepted controls; second-peer notifications reached about 1013 ms after capture. No forwarding claim. |
| 5156 UDP multi-peer, 2 s hold | PASS hold/direct: twelve tuple controls and twelve echoes; notifications 443.28–1006.14 ms. No UDP upstream exists. |
| Artificial +100 ms consumption delay | PASS within 2 s hold. |
| Too-late and skipped source | Zero proxy tunnels; direct policy retained. These prove the tested negative controls, not guaranteed handling of arbitrary historical event replay. |
| External TCP connect-only, 5156 | Two matches and successful connections, about 339 ms notification delay. No payload, echo or transparent external NAT was tested. |

Earlier runs are retained as failure evidence: [42276466874](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42276466874) stopped at MSVC environment initialization; [42277090526](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42277090526) and [42277688366](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42277688366) established holding/5156 but local NAT timed out. Changing local-to-local injection to outbound produced the later TCP success. They are not interchangeable results from the same code revision.

The original full trace artifacts remain attached to those historical Actions runs. Local excerpts preserve raw XML and capture timestamps. Automatic approval review rejected reposting raw telemetry into Git source and adding further full-directory raw uploads, so subsequent source evidence and new artifact uploads contain aggregate counts/latency statistics without paths, PIDs, endpoints or absolute timestamps. No permission to publish those additional raw copies is assumed.

A follow-up native-drop positive control uses one temporary firewall rule for the test executable and external TCP destination, then removes it. [Run 42394400675](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42394400675), head `0d769c50b084f02017da13de38e7f20cb60b1dc2`, repeated TCP relay/retransmission success and the UDP deadline/reuse findings. The control's client was blocked, and the native callback count was one, but its event type was not recognized as a documented drop/allow. Consequently the control **failed**; native allow coverage remains unqualified, including possible decoder/runtime-version issues. Its [aggregate record](evidence/wfp-divert-run-42394400675-aggregate.json) is preserved. The diagnostic does not authorize proxying from unknown event types.
