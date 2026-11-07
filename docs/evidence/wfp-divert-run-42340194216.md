# WFP divert run 42340194216

Source: https://github.com/lukeo3o1/gateinto-dev/actions/runs/42340194216
Job: 128305938309 (windows-2022, image version 20261101.353.1, OS 10.0.20348)
Head: edba3041e675312e12e7cc7417e67952822faedc
Summarized from the decoded job log of the "Run first-packet hold and TCP redirect experiments" step. Values are copied from the per-case result JSON; the full uploaded trace is in the run artifacts.

Topology: one host, IPv4, controlled loopback echo, plus `external-*` cases that only connect to `140.82.112.6:443` (api.github.com) without payload, echo or proxy validation.

The job conclusion is **failure**. The step fails because Subscribe2 and Subscribe4 cases and `hold-security-udp` fail (see below). The 11 poll-mode cases all reached their pass status.

## Poll mode (`wfp_api: poll`)

Configuration recorded by every case: `wfp_poll_timer: high_resolution`, `wfp_poll_interval_ms: 5`, `wfp_poll_overlap_ms: 300`, enumeration filtered to CLASSIFY_ALLOW (`wfp_enum_type_counts` only contains type 6), `collect_after: 1`, `keywords_after: 16`.

| Case | Status | Decisions / selected / redirected | notification−capture p50 / max ms | decision−capture p50 / max ms | Gateway CONNECTs |
| --- | --- | --- | --- | --- | --- |
| hold-wfp-poll-tcp | PASS_RESTRICTED_CASE | 6 / 3 / 0 | 11.8 / 14.7 | 13.8 / 16.9 | 0 |
| hold-wfp-poll-udp | PASS_RESTRICTED_CASE | 12 / 6 / 0 | 10.4 / 15.2 | 15.9 / 16.9 | 0 |
| hold-wfp-poll-delayed | PASS_RESTRICTED_CASE | 6 / 3 / 0 | 10.7 / 13.3 | 112.7 / 113.5 (artificial consumption delay) | 0 |
| hold-wfp-poll-too-late | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 12.5 / 15.6 | none (no decision by design) | 0 |
| hold-wfp-poll-missing | PASS_RESTRICTED_CASE | 0 / 0 / 0 | 11.3 / 14.2 | none (no decision by design) | 0 |
| redirect-wfp-poll | PASS_RESTRICTED_CASE | 9 / 3 / 3 | 12.8 / 14.8 | 14.9 / 17.0 | 3 |
| external-wfp-poll-tcp | PASS_RESTRICTED_CASE | 2 / 1 / 0 | 16.6 / 17.2 | 17.9 / 18.5 | 0 |
| retransmit-wfp-poll | PASS_RESTRICTED_CASE | 9 / 3 / 3 | 13.9 / 16.7 | 16.3 / 18.8 | 3 |
| reuse-wfp-poll | CHARACTERIZED_REUSE_REJECTION | 2 / 1 / 1 | 16.4 / 16.4 | 18.2 / 18.2 | 1 |
| hold-wfp-poll-tcp-repeat | PASS_RESTRICTED_CASE | 6 / 3 / 0 | 14.0 / 16.5 | 15.0 / 17.6 | 0 |
| redirect-wfp-poll-repeat | PASS_RESTRICTED_CASE | 9 / 3 / 3 | 25.6 / 29.2 | 27.4 / 31.3 | 3 |

In every case `native_after_packet_capture` equals the matched tuple count: the notification always arrived after WinDivert captured the packet, so the hold buffer, not event ordering, carried the decision. `reuse-wfp-poll` reports `reused_syn_rejected: true` and `nonselected_client_disrupted: true`; its semantics field reads "Characterized conservative rejection; not normal application connectivity".

### Poll loop cost

| Case | Collector lifetime s | Polls | Polls with new events | Mean / max poll ms | Max timer overshoot ms | Poll share of cycle |
| --- | --- | --- | --- | --- | --- | --- |
| hold-wfp-poll-tcp | 0.465 | 37 | 2 | 7.38 / 9.33 | 0.49 | 0.59 |
| hold-wfp-poll-udp | 0.476 | 38 | 5 | 7.35 / 9.33 | 0.51 | 0.59 |
| hold-wfp-poll-delayed | 0.530 | 43 | 2 | 7.16 / 8.76 | 0.56 | 0.58 |
| hold-wfp-poll-too-late | 0.673 | 54 | 2 | 7.24 / 10.19 | 0.53 | 0.58 |
| hold-wfp-poll-missing | 0.689 | 56 | 2 | 7.09 / 9.66 | 0.53 | 0.58 |
| redirect-wfp-poll | 0.529 | 36 | 6 | 9.46 / 27.79 | 0.51 | 0.64 |
| external-wfp-poll-tcp | 0.425 | 34 | 2 | 7.32 / 9.56 | 0.51 | 0.59 |
| retransmit-wfp-poll | 2.504 | 187 | 9 | 8.14 / 43.26 | 1.64 | 0.61 |
| reuse-wfp-poll | 0.543 | 40 | 7 | 8.37 / 20.04 | 0.75 | 0.62 |
| hold-wfp-poll-tcp-repeat | 0.477 | 38 | 2 | 7.36 / 9.31 | 0.92 | 0.59 |
| redirect-wfp-poll-repeat | 0.564 | 42 | 6 | 8.23 / 21.19 | 0.54 | 0.61 |

Lifetime is `wfp_poll_thread_stop_qpc − wfp_poll_thread_start_qpc`. Poll share is `wfp_poll_total_ms / (wfp_poll_total_ms + wfp_poll_sleep_total_ms)`. All cases: `wfp_poll_errors: 0`, `wfp_poll_missed: 0`, `wfp_enum_errors: 0`, `wfp_enum_truncated: false`, `queue_dropped: 0`, `errors: 0`.

## Other sources in the same job

| Source | Cases | Result |
| --- | --- | --- |
| Subscribe2 | hold tcp/delayed/udp, redirect, external | FAIL or NO_OWNERSHIP_CONFIRMATION: `wfp_count: 0`, `wfp_raw_count: 0` while `wfp_enum_total` was 6–44 per case. |
| Subscribe2 | hold missing/too-late, redirect missing | INCONCLUSIVE_NO_NATIVE_EVENTS: no callbacks, so WFP attribution was not exercised. |
| Subscribe4 | hold tcp/udp/delayed, redirect, external | FAIL or NO_OWNERSHIP_CONFIRMATION, although `wfp_raw_count` equalled `wfp_enum_total` (6–42). |
| Subscribe4 | hold missing/too-late | PASS_RESTRICTED_CASE (no ownership expected). |
| Security 5156 | 10 cases (9 with timing; `redirect-security-missing` has none by design) | notification−capture p50 329–865 ms, max 1024 ms. Passed: TCP hold, delayed and too-late; redirect with 3 bridge tunnels and 3 gateway CONNECTs; redirect with missing ownership; SYN retransmit; external connect; and UDP hold at 2000 ms. Reuse ended as CHARACTERIZED_REUSE_REJECTION. `hold-security-udp` (1000 ms hold) FAIL: max 1011 ms exceeded the hold. |

Failing cases listed by the step (`ci.ps1:134`):

```text
PoC cases failed: hold-wfp-tcp, hold-wfp-delayed, hold-wfp-missing, hold-wfp-too-late, hold-wfp-udp,
hold-security-udp, redirect-wfp-missing, redirect-wfp, external-wfp-tcp, hold-wfp-subscribe4-tcp,
hold-wfp-subscribe4-udp, hold-wfp-subscribe4-delayed, redirect-wfp-subscribe4, external-wfp-subscribe4-tcp
```

No poll-mode case is in this list.
