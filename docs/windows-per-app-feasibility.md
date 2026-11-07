# Windows per-app transparent proxy feasibility review

Review date: 2026-11-06. Source baseline: `ec5f13dbfdf1a43dc91174d29bc6510add7dfca9`.

Updated 2026-11-07 with Windows runtime evidence from GitHub Actions runs 42280670136, 42282264784, 42340194216, 42348888370 and 42356168781 of the PoC at `experiments/wfp-divert`. See [Measured Windows evidence](#measured-windows-evidence) for exact runs and limits.

## Verdict and evidence boundary

| Transport | Verdict | Meaning |
| --- | --- | --- |
| TCP | Conditionally usable (有條件可用), demonstrated only for a restricted topology | On Server 2022/2025 runners (builds 20348/26100, single host, IPv4), newly started TCP flows were held at first packet, attributed by polled native WFP stored net events (`FwpmNetEventEnum3`, CLASSIFY_ALLOW), and redirected through a translating bridge and the real Gateinto proxy to a CONNECT fixture. Async lookup reduced already-decided packet stalls in a 50-client case; first-decision speed did not consistently improve. Subscription delivery was not usable as the ownership source. Arbitrary flows, client Windows SKUs, external routing and sustained load remain unqualified. |
| UDP | Cannot guarantee (無法保證) with current Gateinto | Packet capture and ALE attribution are separate from transport support. In the same restricted topology, polled WFP attribution of first UDP datagrams arrived within the hold deadline, so attribution timing worked under hold. Gateinto implements TCP byte tunnels, not a datagram gateway protocol, so UDP was never forwarded. A new UDP-capable upstream and adapter would be needed; attribution races would remain. |

Neither transport qualifies as precise takeover (精確接管). If “conditionally usable” means a working tested product rather than a restricted experiment result, TCP is also unqualified and must not be released on this evidence.

The required division is preserved: native WFP net events (`FwpmNetEventSubscribe*` callbacks or `FwpmNetEventEnum*` polling of the stored net-event history) or Security 5156 supply ownership; official WinDivert at `NETWORK` captures and reinjects packets. `SOCKET`/`FLOW` may be logged as diagnostic controls only. IP Helper tables, ETW TCP providers, PID polling and DLL injection must not become fallback ownership sources. Polling `FwpmNetEventEnum3` reads the same BFE-produced net events as a subscription and is not PID or process-table polling. No new kernel driver is proposed.

The review workspace is Linux x86_64 (kernel `6.18.57`), without a supplied Windows host or Windows driver execution facility. A follow-up implements an independent [PoC and Actions workflow](../experiments/wfp-divert/README.md) to test the first-packet-hold hypothesis. Cross-compilation and local model tests are not Windows runtime evidence; the only Windows runtime evidence is the Actions runs listed below. UDP forwarding remains unimplemented. The run record is [windows-per-app-review-log.md](windows-per-app-review-log.md).

## Measured Windows evidence

Earlier runs used `windows-2022` (OS build 20348); run 42356168781 also used Server 2025 (build 26100). All use one host, IPv4, controlled loopback endpoints, test EXEs A/B and the official signed WinDivert driver. `external-*` cases connect to `api.github.com:443` for connection/attribution only, with no payload, echo or proxy validation. Every PoC Windows job concluded failure because subscription comparisons fail; the 1000 ms Security UDP and later ALE shadow cases also do not pass. The statements below are per case.

| Run (head) | Measured | Consequence |
| --- | --- | --- |
| 42280670136 (`a46493b`) | `FwpmNetEventSubscribe2` delivered 0 callbacks of any type in every case, while `collect_after=1` and `keywords_after=16` confirmed the engine options were applied. `FwpmNetEventEnum3` found 6–72 stored CLASSIFY_ALLOW events per case with the correct app path and full outbound tuple at layer 48 (ALE_AUTH_CONNECT); their `event_filetime` was about 0.03–0.09 ms before WinDivert captured the first packet. | Ordinary Win32 TCP/UDP allow events are produced on this build; Subscribe2 does not deliver them here. |
| 42282264784 (`ae22135`) | `FwpmNetEventSubscribe4` delivered callbacks equal to the enumeration total, but receipt was about 1004 ms after the event (apparently batched). classifyAllow read through `FWPM_NET_EVENT5` reported direction unknown and `is_loopback` true, contradicting the same events read through Enum3 (outbound, not loopback), so those events were unusable. Poll mode (5 ms `sleep_for`, 1 s overlap, unfiltered) passed 7/7 cases with notification−capture 20–46 ms. | Subscribe4 is too late and its decoded fields are not trusted; polling is viable. |
| [42340194216](evidence/wfp-divert-run-42340194216.md) (`edba304`) | Poll mode on a high-resolution waitable timer (5 ms wait), enumeration filtered to CLASSIFY_ALLOW, 300 ms overlap. 11/11 poll cases reached their pass status: hold tcp, udp, delayed, too-late and missing; redirect through the real Gateinto proxy and CONNECT fixture; external connect; SYN retransmit; tuple reuse (CHARACTERIZED_REUSE_REJECTION); repeats of hold tcp and redirect. | First-packet hold with polled native ownership works for this restricted topology. |
| [42348888370](evidence/wfp-divert-run-42348888370.md) (`e3336bd`) | All 11 split poll cases again reached expected statuses. Seven in-process cases reported PASS, but decision latency omitted blocking enumeration time, UDP launched TCP clients, and leakcheck had zero timeouts/leaks/RSTs. QUIC failed before readiness. Reconstructing complete small-case decision logs gives p50 about 25.7–33.1 ms for TCP hold/redirect, rather than the reported 10.4–11.9 ms. | In-process TCP redirection is promising, but a speedup, real UDP/QUIC coverage and live connection termination are not established. Validation repairs are locally tested and await a new Windows run. |
| [42356168781](evidence/wfp-divert-run-42356168781.md) (`804e004`) | Server 2022 and 2025: 16/16 non-shadow in-process cases pass per OS, including real UDP/QUIC controls and client-observed reset after deliberate late ownership. All 11 split poll cases per OS reach expected statuses. In 50-client cases async reduces decided-direct p95 from 17.3 to 2.7 ms and 32.9 to 12.0 ms respectively. Snapshot creation accounts for about 82–90% of cache-on concurrency query elapsed time. Subscribe2/3 deliver no callbacks; Subscribe4 remains about 1 s late. ALE shadow tuples report System and fail original-app matching. | Prefer async lookup to isolate already-decided traffic from synchronous BFE work. A universal first-packet speedup, CPU saving and replacement ownership source are not established. |

Run 42340194216 poll-mode measurements:

- notification−capture p50 10.4–25.6 ms per case (max 29.2 ms). decision−capture p50 13.8–27.4 ms; the delayed case was 112.7 ms because of its deliberate consumption delay. In every case the native observation arrived after packet capture, so the hold buffer, not event ordering, carried the decision.
- `wfp_poll_errors` 0, `wfp_poll_missed` 0, enumeration errors 0, no truncation, no queue drops. Timer `high_resolution` with maximum overshoot 0.5–1.6 ms.
- Mean poll duration 7.1–9.5 ms, maximum 8.8–43 ms. Collector lifetime was about 0.43–0.69 s per case (2.5 s for retransmit), which explains the 34–187 polls. Polling took about 60% of each poll+wait cycle, so the BFE RPC cost is not negligible.
- Redirect cases passed only with other-app noninterference (no B proxy packets) and the expected upstream CONNECT destinations and counts (3 bridge tunnels and 3 gateway CONNECTs; 1 for reuse). The reuse case is a characterized conservative rejection: the reused SYN was dropped and the non-selected client was disrupted, which is not normal application connectivity.
- Security 5156 in the same job gave notification−capture of roughly 330–1024 ms across the 9 timed cases. It passed TCP hold, delayed and too-late; redirect with 3 bridge tunnels and 3 gateway CONNECTs; redirect with missing ownership; SYN retransmit; external connect; and UDP hold at 2000 ms. Reuse ended as CHARACTERIZED_REUSE_REJECTION. The UDP case at a 1000 ms hold failed.

Still unqualified: Windows 10/11 client SKUs and builds beyond those tested; external routing beyond connect-only probes, including a topology that denies direct access; IPv6, fragmentation and other packet modifiers; sustained load, bounded receive backlog and production tuple reuse; polling cost at scale and long collector lifetimes; event-history eviction; and UDP forwarding. Subscribe4/CALLBACK4/EVENT5 pairing and layouts match the SDK. Latest matched callback/Enum5 records agree on raw direction 14593 and loopback 1, while Enum3 returns 0/0 for the same identity; this narrows the anomaly to a version-dependent representation, without establishing its semantics or an ABI corruption. A zero wrong-app count over finite runs is evidence for those runs only.

## Existing source

| Source | Finding and consequence |
| --- | --- |
| `src/proxy/mod.rs:269`, `:298` | Loopback-only `TcpListener`. It is an explicit proxy listener, not a transparent ingress. |
| `src/proxy/mod.rs:418`, `:434`, `:450` | Parses CONNECT, obtains target from that request, then sends local HTTP 200. Redirecting raw TLS or arbitrary TCP directly here will fail or insert HTTP into the app's stream. |
| `src/http.rs` (`parse_connect_request`), `src/proxy/h2.rs:205`, `src/proxy/pool.rs` | Validates an authority and opens an ordinary TCP CONNECT tunnel using TLS to the gateway, with HTTP/2 or HTTP/1.1. No CONNECT-UDP or datagram framing. |
| `src/proxy/os_user/windows.rs:9`, `:58`, `:78`, `:81`, `:138` | Uses `GetExtendedTcpTable`, opens the owning process, checks its token's user and optionally its Job. This is local proxy authentication, neither native WFP subscription nor EXE selection. |
| `src/proxy/local_auth.rs:132` | Successful OS-user auth is sufficient; otherwise credentials can authenticate. A separate adapter's socket identifies the adapter, not the intercepted app. Preserve this distinction. |
| `src/proxy/mod.rs:473`, `src/proxy/routing.rs` | Mixed routing can open a direct target connection. Force `Route::Gateway` for this experiment. Standalone `session browser` already chooses Gateway (`src/main.rs:659`); do not assume every GUI/agent session does. |
| `Cargo.toml`, `src/` | No WinDivert binding, WFP event subscription, original-destination map, transparent adapter or UDP relay found. Existing Windows features do not include WFP or Windows Event Log APIs. |

A dedicated session for the adapter should use session credentials and Gateway routing. Do not disable authentication globally or borrow a browser Job-restricted session: the bridge normally is outside that Job. The bridge must consume the local CONNECT response, including buffered early payload, before exposing tunnel bytes to the app. Existing explicit-proxy tests are not evidence for transparent redirection.

## 1. Ownership sources

| Property | Native net-event subscription | Security event 5156 |
| --- | --- | --- |
| API | `FwpmEngineOpen0`, `FwpmNetEventSubscribe1` (Windows 8) or `Subscribe2` (Windows 10 1607+); use exact matching callback/event types [1] | `EvtSubscribe` on Security, query `*[System[EventID=5156]]`; render XML with `EvtRender` [5,6] |
| Allowed TCP/UDP | `CLASSIFY_ALLOW` exists from Windows 8; enable allow keyword, not merely collection. The type is general; do not confuse it with app-container-only `CAPABILITY_ALLOW`. Actual ordinary Win32 coverage on each target Windows build remains a mandatory test [2,3,4]. | Documents permitted connections, including protocol 6 and 17. Enable successful Filtering Platform Connection auditing. Not one event per UDP datagram [5,7,8]. |
| Application | `header.appId`, only if APP_ID_SET. For Win32 compare against `FwpmGetAppIdFromFileName0` output; retain raw blob/length, not just a basename or guessed drive-letter string. | EventData Application is full executable device path. Normalize configured EXE using Windows path/device mapping, not suffix matching. |
| PID | **Absent** from the documented headers and classify-allow payload. User/package SID is not PID. Selecting an EXE can use App ID without PID; selecting one instance needs more evidence. | EventData ProcessID; parse XML numeric representation correctly. **System/Execution/ProcessID is the event producer, not the app.** PID is historical; a later process lookup can hit a reused PID. |
| Tuple | IP version, protocol, local/remote address and port; fields are optional and governed by flags. Direction/layer/filter/reauth information is in classifyAllow [2,9]. Reject incomplete fields. | Source/destination address/port, protocol and Direction, LayerRTID/FilterRTID [5]. Normalize outbound and inbound to local/remote consistently; do not blindly reverse by callback order. |
| Timestamp | Header FILETIME: event occurrence time. | System/TimeCreated: event creation time. Neither is callback receipt time or a socket generation ID. |
| Permissions | BFE available; engine open rights, net-event container `FWPM_ACTRL_SUBSCRIBE`, and engine option write access. Elevated admin is the lab baseline, but ACLs still govern actual calls [1,10]. | Permission to read Security and configure audit policy are separate. Use elevated admin lab session; delegated operation needs channel access/appropriate privileges. Reading is not the same as SeAuditPrivilege (generating audits). Inspect actual ACL/error results. |
| Setup | Read/save engine options; set COLLECT_NET_EVENTS=1 and OR `FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW` (0x10) into existing MATCH_ANY_KEYWORDS; restore on exit. These are shared settings, not private per subscriber [3,4,11]. | Back up audit policy; enable success on Filtering Platform Connection (GUID below), verify effective policy and Security retention. Firewall text-file logging is a different mechanism. |
| Latency / loss / repeats | Notification when ready; no documented deadline relative to NETWORK packet delivery, no exactly-once ownership journal contract. Startup gaps, disabled collection, incomplete events and consumer overload must be handled. WFP enumeration is a finite circular history, not reliable replay [1,11]. | Event Log delivery is asynchronous; high-volume audit source. Disabled auditing, log clear/rollover, consumer gaps and errors can lose observations. Bookmarks allow replay and can produce application-level repeats; strict subscriptions report some missing records [6,7,12]. |

`Subscribe0` targets Windows 7 and the older event type does not provide the Windows 8 CLASSIFY_ALLOW union. Do not “support Windows 7” by assuming all Subscribe versions have the same payload. Newer Subscribe variants do not add a documented PID or packet-correlatable socket cookie to HEADER3.

Reauthorization and classification at different layers can yield multiple observations of the same apparent tuple; replay can repeat a record. A repeated tuple is not necessarily a duplicate event. Keep raw event identities, layer/filter/reauth fields, source and receive times. For 5156 deduplicate by channel epoch plus EventRecordID, not tuple alone. Record-ID gaps in a query filtered to 5156 do not prove loss: other Security event IDs consume record IDs too.

The official UWP troubleshooting example proves the allow mechanism exists, not that every normal Win32 TCP/UDP flow on every Windows build is delivered. Record empirical coverage before choosing net events as the production source. 5156 can be the native source instead; it cannot fix notifications arriving late or never arriving.

## 2. First packets, mapping and failure behavior

ALE AUTH_CONNECT classifies TCP connect attempts and first UDP sends to each unique remote address/port. That is a kernel authorization point, before a normally permitted packet continues. It does **not** synchronously deliver the user callback first [8]. FLOW_ESTABLISHED for TCP occurs after the handshake and therefore cannot be a SYN ownership gate.

Log distinct times: WFP occurrence FILETIME, WFP callback-entry QPC, evidence-consumption/decision-ready QPC, WinDivert capture `addr.Timestamp` (QPC clock), and `WinDivertRecv` return QPC [13]. For 5156 additionally log TimeCreated and callback-entry QPC. Compare the two receive QPC values to answer which consumer received first. Compare decision-ready QPC against packet capture QPC to determine whether the ownership decision was available at interception; callback receipt alone does not establish this when evidence processing is queued or artificially delayed. Calibrate UTC/QPC using tightly bracketed `GetSystemTimePreciseAsFileTime` samples and report uncertainty and clock jumps. Never subtract raw FILETIME from QPC or label UTC audit timestamps exact classifyFn execution measurements. Ordering and latency numbers for the restricted runner topology are in [Measured Windows evidence](#measured-windows-evidence); they are not general bounds. With polling, the native receive time is when a poll observed the event, so it includes polling latency.

Proposed restricted state machine (a subset is implemented in the PoC; not production code):

1. Start the native ownership source (net-event subscription, polling of stored net events, or Security 5156 subscription) and the local adapter before admitting test apps. For a controlled destination, capture outbound TCP/UDP at NETWORK without SNIFF; otherwise a “held” copy cannot prevent escape. Receive continuously into a separately bounded userspace pending queue. Set and log driver queue length/size/time too; userspace buffering cannot recover a packet already dropped in the driver queue.
2. Normalize key to address family, protocol, local IP/port, remote IP/port, scope/interface context where relevant. A full forward/reverse tuple is essential. Two apps connecting to the same remote endpoint usually have different local ports; remote IP/port alone mixes them.
3. For a newly observed TCP SYN, create a tentative generation containing SYN sequence number and first capture QPC. Same-generation retransmitted SYNs share a decision. A conflicting SYN, reused tuple, missing lifecycle or stale event is ambiguous; invalidate rather than inherit ownership. Buffer subsequent packets too, not only one SYN/datagram.
4. Commit only with complete, direction-correct native WFP evidence that is sufficiently fresh and unambiguous under the restricted test assumptions. App ID equality alone cannot prove the event describes this generation. Late events must never revive expired pending entries. Reject conflicting native events. SOCKET/FLOW controls must not authorize a decision.
5. Pin the decision for the generation: confirmed selected app -> translate every packet both ways; confirmed other app -> reinject unchanged. Unknown at timeout or capacity -> the explicitly chosen policy below. Once any packet is sent direct, never switch that generation to the proxy after a later event.
6. Track FIN in both directions plus final ACK, RST, handshake timeout and idle expiration. Keep translated-map tombstones while packets may still arrive; FIN alone is not completion. Handle simultaneous close, retransmission and half-close. A timeout is a bound on retained state, not proof that an old event cannot arrive.
7. For UDP, make a separate entry for each destination tuple even when one socket/source port sends to many peers. UDP has no SYN sequence or FIN; idle expiry and rebinding are particularly ambiguous. Port-only ownership caches are invalid.

There is no policy that simultaneously guarantees no selected-app leakage, no disruption of other apps, finite buffering, and correct attribution when evidence is missing. Two explicit options:

| Unknown policy | Consequence |
| --- | --- |
| Release unchanged after deadline, pin direct | Never intentionally proxy unknown packets, but selected-app traffic can bypass Gateinto and a restricted service can fail. Other apps incur buffering delay. |
| Drop/fail after deadline | Avoids direct leakage for captured unknown traffic but can break other apps. TCP might retransmit; UDP first datagrams may be permanently lost. |

Use release-unchanged for the noninterference experiment and separately test drop mode. Neither may be silently described as precise takeover. An unambiguous “unknown” can be kept out of Gateinto in userspace; detecting every ambiguity is not guaranteed: a delayed event for an earlier flow can have the exact same tuple and EXE as a later packet. Timestamps, quarantine and conservative rejection reduce exposure but do not create a missing generation cookie. Unlimited waiting also cannot distinguish an event that will never arrive.

| Failure | Miss / wrong app | Userspace remedy and remaining limit |
| --- | --- | --- |
| Allow/audit disabled, subscription starts late, event omitted | Miss under release policy | Correct setup, readiness barrier; no recovery guarantee for already authorized flows. |
| SYN/datagram reaches NETWORK before ownership | Miss if sent immediately | Bounded buffering can handle measured latency; no finite universal bound. |
| Buffer/driver queue exhaustion | Packet loss or direct miss | Bounds/backpressure/metrics; cannot guarantee other-app normal behavior under overload. |
| Keyed only by destination or source port | Wrong app/destination | Use full tuples and injective translated map; avoidable implementation defect. |
| Delayed old event after tuple/port reuse, restart with stale cache | Wrong app/generation | Flush cache on restart, reject ambiguous generations and tombstone; no fully reliable passive cookie from these sources. |
| PID reuse / EXE basename matching | Wrong app | Use event's App ID/path; do not resolve old PID into current EXE. Instance identity remains limited. |
| UDP shared/reused port or identical tuple across sockets | Wrong socket/app | Detect conflicts and decline; packet tuple alone may not distinguish senders. |
| App delegates I/O to helper/broker/service | Apparent miss | Native ownership is the network process; explicitly select helper EXEs if desired. It cannot infer the requesting UI app. |
| Fragments, IPv6 scope, VPN/NAT or other packet modifiers | Miss or wrong mapping | Restrict initial scope; implement and test parsing, fragment association, layer context and coexistence before expanding. |

## 3. Actual TCP redirection design to test

The following is a candidate, not observed behavior. Use a controlled IPv4 destination R:r, one selected EXE A and distinct EXE B, with fresh sockets and no shared ports. Start the bridge listener before enabling diversion. Use a dedicated Gateinto credential session with route Gateway.

An explicit packet translation layout avoids pretending that changing only destination port is enough:

```text
Original app socket:       L:p -> R:r
Translated listener input: L:q -> L:t       (local alias q unique per live mapping)
Listener output:           L:t -> L:q
Restored socket input:     R:r -> L:p

adapter TCP stream -> authenticated CONNECT R:r to Gateinto loopback listener
Gateinto -> TLS to configured gateway -> CONNECT R:r -> controlled server
```

Allocate/reserve q to avoid local TCP socket/alias collisions and retain it through teardown/quarantine. Keep an injective map `(L,q,L,t,TCP) -> (L,p,R,r,TCP,generation,app-evidence)` **before** reinjecting the SYN. All original outgoing packets use the forward rewrite; listener responses use its inverse, reconstructing the original remote IP/port and injecting in the direction accepted by the original TCP socket. Recompute IP/TCP checksums and respect address/interface metadata. Local delivery, direction flags, routing to a local address and alias reservation must be validated on Windows; the diagram is not proof Windows accepts this layout. Use the official streamdump example as a packet-to-local-TCP reference [14], not as proof of native-WFP attribution or a finished NAT.

The bridge recovers original destination from this map using its accepted peer **and local endpoint**, not from `getsockname`, Host, SNI, or an unsupported assumption that WFP redirect-context IOCTLs apply to WinDivert NAT. A dedicated bridge-originated CONNECT supplies the recovered IP literal and port to Gateinto. Ordinary HTTP CONNECT preserves TCP bytes; it does not discover the original hostname. If gateway policy needs a hostname rather than an IP literal, additional design is needed, and SNI cannot be assumed for arbitrary TCP.

The bridge must parse a successful local CONNECT response before relaying, preserve response early data, and handle rejection, half-close and backpressure. Never send the local proxy's HTTP 200 into the original app's stream. Gateinto then opens the upstream CONNECT through its existing pool/mTLS path. Verify upstream logs rather than assuming receipt at the local listener proves the upstream was used.

Exclude bridge-to-Gateinto local traffic, listener traffic after inverse translation, and Gateinto's gateway connections. For the one-destination PoC use a gateway endpoint different from R:r and a filter scoped to R:r plus exact listener response paths. For a broader implementation establish Gateinto/bridge-originated socket bypass entries before connect (using their own bound endpoints is bypass bookkeeping, not ownership of third-party traffic), or wait for native WFP evidence confirming their excluded App IDs. Do not use NETWORK `processId`: it does not exist there. A blanket “all loopback bypass” cannot precede listener inverse translation, and `!impostor` alone is not a complete self-exclusion policy. Log reinjection and check that packets are not repeatedly recaptured across priorities/other handles [13].

UDP needs another design: per-destination datagram association, message boundaries, reply sender restoration, fragmentation/MTU/ICMP handling, timeouts, and an upstream datagram protocol such as a separately implemented CONNECT-UDP capability. Raw UDP cannot be made functional by writing datagrams to the existing CONNECT byte stream. UDP/QUIC success must be separately demonstrated end to end.

## 4. Windows reproduction procedure

### Preparation and required harness

Use an isolated Windows 10/11 x64 machine with administrator access, Windows SDK/MSVC, official signed WinDivert 2.2.x release, and a second controlled machine hosting TCP/UDP echo and an HTTPS CONNECT gateway. Record OS build, adapter/VPN/firewall settings, driver/DLL hashes and signatures, Gateinto SHA, gateway certificate/ALPN/auth mode, target EXE absolute paths and hashes. Do not disable driver signature enforcement. Existing Gateinto fixture success can verify explicit CONNECT only.

Before changes, in an elevated PowerShell terminal:

```powershell
New-Item -ItemType Directory -Force C:\gateinto-wfp-lab
Set-Location C:\gateinto-wfp-lab
auditpol /backup /file:audit-before.csv
auditpol /get /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable
wevtutil gl Security > security-channel-before.txt
netsh wfp show state file=wfp-before.xml
```

Confirm each command succeeds and check effective audit policy again (GPO can override it). Read-only sanity query after generating connections:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156} -MaxEvents 20 |
  ForEach-Object { $_.ToXml() } | Set-Content -Encoding utf8 security-5156-sanity.xml
```

This query is retrospective, **not** a delivery-latency measurement. The missing native harness must:

- Subscribe1/2 with matching SDK callback, save/set/restore engine options, deep-copy valid event fields before returning, and log callbacks without blocking them on network I/O. Keep net events and 5156 as separately selectable ownership sources; do not merge them into assumed truth.
- Use EvtSubscribe future-events plus Strict, record delivery/error actions, render raw XML, persist bookmarks and distinguish log-clear epochs. Do not treat historic replay as fresh authorization.
- Open WinDivert NETWORK scoped to the test target (and, for redirection, listener reply paths). Start with SNIFF observation, then repeat with divert-and-buffer. Log capture QPC, receive QPC, packet tuple, TCP flags/sequence/ack, length and decision. Optional SOCKET/FLOW comparison logs must be inaccessible to the ownership decision function.
- Implement the pending state machine and adapter described above, with configurable 10/50/250/1000 ms hold deadlines, 0/10/100/1000/5000 ms artificial ownership-consumption delays, deterministic skip-every-N, reverse delivery, duplicate delivery and stale-event replay. Record raw receive time separately from delayed consumption time.
- Build two distinct Win32 test EXEs, A and B (not merely two instances of the same EXE); log PID, creation time, explicit local bind, connect/send/close times, destinations and unique payload nonces as test ground truth only. Support TCP half-close/RST, UDP sendto multi-peer, repeat binds and short-lived instances.

The follow-up PoC implements a subset of these harness requirements, described in its README. The matrix below remains the full qualification specification: the initial workflow does not cover every row. No Windows runtime success is inferred from the presence of source or CI configuration.

### Test matrix and pass evidence

Status after the runs in [Measured Windows evidence](#measured-windows-evidence). PARTIAL means a small restricted subset ran on windows-2022 build 20348 only; it does not satisfy the row's pass condition.

| ID | Status |
| --- | --- |
| W1 | PARTIAL: collection and allow keyword set together, ordinary A/B TCP and UDP coverage counted by source/type/layer. Independent toggles and audit off/on not run. |
| W2 | NOT RUN: elevated only. |
| O1 | PARTIAL: idle host, 2–6 client runs per case (at most 6 TCP connections or 12 UDP destination tuples), p50/max only. 1,000 flows and load not run. |
| M1 | PARTIAL: A and B to the same controlled R:r with distinct local tuples, 3 iterations each per case. |
| M2 | PARTIAL: one SYN retransmit scenario passed. |
| M4 | PARTIAL: full-tuple reuse characterized as conservative rejection that disrupts the non-selected client. |
| M6 | PARTIAL: missing, too-late and delayed ownership passed. Duplicate/reorder and stale replay against real reused sockets not run. |
| R1 | PARTIAL: nonce returned through bridge, Gateinto and a local CONNECT fixture. Direct path was not denied at a controlled network. |
| R2 | PARTIAL: B unchanged and expected gateway CONNECT counts. Reconnect and recursion stress not run. |
| M3, M5, M7, R3, R4 | NOT RUN or not qualified. |
| U1 | NOT RUN end to end; UDP forwarding remains unimplemented. |

| ID | Execution | Required evidence / pass condition |
| --- | --- | --- |
| W1 | Toggle collection and allow keyword independently; ordinary A/B TCP and UDP; audit success off/on | Coverage counts by source/type/layer/field flags, including missing App ID/PID, no confusion with capability events; preserve baseline firewall policy. |
| W2 | Run non-elevated and elevated subscribers; disable/restart subscriptions; inspect API errors | Exact permissions/errors and startup readiness, not a blanket “requires admin” guess. |
| O1 | 1,000 fresh TCP and UDP flows, idle host then CPU/I/O load; SNIFF then buffering | Raw timestamps and counts, WFP-after-packet count, delivery p50/p95/p99/max and clock uncertainty. UDP first datagram included. No invented latency bound. |
| M1 | A and B simultaneously connect to identical R:r, 1,000 iterations | Different local tuples, A enters bridge/gateway only, B unchanged; nonces agree at target and gateway. |
| M2 | Drop first SYN at controlled receiver, permit retransmission; repeat with delay injection | One generation/CONNECT, no map replacement on retransmit; sequence numbers and SYN attempts retained. |
| M3 | FIN/half-close, simultaneous close, RST, aborted connect, idle timeout | Bidirectional data/EOF preserved; maps retained for late packets and eventually reclaimed, no stale remap. |
| M4 | Rebind same source port to different remotes; then attempt same full tuple reuse after OS permits it; alternate A/B | Log bind failures/TIME_WAIT honestly, do not call failed reuse coverage. Replay old attribution across successful reuse; reject ambiguity, never assign by source port. |
| M5 | One UDP socket sends alternating datagrams to two destinations, plus B to same destinations | Independent destination associations and restored sender identity; do not infer UDP forwarding from capture. |
| M6 | Drop all ownership for chosen flows; delay past hold timeout; duplicate/reorder; replay old A event during B generation | Zero unconfirmed CONNECTs; direct/drop pinned decisions and late-event rejection logged. Any B proxying fails the design. |
| M7 | Saturate driver/userspace queues; stop consumer, restart service; clear/roll Security log in disposable VM | Loss/overflow/error counts, bounded memory, explicit policy, no stale cache authorization or presumed exactly-once replay. |
| R1 | A sends non-HTTP TCP nonce to controlled R:r, then target TLS; enable actual NAT + adapter | Listener accepts, map yields exact R:r, bridge sends authenticated CONNECT, gateway records upstream CONNECT R:r, server returns nonce to original socket. Local/direct path cannot explain success. |
| R2 | Run B simultaneously; run Gateinto gateway connection; repeat bridge creation and upstream reconnect | B never reaches bridge; Gateinto connects upstream once as expected, no recursive CONNECTs or injection loop; gateway traffic excluded. |
| R3 | Large bidirectional data, early server data, half-close, gateway denial/timeout | Hashes and shutdown agree, local HTTP headers never appear in app payload; failure closes cleanly. |
| R4 | IPv6, fragmentation, network changes and other WinDivert handles | Separately qualify each expansion; initial IPv4 result must not imply these pass. |
| U1 | Attempt UDP through current Gateinto | Source review predicts unsupported; packet capture alone cannot pass. Future UDP implementation needs target/gateway/client datagram nonces, boundaries and replies. |

For R1, additionally make R:r reachable from the gateway while denying a direct A-to-R path at the controlled network, without suppressing the local ALE allow event. Record both network paths and disable mixed routing. This distinguishes true upstream use from a direct-route false positive. Do not treat an authorization block before packet capture as a successful redirection test.

Required artifacts per run: `manifest.json`, native-WFP JSONL, raw 5156 XML and callback JSONL, NETWORK packet trace/PCAP plus metadata, optional control-only SOCKET/FLOW JSONL, decision/map transitions, adapter accept/CONNECT logs (credentials redacted), Gateinto debug output, gateway CONNECT log, target/client nonce and hash logs. Include emitted/observed/missing/repeated counts separately for each source and transport. The trace record must include run ID, record sequence, source, occurrence time, receipt QPC, consumption QPC, full tuple, app blob/path, nullable PID, layer/filter/reauth, generation, action and reason. A zero wrong-app count over a finite run is evidence for that run, not a universal guarantee.

After testing export Security evidence before restoring audit settings:

```powershell
wevtutil epl Security security-after.evtx
auditpol /restore /file:audit-before.csv
```

Restore saved BFE options through the collector's cleanup path as well, coordinate with other consumers, stop diversion, and close only handles/services created for this test. Re-run sanity checks after rollback.

## Official references

Accessed 2026-11-06. Microsoft Learn's older Logging overview predates the newer allow-event types; use versioned API/structure definitions alongside it, not as proof allow events are impossible. WinDivert maintainer documentation was accessible via its official GitHub mirror/search excerpts; direct reqrypt page fetch returned 502 here.

1. [FwpmNetEventSubscribe2: versions, notification and ACL](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe2)
2. [FWPM_NET_EVENT_HEADER3: fields and validity flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header3)
3. [FWPM_NET_EVENT_TYPE: CLASSIFY_ALLOW versus CAPABILITY_ALLOW](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ne-fwpmtypes-fwpm_net_event_type)
4. [Microsoft allow-event tracing example, keywords=19](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall) and [Microsoft keyword constant, value 16](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/WindowsFilteringPlatform/constant.FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW.html)
5. [Security 5156 schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156)
6. [EvtSubscribe: delivery models and errors](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe)
7. [Audit Filtering Platform Connection: high event volume](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)
8. [ALE layers: TCP, per-remote UDP and FLOW_ESTABLISHED](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
9. [FWPM_NET_EVENT_CLASSIFY_ALLOW0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_classify_allow0)
10. [WFP access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)
11. [WFP logging: shared settings and bounded enumeration history](https://learn.microsoft.com/en-us/windows/win32/fwp/logging), [FwpmEngineSetOption0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmenginesetoption0)
12. [Event bookmarks and missing-record errors](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events), [cross-thread event ordering](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)
13. [Official WinDivert 2.2.2 documentation](https://github.com/basil00/WinDivert/blob/v2.2.2/doc/windivert.html), sections 5.2 (layers), 5.3 (timestamps/direction), 5.8 (queue parameters), 7 (filter fields), 10 (known issues); [rendered documentation](https://reqrypt.org/windivert-doc.html)
14. [Official streamdump example](https://github.com/basil00/WinDivert/blob/v2.2.2/examples/streamdump/streamdump.c)
