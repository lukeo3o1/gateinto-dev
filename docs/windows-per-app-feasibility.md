# Windows per-app transparent proxy feasibility review

Initial review: 2026-11-06; updated with Windows measurements on 2026-11-08. Source review baseline: `ec5f13dbfdf1a43dc91174d29bc6510add7dfca9`. Runtime evidence identifies its own tested PoC SHA below.

Updated with Windows runtime evidence from GitHub Actions runs 42280670136, 42282264784, 42340194216, 42348888370, 42356168781, 42394400675, completed attempts of 42468677635 and the corrected SOCKET observation run 42497668177 of the PoC at `experiments/wfp-divert`. See [Measured Windows evidence](#measured-windows-evidence) for exact runs and limits.

## Verdict and evidence boundary

| Transport | Verdict | Meaning |
| --- | --- | --- |
| TCP | Conditionally usable, demonstrated only for a restricted topology | On Server 2022/2025 runners (builds 20348/26100, single host, IPv4), newly started TCP flows were held at first packet, attributed by polled native WFP stored net events (`FwpmNetEventEnum3`, CLASSIFY_ALLOW), and redirected through a translating bridge and the real Gateinto proxy to a CONNECT fixture. Async lookup reduced already-decided packet stalls in a 50-client case; first-decision speed did not consistently improve. Subscription delivery was not usable as the ownership source. Arbitrary flows, client Windows SKUs, external routing and sustained load remain unqualified. |
| UDP | Cannot guarantee with current Gateinto | Packet capture and ALE attribution are separate from transport support. In the same restricted topology, polled WFP attribution of first UDP datagrams arrived within the hold deadline, so attribution timing worked under hold. Gateinto implements TCP byte tunnels, not a datagram gateway protocol, so UDP was never forwarded. A new UDP-capable upstream and adapter would be needed; attribution races would remain. |

Neither transport qualifies as precise takeover. If “conditionally usable” means a working tested product rather than a restricted experiment result, TCP is also unqualified and must not be released on this evidence.

The required division is preserved: native WFP net events (`FwpmNetEventSubscribe*` callbacks or `FwpmNetEventEnum*` polling of the stored net-event history) or Security 5156 supply ownership; official WinDivert at `NETWORK` captures and reinjects packets. `SOCKET`/`FLOW` may be logged as diagnostic controls only. IP Helper tables, ETW TCP providers, PID polling and DLL injection must not become fallback ownership sources. Polling `FwpmNetEventEnum3` reads the same BFE-produced net events as a subscription and is not PID or process-table polling. No new kernel driver is proposed.

The separately authorized SOCKET observation comparison evaluates an event-driven ownership alternative for a future controlled routing experiment. It does not change ownership authority in the existing routing cases. Its successful coverage and timing findings below do not qualify packet admission or production takeover.

The review workspace is Linux x86_64 (kernel `6.18.57`), without a supplied Windows host or Windows driver execution facility. A follow-up implements an independent [PoC and Actions workflow](../experiments/wfp-divert/README.md) to test the first-packet-hold hypothesis. Cross-compilation and local model tests are not Windows runtime evidence; the only Windows runtime evidence is the Actions runs listed below. UDP forwarding remains unimplemented. The run record is [windows-per-app-review-log.md](windows-per-app-review-log.md).

## Measured Windows evidence

Earlier runs used `windows-2022` (OS build 20348); runs 42356168781, 42468677635 and 42497668177 also used Server 2025 (build 26100). Packet cases use one host, IPv4, controlled loopback endpoints, test EXEs A/B and the official signed WinDivert driver. Live ALE controls run before packet interception; SOCKET observation uses capture-only handles. The corrected SOCKET jobs passed. Other PoC Windows matrices remain red because subscription comparisons fail; short-hold Security UDP, native-drop recognition and first-packet ALE shadows also fail or stay inconclusive. `external-*` cases validate connection/attribution only, without payload, echo or proxy validation. The statements below are per case.

| Run (head) | Measured | Consequence |
| --- | --- | --- |
| 42280670136 (`a46493b`) | `FwpmNetEventSubscribe2` delivered 0 callbacks of any type in every case, while `collect_after=1` and `keywords_after=16` confirmed the engine options were applied. `FwpmNetEventEnum3` found 6–72 stored CLASSIFY_ALLOW events per case with the correct app path and full outbound tuple at layer 48 (ALE_AUTH_CONNECT); their `event_filetime` was about 0.03–0.09 ms before WinDivert captured the first packet. | Ordinary Win32 TCP/UDP allow events are produced on this build; Subscribe2 does not deliver them here. |
| 42282264784 (`ae22135`) | `FwpmNetEventSubscribe4` delivered callbacks equal to the enumeration total, but receipt was about 1004 ms after the event (apparently batched). classifyAllow read through `FWPM_NET_EVENT5` reported direction unknown and `is_loopback` true, contradicting the same events read through Enum3 (outbound, not loopback), so those events were unusable. Poll mode (5 ms `sleep_for`, 1 s overlap, unfiltered) passed 7/7 cases with notification−capture 20–46 ms. | Subscribe4 is too late and its decoded fields are not trusted; polling is viable. |
| [42340194216](evidence/wfp-divert-run-42340194216.md) (`edba304`) | Poll mode on a high-resolution waitable timer (5 ms wait), enumeration filtered to CLASSIFY_ALLOW, 300 ms overlap. 11/11 poll cases reached their pass status: hold tcp, udp, delayed, too-late and missing; redirect through the real Gateinto proxy and CONNECT fixture; external connect; SYN retransmit; tuple reuse (CHARACTERIZED_REUSE_REJECTION); repeats of hold tcp and redirect. | First-packet hold with polled native ownership works for this restricted topology. |
| [42348888370](evidence/wfp-divert-run-42348888370.md) (`e3336bd`) | All 11 split poll cases again reached expected statuses. Seven in-process cases reported PASS, but decision latency omitted blocking enumeration time, UDP launched TCP clients, and leakcheck had zero timeouts/leaks/RSTs. QUIC failed before readiness. Reconstructing complete small-case decision logs gives p50 about 25.7–33.1 ms for TCP hold/redirect, rather than the reported 10.4–11.9 ms. | In-process TCP redirection is promising, but a speedup, real UDP/QUIC coverage and live connection termination are not established. The later run below validates the repaired paths. |
| [42356168781](evidence/wfp-divert-run-42356168781.md) (`804e004`) | Server 2022 and 2025: 16/16 non-shadow in-process cases pass per OS, including real UDP/QUIC controls and client-observed reset after deliberate late ownership. All 11 split poll cases per OS reach expected statuses. In 50-client cases async reduces decided-direct p95 from 17.3 to 2.7 ms and 32.9 to 12.0 ms respectively. Snapshot creation accounts for about 82–90% of cache-on concurrency query elapsed time. Subscribe2/3 deliver no callbacks; Subscribe4 remains about 1 s late. ALE shadow tuples report System and fail original-app matching. | Prefer async lookup to isolate already-decided traffic from synchronous BFE work. A universal first-packet speedup, CPU saving and replacement ownership source are not established. |
| [42468677635, attempts 1 and 2](evidence/wfp-divert-run-42468677635.md) (`7398bf4`, checkout merge `e3bd9e4`) | Attempt 1 on Server 2022/2025: 27/27 non-shadow in-process cases pass per OS, including all eight snapshot cases; 11 split poll cases reach expected statuses. Destination/5 ms returns 91–96% fewer rows and improves first-decision p95 in these initial rounds, but the completed Server 2022 rerun develops large create/decision tails despite all profiles passing. Live TCP/UDP ALE controls match all six original apps and native references; first-packet shadows remain inconclusive. The Server 2025 rerun fails download before traffic. | Keep both destination scopes/windows experimental and retain the legacy default. Row reduction is repeatable; faster or more reliable admission is not established. Established ALE identity does not qualify first-packet admission or establish the cause of the earlier anomaly. |
| [42497668177](evidence/wfp-socket-run-42497668177.md) (`2dd799e`) | All eight SOCKET observation cases pass per OS, with 408 total clients matching PID, usable path, creation time, independent native WFP reference, first observed NETWORK packet and echo. Short sequential identity-ready−capture p50 is 0.0919–0.1204 ms; native poll receipt−capture p50 in those same cases is 20.8902–27.8970 ms. Only 21/408 image identities are ready before capture. | Promising source for the next buffered routing experiment. These are observation-time differences, not routing latency or a packet-admission guarantee. Existing WFP subscription findings remain unchanged. |

Run 42340194216 poll-mode measurements:

- notification−capture p50 10.4–25.6 ms per case (max 29.2 ms). decision−capture p50 13.8–27.4 ms; the delayed case was 112.7 ms because of its deliberate consumption delay. In every case the native observation arrived after packet capture, so the hold buffer, not event ordering, carried the decision.
- `wfp_poll_errors` 0, `wfp_poll_missed` 0, enumeration errors 0, no truncation, no queue drops. Timer `high_resolution` with maximum overshoot 0.5–1.6 ms.
- Mean poll duration 7.1–9.5 ms, maximum 8.8–43 ms. Collector lifetime was about 0.43–0.69 s per case (2.5 s for retransmit), which explains the 34–187 polls. Polling took about 60% of each poll+wait cycle, so the BFE RPC cost is not negligible.
- Redirect cases passed only with other-app noninterference (no B proxy packets) and the expected upstream CONNECT destinations and counts (3 bridge tunnels and 3 gateway CONNECTs; 1 for reuse). The reuse case is a characterized conservative rejection: the reused SYN was dropped and the non-selected client was disrupted, which is not normal application connectivity.
- Security 5156 in the same job gave notification−capture of roughly 330–1024 ms across the 9 timed cases. It passed TCP hold, delayed and too-late; redirect with 3 bridge tunnels and 3 gateway CONNECTs; redirect with missing ownership; SYN retransmit; external connect; and UDP hold at 2000 ms. Reuse ended as CHARACTERIZED_REUSE_REJECTION. The UDP case at a 1000 ms hold failed.

Still unqualified: Windows 10/11 client SKUs and builds beyond those tested; external routing beyond connect-only probes, including a topology that denies direct access; IPv6, fragmentation and other packet modifiers; sustained load, bounded receive backlog and production tuple reuse; polling cost at scale and long collector lifetimes; event-history eviction; and UDP forwarding. Subscribe4/CALLBACK4/EVENT5 pairing and layouts match the SDK. Latest matched callback/Enum5 records agree on undocumented direction/loopback fields, while Enum3 differs for the same event; this narrows the anomaly to a version-dependent representation, without establishing its semantics or an ABI corruption. A zero wrong-app count over finite runs is evidence for those runs only.

### Security 5156 baseline and native-drop control

The workspace is Linux, but the independent [PoC and Actions workflow](../experiments/wfp-divert/README.md) ran on GitHub-hosted **Windows Server 2022, build 20348**, with official signed WinDivert 2.2.2. [Run 42278267576](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42278267576), PoC head `e2990fa13365ca666644ae8797a2f11e2904fe25`, supplies the results below. The job is red because it deliberately tests unsupported/insufficient cases too; a successful TCP subcase does not mean the entire matrix passed. [Aggregate evidence](evidence/wfp-divert-run-42278267576-aggregate.json) omits paths, PIDs, endpoints and absolute timestamps. Full traces are retained in original Actions artifacts and locally; they are not reposted as Git source. See [execution record](windows-per-app-review-log.md).

| Case | Actual observation |
| --- | --- |
| Subscribe2 allow coverage | Subscription and engine-option calls succeeded, but recognized CLASSIFY_ALLOW count was zero for tested normal Win32 loopback TCP/UDP and external TCP. A blocked-flow control later received one callback whose type the collector did not recognize as documented drop/allow. The native source is **unqualified**: this does not prove Windows lacks allow events, and decoder/runtime-version questions remain. |
| 5156 TCP hold | Six complete client tuples, six accepted native controls and six successful echoes. All six notifications arrived after SYN capture and receive: **414.23–418.47 ms** after capture in this run. The earlier run observed 378.84–385.38 ms. These are sample ranges, not delivery bounds. |
| TCP transparent relay | Three A clients proxied; three B clients direct; all six echoed successfully. Three bridge tunnels and exactly three gateway CONNECT requests to the recovered destination. Gateinto is embedded in the fixture process; its additional target connections were confirmed nonselected/direct, and its TLS gateway endpoint was outside the capture filter. |
| TCP retransmission | Dropping the first native-confirmed SYN led to a later capture with the same tuple, generation and sequence. Six clients succeeded and only three selected-app gateway CONNECTs were opened. |
| TCP close / reuse | Ordinary half-close completed in the relay case. A reset-close followed by B binding the same full tuple produced a different SYN sequence; the PoC rejected it rather than inheriting A's proxy decision. B was disrupted. This is **CHARACTERIZED_REUSE_REJECTION**, not a noninterference pass. Maps are retained until process exit; general reclamation remains unqualified. |
| Delayed / skipped ownership | An additional 100 ms consumption delay worked within a 2 s hold. A 250 ms deadline and skip-all controls produced zero proxy tunnels; the decision stayed direct. Missing/late attribution can therefore leak selected traffic directly under this explicit policy. |
| UDP two destinations, 1 s hold | Six sockets, two destinations each: all twelve datagrams echoed directly, but only the first six tuple controls were accepted. Some second-destination notifications arrived **1010–1013 ms** after capture and missed the hold deadline. No collector queue loss was reported. |
| UDP two destinations, 2 s hold | Twelve tuple controls accepted, twelve direct echoes. Notification range **443.28–1006.14 ms**; still **no UDP forwarding through Gateinto**. |
| External TCP observation | Two ordinary external TCP connections completed; 5156 matched both, arriving about **338.95–339.62 ms** after capture. This connect-only probe sent no application payload and did not validate external transparent NAT or a restricted service. Subscribe2 supplied no allow attribution there. |

The local target, adapter, Gateinto and gateway fixture share one Windows host. The gateway path uses real TLS and CONNECT, but production mTLS identity, an external controlled target, Windows 10/11, IPv6 and load/loss stress remain unverified. Both apps' first packets are buffered, so even direct B connections incur attribution latency. “Other app direct” means connectivity and route were preserved in the fresh-tuple case, not that timing was unaffected. [Run 42394400675](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42394400675) repeated the successful TCP relay and retransmission, the disruptive reuse rejection, the 1 s UDP deadline failure and the 2 s success; its [aggregate record](evidence/wfp-divert-run-42394400675-aggregate.json) also records the unsuccessful native-drop recognition control.

The corrected loopback injection uses outbound direction for translated local-to-local packets and restores direction according to the original flow. Earlier inbound injection timed out; that was a PoC packet-path bug, not evidence that buffering cannot work. Full local raw records are available separately from the redacted Git summaries.

### Scoped lookup and live endpoint results

In [attempt 1 of run 42468677635](evidence/wfp-divert-run-42468677635.md), destination/5 ms first-decision p95 was 34.73/33.40 ms across the two Server 2022 rounds, versus legacy/500 ms at 41.68/57.64 ms; Server 2025 measured 40.15/46.58 versus 52.88/52.92 ms. Creation still dominated query work, and packet tails did not improve universally. The completed Server 2022 rerun reversed the first-decision result: destination/5 ms reached 134.67/441.61 ms versus legacy/500 ms at 38.23/48.32 ms; destination/500 ms also reached 102.88 ms in round 1. A create call reached 235.11 ms. All eight snapshot cases passed functional checks. Keep both destination variants optional experiments and retain legacy/500 ms as the default; no CPU, production or repeatable speedup claim is established. See [the full profile comparison](windows-per-app-low-latency.md).

Separate live ALE controls sampled established TCP/UDP sockets during a 500 ms post-echo hold before any WinDivert case. Each case had six correct original-app ALE matches and six native stored-event references, with no System app or shared-endpoint groups; both Server 2022 controls repeated this in attempt 2. Complete mean query cost in attempt 1 was 1.12/1.57 ms for TCP/UDP on Server 2022 and 1.67/2.34 ms on Server 2025; the Server 2022 rerun measured 1.95/1.96 ms. These are established-socket query costs, not admission latency. First-packet shadows still had zero qualifying observations while held. Both lifecycle and interception differ between controls, so the earlier anomaly cannot be attributed to WinDivert from this comparison.

### SOCKET observation results and limits

[Run 42497668177](evidence/wfp-socket-run-42497668177.md) tested two broad CONNECT controls and six scoped TCP/UDP cases per OS. All 408 controlled clients matched every required observation with no missing/mismatched identity, ambiguity or reported collector errors. The earlier [run 42496744881](https://github.com/lukeo3o1/gateinto-dev/actions/runs/42496744881) had no SOCKET events because the probe incorrectly applied the packet-header `ip` predicate to SOCKET metadata. The pinned DLL self-test reproduced that filter error; corrected filters delivered the controlled events.

Image readiness was not available before the first observed packet capture for 387/408 clients. No blocking, reinjection, redirection or admission deadline was tested. Clients explicitly bound IPv4 loopback tuples and retained process handles supported creation-time ground truth, so auto-bind, immediate process reclamation and arbitrary reuse remain unqualified. WinDivert exposes no driver queue-loss counter. The next step is controlled buffered routing with SOCKET identity while retaining exact matching and lifecycle checks; the current restricted TCP/UDP verdicts remain unchanged. See [the timing comparison](windows-per-app-low-latency.md).

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

The PoC logs distinct times: WFP occurrence FILETIME, WFP callback-entry QPC, evidence-consumption/decision-ready QPC, WinDivert capture `addr.Timestamp` (QPC clock), and `WinDivertRecv` return QPC [13]. For 5156 it also logs TimeCreated and callback-entry QPC. Compare receive QPC values for notification order, and decision-ready QPC against capture QPC for decision availability. The tested runs use one tightly bracketed UTC/QPC anchor; reported bracket widths were microseconds, but wall-clock steps during a run are not monitored. Cross-clock occurrence estimates are consequently approximate. Receipt/capture comparisons use QPC directly. TimeCreated is not an exact classifyFn execution measurement.
With polling, receipt is when a poll observed the event and includes polling latency. These restricted-run measurements are not delivery bounds. Raw clocks stay in local evidence; published summaries contain aggregate relative latency.

State-machine requirements (the PoC implements the fresh-flow subset and retains maps until process exit):

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

The following describes the tested local IPv4 layout and the candidate external expansion. Use a controlled destination R:r, one selected EXE A and distinct EXE B, with fresh sockets and no shared ports. Start the bridge listener before enabling diversion. Use a dedicated Gateinto credential session with route Gateway.

An explicit packet translation layout avoids pretending that changing only destination port is enough:

```text
Original app socket:       L:p -> R:r
Translated listener input: L:q -> L:t       (local alias q unique per live mapping)
Listener output:           L:t -> L:q
Restored socket input:     R:r -> L:p

adapter TCP stream -> authenticated CONNECT R:r to Gateinto loopback listener
Gateinto -> TLS to configured gateway -> CONNECT R:r -> controlled server
```

Allocate/reserve q to avoid local TCP socket/alias collisions and retain it through teardown/quarantine. Keep an injective map `(L,q,L,t,TCP) -> (L,p,R,r,TCP,generation,app-evidence)` **before** reinjecting the SYN. Forward packets use the rewrite; listener responses use its inverse. Recompute checksums and preserve interface metadata. Local-to-local packets are injected outbound; restored responses use outbound for an original loopback flow and inbound otherwise. Windows loopback operation passed the measured case; the non-loopback NAT branch remains unverified. The official streamdump example [14] is a reference, not proof of this implementation or native ownership.

The bridge recovers original destination from this map using its accepted peer **and local endpoint**, not from `getsockname`, Host, SNI, or an unsupported assumption that WFP redirect-context IOCTLs apply to WinDivert NAT. A dedicated bridge-originated CONNECT supplies the recovered IP literal and port to Gateinto. Ordinary HTTP CONNECT preserves TCP bytes; it does not discover the original hostname. If gateway policy needs a hostname rather than an IP literal, additional design is needed, and SNI cannot be assumed for arbitrary TCP.

The bridge must parse a successful local CONNECT response before relaying, preserve response early data, and handle rejection, half-close and backpressure. Never send the local proxy's HTTP 200 into the original app's stream. Gateinto then opens the upstream CONNECT through its existing pool/mTLS path. Verify upstream logs rather than assuming receipt at the local listener proves the upstream was used.

Exclude bridge-to-Gateinto local traffic, listener traffic after inverse translation, and Gateinto's gateway connections. For the one-destination PoC use a gateway endpoint different from R:r and a filter scoped to R:r plus exact listener response paths. For a broader implementation establish Gateinto/bridge-originated socket bypass entries before connect (using their own bound endpoints is bypass bookkeeping, not ownership of third-party traffic), or wait for native WFP evidence confirming their excluded App IDs. Do not use NETWORK `processId`: it does not exist there. A blanket “all loopback bypass” cannot precede listener inverse translation, and `!impostor` alone is not a complete self-exclusion policy. Log reinjection and check that packets are not repeatedly recaptured across priorities/other handles [13].

UDP needs another design: per-destination datagram association, message boundaries, reply sender restoration, fragmentation/MTU/ICMP handling, timeouts, and an upstream datagram protocol such as a separately implemented CONNECT-UDP capability. Raw UDP cannot be made functional by writing datagrams to the existing CONNECT byte stream. UDP/QUIC success must be separately demonstrated end to end.

## 4. Reproduction and remaining qualification

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

This query is retrospective, **not** a delivery-latency measurement. The full qualification harness should:

- Subscribe1/2 with matching SDK callback, save/set/restore engine options, deep-copy valid event fields before returning, and log callbacks without blocking them on network I/O. Keep net events and 5156 as separately selectable ownership sources; do not merge them into assumed truth.
- Use EvtSubscribe future-events plus Strict, record delivery/error actions, render raw XML, persist bookmarks and distinguish log-clear epochs. Do not treat historic replay as fresh authorization.
- Open WinDivert NETWORK scoped to the test target (and, for redirection, listener reply paths). Start with SNIFF observation, then repeat with divert-and-buffer. Log capture QPC, receive QPC, packet tuple, TCP flags/sequence/ack, length and decision. Optional SOCKET/FLOW comparison logs must be inaccessible to the ownership decision function.
- Implement the pending state machine and adapter described above, with configurable 10/50/250/1000 ms hold deadlines, 0/10/100/1000/5000 ms artificial ownership-consumption delays, deterministic skip-every-N, reverse delivery, duplicate delivery and stale-event replay. Record raw receive time separately from delayed consumption time.
- Build two distinct Win32 test EXEs, A and B (not merely two instances of the same EXE); log PID, creation time, explicit local bind, connect/send/close times, destinations and unique payload nonces as test ground truth only. Support TCP half-close/RST, UDP sendto multi-peer, repeat binds and short-lived instances.

The follow-up PoC implements a subset of these harness requirements, described in its README. The matrix below remains the full qualification specification: the initial workflow does not cover every row. No Windows runtime success is inferred from the presence of source or CI configuration.

### Test matrix and pass evidence

Status after the runs in [Measured Windows evidence](#measured-windows-evidence), including both completed Server 2022 attempts of the scoped lookup/live ALE comparison. PARTIAL means a bounded subset on the identified Server 2022/2025 runners; it does not satisfy the full row's pass condition.

| ID | Status |
| --- | --- |
| W1 | PARTIAL: collection and allow keyword set together, ordinary A/B TCP and UDP coverage counted by source/type/layer. Independent toggles and audit off/on not run. Native-drop callback recognition failed. |
| W2 | NOT RUN: elevated only. |
| O1 | PARTIAL: idle-host cases, including 50 concurrent clients and relative latency percentiles. 1,000 flows and CPU/I/O load stress not run. |
| M1 | PARTIAL: A and B to the same controlled destination with fresh local tuples; small repeated cases and 50-client concurrency. |
| M2 | PARTIAL: injected first-SYN loss and retransmission passed. |
| M3 | PARTIAL: ordinary half-close and client-observed reset after late ownership; remaining close/reauthorization variants unqualified. |
| M4 | PARTIAL: full-tuple reuse characterized as conservative rejection that disrupts the non-selected client. |
| M5 | PARTIAL: two UDP destinations per socket in the split engine; general mapping/reuse remains unqualified. |
| M6 | PARTIAL: missing, too-late and delayed ownership passed. Duplicate/reorder and stale replay against real reused sockets not run. |
| R1 | PARTIAL: nonce returned through bridge, Gateinto and a local CONNECT fixture. Direct path was not denied at a controlled network. |
| R2 | PARTIAL: fresh-tuple B connectivity and expected gateway CONNECT counts. Reconnect and recursion stress not run. |
| M7, R3, R4 | NOT RUN or not qualified. |
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

Required restricted local evidence per run: `manifest.json`, native-WFP JSONL, raw 5156 XML and callback JSONL, NETWORK packet trace/PCAP plus metadata, optional control-only SOCKET/FLOW JSONL, decision/map transitions, adapter accept/CONNECT logs (credentials redacted), Gateinto debug output, gateway CONNECT log, target/client nonce and hash logs. Include emitted/observed/missing/repeated counts separately for each source and transport. Local trace records retain run ID, record sequence, source, occurrence time, receipt QPC, consumption QPC, full tuple, app blob/path, nullable PID, layer/filter/reauth, generation, action and reason. New Git evidence and Actions uploads contain aggregate counts and relative latency statistics only. A zero wrong-app count over a finite run is evidence for that run, not a universal guarantee.

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
