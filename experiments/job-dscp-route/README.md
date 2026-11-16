# Job DSCP route

Experiment 2 of the Job DSCP track. Experiment 1 (`experiments/job-dscp`) showed that a Windows Job object with
network rate control DSCP tagging marks every outbound packet of its processes, from the first SYN, at WinDivert's
NETWORK layer. This experiment asks whether that tag is enough to route sessions end to end, and answers the open
questions around it in one CI run.

## Data path

```
curl.exe in a Job (DSCP tag), no proxy settings
  -> outbound TCP L:p -> R:443, tagged                  (R = target address, L = local NIC address)
  -> route.exe engine (WinDivert NETWORK, divert mode) reflects it inbound as R:p -> L:T, DSCP cleared
  -> bridge listener on 0.0.0.0:T accepts a connection from R:p, reads R:443 from the engine's translation map
  -> authenticated CONNECT R:443 to Gateinto's local proxy (gateinto::proxy::Proxy, Route::Gateway)
  -> TLS to the gateway fixture -> TCP to R:443
bridge replies L:T -> R:p are captured by the same handle and restored inbound as R:443 -> L:p.
```

Default engine filter: `outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == T)`. Only Job
processes carry a non-zero DSCP; the bridge, Gateinto and the gateway run outside any Job, so their traffic never
matches. Loopback is excluded because loopback replies to a tagged client inherit the tag. A pure SYN creates a flow
and its translation record is flushed before the SYN is injected; a pure SYN with the same sequence number is a
retransmit (`syn_retransmits`), a new sequence number on the same local port starts a new flow generation. Non-SYN
packets of unknown flows (`orphan_dropped`), IPv4 fragments and unparsable packets are dropped and counted. Closing
the handle (stop file, `--max-seconds`, crash) restores normal networking.

Engine options, all off by default: `--match-dscp N` matches exactly DSCP N
(`(ip.TOS >= 4N and ip.TOS <= 4N+3)`, ECN bits allowed) instead of any non-zero value; `--contain` (only with
`--match-dscp`) also captures tagged non-TCP IPv4 packets and drops them, counted as `contained_udp` and
`contained_other`.

`route.exe launch` prints a `launch_setup` record (Job, DSCP, read-back, assignment) before it resumes the child and a
final `launch` record after the child exits, so an attempt killed by the harness timeout is a failed attempt, not a
Job setup failure. The child is only created when the DSCP was set and read back with the expected value.

## Cases

Cases run in this order, each with its own Gateinto lab, bridge, firewall rule, pktmon capture, engine, private
directory, time budget and verdict. An exception, timeout or invalid result in one case turns only that case into
`HARNESS_ERROR` / `SKIPPED_DEADLINE`; later cases still run and the aggregate is always written.

`load` runs only when `https-external` is `ROUTED_VIA_GATEWAY` or `PARTIAL`; otherwise its verdict is
`NOT_RUN_CORE_NOT_ROUTED` (green, nothing started). The other cases always run because they use a different engine
mode. In every case a role's sequential phase stops after 3 consecutive failed attempts and the role is listed as
`true` in `stopped_early`; `load` then skips its burst (`burst_skipped`). Verdict rules count only attempts actually
made, so broken routing ends as `PARTIAL` or `ROUTING_BROKE_TAGGED` rather than running out of time.

| Case | Engine | Roles | Question |
|---|---|---|---|
| `https-external` | default | `tagged-no-engine` baseline (DSCP 10, before the engine), then 3 attempts each of `untagged`, `tagged-a` (DSCP 10), `tagged-b` (DSCP 20) | Is a tagged session routed through Gateinto while untagged traffic goes direct? |
| `load` | default | 10 sequential attempts per role, then a burst of 30 concurrent curls (10 per role) | Does routing hold for a larger sample and under concurrency? p50/p95 of `time_total` per role and phase show the routed overhead. |
| `shared-dscp` | `--match-dscp 43` | `untagged`; `session-a` and `session-b`, two long-lived named Jobs both tagged 43, each with 3 sequential then 3 concurrent curls | Can sessions share one code point and be told apart at accept time? The bridge looks up the owner of the original connection (`route.exe owner`: `GetExtendedTcpTable` + `IsProcessInJob`, as Gateinto's `os_user` authentication does) before CONNECT; the relay never depends on the result. |
| `qos-policy` | `--match-dscp 43` | `policy-outside` (a private `curl-qos.exe` copy under a QoS policy with DSCP 46, outside any Job); `policy-inside` (the same copy in a DSCP 43 Job) | Does an exact filter ignore foreign QoS marks, and which mark wins when both apply? |
| `udp-containment` | `--match-dscp 43 --contain` | `udp-tagged-no-engine` baseline, `udp-untagged`, `udp-tagged` (`route.exe udp-send`, 3 datagrams each), and one tagged curl | Is tagged UDP (QUIC) contained so that it cannot bypass the route, while TCP routing still works? |

## Verdicts

`ci.ps1` prints the aggregate between `=== JOB-DSCP-ROUTE AGGREGATE BEGIN ===` and
`=== JOB-DSCP-ROUTE AGGREGATE END ===` and appends one table row per case to the job summary. So that a killed job
still leaves evidence, the harness prints each case's public result as one JSON line between
`=== JOB-DSCP-ROUTE CASE <name> BEGIN ===` and `=== JOB-DSCP-ROUTE CASE <name> END ===` as soon as the case
finishes, and rewrites the result files after every case with the cases not yet run marked `PENDING`. A final
aggregate that still contains `PENDING` means the harness stopped early and turns the job red.

`https-external` and `load`:

- `ROUTED_VIA_GATEWAY`: every tagged attempt finished with curl exit 0 and a 2xx/3xx status; the gateway saw exactly
  one `CONNECT R:443` per tagged attempt and no other CONNECT; every `untagged` attempt succeeded; the engine created
  one flow per tagged attempt with no send errors or key collisions. `orphan_dropped` and `syn_retransmits` are
  published anomaly counters and do not change the verdict. With the NIC capture (`nic_confirmed` true): no pure SYN
  from a tagged local port and no segment from the bridge port (`bridge_segments_on_wire`) reached the wire, and every
  untagged attempt did. `nic.roles` (all packets) and `nic.syns` are both published. `nic_confirmed` false downgrades
  to `PARTIAL`; null means the capture was unavailable.
- `NOT_ROUTED`: tagged attempts succeeded but the gateway saw no CONNECT.
- `ROUTING_BROKE_TAGGED`: untagged attempts succeeded and every tagged attempt failed.
- `PARTIAL`: anything in between; histograms, gateway counts and engine counters explain it.
- `INCONCLUSIVE_FIREWALL_RULE_FAILED`: adding the inbound firewall rule failed and not every tagged attempt
  succeeded. If the rule failed but everything still routed, the verdict stands and `firewall` shows `failed`.

`shared-dscp`: `ROUTED_AND_ATTRIBUTED` when routing passes the rules above and every session connection is attributed
to its own session; `ROUTED_ATTRIBUTION_INCOMPLETE` when routing passes but attribution does not; otherwise the
verdicts above. Per session: attempts, owner found, attributed correctly, attributed to the wrong session,
unattributed, and attribution errors by fixed label or Win32 code (for example `owner_not_found`, `job_query_5`).

`qos-policy`: `JOB_TAG_WINS` (every inside attempt routed with one CONNECT each), `POLICY_WINS` (every inside attempt
went direct with DSCP 46 on the wire), `MIXED`, or `INCONCLUSIVE_POLICY_NOT_APPLIED` when the policy could not be
created, the NIC capture is unavailable, or the control shows no DSCP 46 (`policy.applied_reason`). `JOB_TAG_WINS` and
`POLICY_WINS` describe the mark seen at the WinDivert NETWORK layer, which is what routing depends on; the on-wire
DSCP of each role is published separately under `nic` when the capture is available.

`udp-containment`: `CONTAINED` (no tagged datagram on the wire, `contained_udp` equals the tagged datagrams sent,
untagged datagrams on the wire), `LEAKED` (tagged datagrams on the wire, none contained), `PARTIAL`, or
`INCONCLUSIVE_NO_BASELINE` with `baseline_reason` `nic_unavailable`, `baseline_not_on_wire` or `baseline_unmarked`
(engine counters are still published). `tcp_coexists` reports the tagged curl separately.

Every case can also be `INCONCLUSIVE_TARGET_UNREACHABLE`, `INCONCLUSIVE_JOB_SETUP_FAILED`, `HARNESS_ERROR` (exception,
or engine, bridge or gateway-log fault listed in `faults`) or `SKIPPED_DEADLINE` (its budget inside the 20-minute
harness deadline ran out). The `tagged-no-engine` baseline never changes a verdict. The workflow job is red only for
`HARNESS_ERROR`, `SKIPPED_DEADLINE`, build, unit or self-test failures, a failed cleanup (processes, firewall rule,
pktmon, QoS policy), or a missing or invalid aggregate; measured results stay green.

## Privacy

Published output is aggregate only: fixed labels, counts, booleans, DSCP values, HTTP status classes, curl exit
codes, Win32 error codes, medians and p50/p95 in milliseconds, and OS build or image metadata.
`analysis.validate_public` rejects addresses, paths and port or PID keys for every case. curl output, the gateway
and bridge logs, translation maps, owner lookups, Job names and the lab manifest (throwaway proxy credentials) stay
in a restricted private directory that is never uploaded.

## Limits

- GitHub-hosted Windows Server 2022 and 2025 images only, elevated; client SKUs are not covered.
- One destination (one IPv4 address of `github.com`) and port 443. IPv4 only: IPv6 is untested because the hosted
  runners have no IPv6 route, and containment of tagged IPv6 is not implemented. Containment also does not cover
  tagged loopback traffic.
- Small samples (3 to 30 attempts per role): evidence, not a guarantee.
- While an engine runs, every matching non-loopback IPv4 packet on the runner is diverted; only safe on a disposable
  runner.
- The bridge listener is reachable from R through a temporary inbound firewall rule
  (`gateinto-job-dscp-route-bridge`) that is removed in `finally`; the QoS policy
  (`gateinto-job-dscp-route-qos-*`, matching `curl-qos.exe` only) is removed in `finally` and leftovers are removed
  before a run.
- Owner attribution runs a short-lived `route.exe owner` process per connection, which adds latency before CONNECT.
- Experiment code, not production code: the flow table is never aged and is bounded at 4096 entries.
- The workflow job has a 60-minute timeout because the `wfp_lab` cargo build may be uncached.

Local checks:

```sh
python3 -m unittest discover -s experiments/job-dscp-route -p 'test_*.py' -v
g++ -std=c++17 -Wall -Wextra -Werror experiments/job-dscp-route/route.cpp -o /tmp/job-dscp-route-test && /tmp/job-dscp-route-test
```
