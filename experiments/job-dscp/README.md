# Job DSCP visibility probe

Capture-only experiment. It checks whether the DSCP tag that a Windows Job object stamps on its processes'
traffic can select one Gateinto session's packets with a static WinDivert filter.

## Hypothesis

`SetInformationJobObject(JobObjectNetRateControlInformation)` with
`JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG` marks outbound traffic of every
process in the job, descendants included. The hypothesis is that the kernel applies this mark before WinDivert's
NETWORK layer sees the outbound packet, on the very first packet (TCP SYN or first UDP datagram), and only for
processes in that job. If so, a filter on `ip.TOS` / `ipv6.TrafficClass` selects a session's traffic with no
ownership lookup and no first-packet hold.

## How it runs

`build.ps1` downloads the pinned, signed WinDivert 2.2.2 release, verifies the driver signature, writes
`driver-manifest.json` and builds `probe.exe` plus a byte-identical `probe-qos.exe`. `ci.ps1` (elevated) runs the
Python unit tests and `probe.exe self-test`, creates a temporary QoS policy for the control, runs `harness.py`, and
always removes the policy, stops pktmon and kills leftover probes. Every WinDivert handle is opened with
`WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`; nothing is blocked, injected or modified.

Each case starts two sniffers before any client runs:

- `observe`: outbound packets to the case's target address and port.
- `marked`: `outbound and ((ip and ip.TOS >= 4) or (ipv6 and ipv6.TrafficClass >= 4))`, the production filter
  prototype. It measures completeness (tagged packets seen by `observe` are also here) and selectivity (no
  `untagged` packet, and a count of foreign marked packets).

Packets are attributed to roles by protocol, client local port and destination. Everything else is counted as
`unattributed`.

Roles, run one after another in every case:

| Role | Process |
|---|---|
| `tagged-a` | client in a job with DSCP 10 |
| `tagged-b` | client in a second job with DSCP 20 |
| `tagged-child` | job with DSCP 10; the client respawns itself, so packets come from a grandchild |
| `untagged` | client outside our jobs (negative control) |
| `qos-policy` | `probe-qos.exe` outside our jobs, under a `New-NetQosPolicy` DSCP 30 policy (diagnostic control) |

Cases:

| Case | Target |
|---|---|
| `tcp-external-syn` | TCP to 192.0.2.1:443 (TEST-NET-1, never answers: SYNs only) |
| `udp-external` | UDP to 192.0.2.1:443 |
| `tcp-external-complete` | TCP connect and graceful close to one IPv4 address of `api.github.com:443` |
| `tcp-loopback`, `udp-loopback` | harness listener on 127.0.0.1 (informational) |
| `tcp6-loopback` | harness listener on `::1` (informational) |

External cases also try an in-box `pktmon` capture at the NIC to tell "not visible at WinDivert" apart from
"applied below the IP layer". Any pktmon failure is reported as `nic.status: unavailable` with the failing step.

## Reading the results

`ci.ps1` prints the aggregate between `=== JOB-DSCP AGGREGATE BEGIN ===` and `=== JOB-DSCP AGGREGATE END ===`
and appends a verdict table to the job summary. Job verdicts per case:

- `MARK_AT_FIRST_PACKET`: every job was set up and read back, every attempt of every tagged role has an
  observed first packet, every observed tagged packet carries exactly its role's DSCP, and every `untagged`
  packet has DSCP 0. `negative_control_observed` says whether any `untagged` packet was seen at all.
- `NO_MARK`: jobs were set up, and no tagged packet carries a non-zero DSCP.
- `PARTIAL_MARK`: anything in between; the per-role histograms (`first_packet_dscp`, `syn_dscp`, `all_dscp`,
  flow counts) explain it.
- `INCONCLUSIVE_JOB_SETUP_FAILED` (see `roles.*.job` for step booleans, Win32 error codes and read-back),
  `INCONCLUSIVE_NO_PACKETS`, `INCONCLUSIVE_TARGET_UNREACHABLE`, `INCONCLUSIVE_NO_IPV6`,
  `INCONCLUSIVE_SNIFFER_ERROR`, `HARNESS_ERROR`.

The QoS control has its own verdict (`QOS_MARK_VISIBLE`, `QOS_NO_MARK`, `QOS_PARTIAL_MARK`, `QOS_NO_PACKETS`,
`QOS_POLICY_UNAVAILABLE`) and never changes the job verdict. If the QoS mark is visible but the job mark is not,
the job tag is applied elsewhere or not at all; if neither is visible, WinDivert's layer may sit above every
DSCP marker and the NIC histogram decides.

The job goes red only when the harness malfunctions: build, unit or self-test failure, crash or timeout of a
probe process, sniffer failure, harness exception, or a missing or invalid aggregate. A measured `NO_MARK` or
`PARTIAL_MARK` is green.

## Privacy

Published output is aggregate only: fixed labels, counts, DSCP values, booleans, Win32 error codes and OS build
or image metadata. `analysis.validate_public` rejects addresses, paths and port or PID keys before anything is
written. Per-packet and per-attempt records stay in a restricted private directory that is never uploaded.

## Limits

- GitHub-hosted Windows Server 2022 and 2025 images only; client SKUs are not covered.
- Non-domain runner; local QoS policy behaviour may differ on domain-joined machines.
- Capture only: no routing, blocking or injection is tested.
- Three attempts per role and case: a finite sample, not a guarantee.
- Network rate control can be set on only one job in a nested hierarchy; a runner that already sets it on an
  enclosing job shows up as `INCONCLUSIVE_JOB_SETUP_FAILED` with the error code.

Local checks:

```sh
python3 -m unittest discover -s experiments/job-dscp -p 'test_*.py' -v
g++ -std=c++17 -Wall -Wextra -Werror experiments/job-dscp/probe.cpp -o /tmp/job-dscp-probe-test && /tmp/job-dscp-probe-test
```
