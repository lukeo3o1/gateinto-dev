import collections
import math
import re

import analysis

LOAD = "load"
SHARED = "shared-dscp"
QOS = "qos-policy"
UDP = "udp-containment"
PHASES = ("sequential", "burst")
SHARED_DSCP = 43
POLICY_DSCP = 46
SESSIONS = ("session-a", "session-b")
SHARED_ROLES = ("untagged",) + SESSIONS
QOS_OUTSIDE = "policy-outside"
QOS_INSIDE = "policy-inside"
UDP_BASELINE = "udp-tagged-no-engine"
UDP_UNTAGGED = "udp-untagged"
UDP_TAGGED = "udp-tagged"
UDP_ROLES = (UDP_BASELINE, UDP_UNTAGGED, UDP_TAGGED)
TCP_TAGGED = "tcp-tagged"
SHARED_SETUP_STEPS = ("job_created", "readback_ok", "redirect_ok", "process_created", "assigned", "resumed")
HOLDER_ERRORS = ("job_error", "dscp_error", "readback_error")
POLICY_REASONS = ("cmdlet_missing", "create_failed", "not_elevated", "copy_failed")
ATTRIBUTION_LABEL = re.compile(r"[a-z0-9_]{1,40}")


def percentile_ms(values, fraction):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    return round(values[max(0, math.ceil(fraction * len(values)) - 1)] * 1000, 1)


def _ran(attempts):
    return [a for a in attempts if isinstance(a, dict) and not a.get("skipped")]


def _attempts(value):
    return [a for a in value.get("attempts") or [] if isinstance(a, dict)]


def _common(value):
    target = value.get("target_ip")
    gateway = analysis.gateway_counts(value.get("gateway"), target)
    engine = analysis.engine_projection(value.get("engine"))
    bridge = analysis.bridge_projection(value.get("bridge"))
    faults = analysis.engine_faults(engine) + analysis.bridge_faults(bridge) + (
        [] if gateway["read"] else ["gateway_log"])
    firewall = value.get("firewall") if value.get("firewall") in analysis.FIREWALL_STATUSES else "invalid"
    return target, gateway, engine, bridge, faults, firewall


def _stopping_verdict(value, faults):
    if value.get("precondition") in analysis.PRECONDITIONS:
        return value["precondition"]
    if any(a.get("skipped") == "deadline" for a in _attempts(value)):
        return "SKIPPED_DEADLINE"
    if faults:
        return "HARNESS_ERROR"
    return None


def _stopped(value):
    stopped = value.get("stopped_early")
    if not isinstance(stopped, dict):
        return {}
    return {k: v for k, v in sorted(stopped.items())
            if isinstance(k, str) and analysis.LABEL.fullmatch(k) and type(v) is bool}


def analyze_load(value):
    result = analysis.analyze(value, case=LOAD, with_baseline=False)
    attempts = _attempts(value)
    latency = {}
    for role in analysis.ROLE_NAMES:
        latency[role] = {}
        for phase in PHASES:
            totals = [a["curl"]["time_total"] for a in _ran(attempts)
                      if a.get("role") == role and a.get("phase") == phase and analysis.attempt_ok(a)]
            latency[role][phase] = dict(n=len(totals), p50_time_total_ms=percentile_ms(totals, 0.5),
                                        p95_time_total_ms=percentile_ms(totals, 0.95))
    result["latency"] = latency
    result["phases"] = {phase: sum(1 for a in attempts if a.get("phase") == phase) for phase in PHASES}
    result["stopped_early"] = _stopped(value)
    result["burst_skipped"] = value.get("burst_skipped") is True
    return result


def shared_launch_ok(launch, expected):
    if not isinstance(launch, dict) or launch.get("shared_job") is not True:
        return False
    steps = SHARED_SETUP_STEPS if launch.get("kind") != "launch_setup" else SHARED_SETUP_STEPS[:-1]
    flags = analysis._number(launch.get("readback_flags"))
    return (all(launch.get(step) is True for step in steps) and flags is not None
            and flags & analysis.NET_RATE_REQUIRED_FLAGS == analysis.NET_RATE_REQUIRED_FLAGS
            and launch.get("readback_dscp") == expected)


def _holder_projection(record):
    record = record if isinstance(record, dict) else {}
    result = dict(ready=record.get("ready") is True)
    for key in HOLDER_ERRORS:
        result[key] = analysis._number(record.get(key))
    return result


def _code_label(prefix, code):
    return f"{prefix}_{code}" if analysis._number(code) is not None else f"{prefix}_other"


def classify_attribution(record, own, count):
    if not isinstance(record, dict):
        return "unattributed", "no_record", False
    if record.get("error") is not None:
        label = record["error"]
        valid = (isinstance(label, str) and ATTRIBUTION_LABEL.fullmatch(label)
                 and not analysis.FORBIDDEN_KEY_TOKENS & set(label.split("_")))
        return "unattributed", label if valid else "other", False
    owner = record.get("owner")
    if not isinstance(owner, dict):
        return "unattributed", "owner_output", False
    if owner.get("table_error"):
        return "unattributed", _code_label("table", owner["table_error"]), False
    if owner.get("found") is not True:
        return "unattributed", "owner_ambiguous" if (owner.get("rows") or 0) > 1 else "owner_not_found", False
    if owner.get("process_error"):
        return "unattributed", _code_label("process", owner["process_error"]), True
    jobs = owner.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != count or not all(isinstance(j, dict) for j in jobs):
        return "unattributed", "owner_output", True
    members = [j.get("in_job") for j in jobs]
    if any(m is True for index, m in enumerate(members) if index != own):
        return "wrong", None, True
    if members[own] is True:
        return "correct", None, True
    for job in jobs:
        if job.get("open_error"):
            return "unattributed", _code_label("job_open", job["open_error"]), True
        if job.get("query_error"):
            return "unattributed", _code_label("job_query", job["query_error"]), True
    return "unattributed", "not_in_job", True


def _attribution(value):
    records = {}
    for record in value.get("attributions") or []:
        if isinstance(record, dict) and type(record.get("local_port")) is int:
            records[record["local_port"]] = record
    claimed = set()
    sessions = {}
    for own, session in enumerate(SESSIONS):
        outcomes, errors, found = collections.Counter(), collections.Counter(), 0
        ran = [a for a in _ran(_attempts(value)) if a.get("role") == session]
        for attempt in ran:
            port = analysis._curl(attempt).get("local_port")
            if port is None:
                outcome, label, owner_found = "unattributed", "curl_not_connected", False
            else:
                claimed.add(port)
                outcome, label, owner_found = classify_attribution(records.get(port), own, len(SESSIONS))
            outcomes[outcome] += 1
            found += owner_found
            if label:
                errors[label] += 1
        sessions[session] = dict(attempts=len(ran), owner_found=found, attributed_correct=outcomes["correct"],
                                 attributed_wrong=outcomes["wrong"], unattributed=outcomes["unattributed"],
                                 errors=dict(sorted(errors.items())))
    return sessions, sum(1 for port in records if port not in claimed)


def analyze_shared(value):
    result = analysis.analyze(value, case=SHARED, role_names=SHARED_ROLES, tagged_names=SESSIONS,
                              expected={s: SHARED_DSCP for s in SESSIONS}, setup_ok=shared_launch_ok,
                              with_baseline=False)
    holders = value.get("holders") if isinstance(value.get("holders"), dict) else {}
    result["holders"] = {s: _holder_projection(holders.get(s)) for s in SESSIONS}
    result["attribution"], result["unexpected_attributions"] = _attribution(value)
    result["stopped_early"] = _stopped(value)
    verdict = result["verdict"]
    if verdict not in analysis.PRECONDITIONS + ("SKIPPED_DEADLINE",) and not all(
            h["ready"] for h in result["holders"].values()):
        verdict = "INCONCLUSIVE_JOB_SETUP_FAILED"
    elif verdict == "ROUTED_VIA_GATEWAY":
        complete = all(s["attributed_correct"] == s["attempts"] for s in result["attribution"].values())
        verdict = "ROUTED_AND_ATTRIBUTED" if complete else "ROUTED_ATTRIBUTION_INCOMPLETE"
    result["verdict"] = verdict
    return result


def _wire_by_port(nic, target, protocol, ports):
    found = collections.defaultdict(list)
    target_address = analysis._address(target)
    for packet in nic.get("packets") or []:
        if (target_address is not None and analysis._address(packet.get("dst")) == target_address
                and packet.get("proto") == protocol and packet.get("dport") == analysis.TARGET_PORT
                and packet.get("sport") in ports):
            found[packet["sport"]].append(packet)
    return found


def _dscp(packet):
    return (int(packet.get("tos") or 0) & 0xFF) >> 2


def _policy_projection(policy, nic, outside):
    policy = policy if isinstance(policy, dict) else {}
    status = policy.get("status") if policy.get("status") in ("created", "failed", "unavailable") else "invalid"
    result = dict(status=status)
    if policy.get("reason") in POLICY_REASONS:
        result["reason"] = policy["reason"]
    if status != "created":
        result["applied"] = False
        return result
    if nic.get("status") != "ok":
        result.update(applied=None, applied_reason="nic_unavailable")
    elif not outside:
        result.update(applied=None, applied_reason="control_not_on_wire")
    elif all(_dscp(p) == POLICY_DSCP for p in outside):
        result["applied"] = True
    elif any(_dscp(p) == POLICY_DSCP for p in outside):
        result.update(applied=False, applied_reason="control_partially_marked")
    else:
        result.update(applied=False, applied_reason="control_unmarked")
    return result


def _inside_outcome(attempt, packets):
    if not analysis.attempt_ok(attempt):
        return "failed"
    if not packets:
        return "routed"
    if all(_dscp(p) == POLICY_DSCP for p in packets):
        return "policy"
    if any(_dscp(p) == SHARED_DSCP for p in packets):
        return "tag_on_wire"
    return "other"


def analyze_qos(value):
    target, gateway, engine, bridge, faults, firewall = _common(value)
    attempts = _attempts(value)
    by_role = {role: [a for a in attempts if a.get("role") == role] for role in (QOS_OUTSIDE, QOS_INSIDE)}
    nic_value = value.get("nic") if isinstance(value.get("nic"), dict) else {}
    ports = {role: [analysis._curl(a).get("local_port") for a in _ran(by_role[role])] for role in by_role}
    wire = _wire_by_port(nic_value, target, 6, {p for role_ports in ports.values() for p in role_ports if p})
    nic = {}
    if nic_value.get("status") == "ok":
        for role in by_role:
            packets = [p for port in ports[role] if port for p in wire.get(port, [])]
            nic[role] = dict(packets=len(packets),
                             syns=sum(1 for p in packets if p.get("syn") is True and p.get("ack") is not True),
                             attempts_on_wire=sum(1 for port in ports[role] if port and wire.get(port)),
                             dscp=analysis._histogram(_dscp(p) for p in packets))
    else:
        nic = analysis.nic_projection(nic_value, [], target)
    outside_packets = [p for port in ports[QOS_OUTSIDE] if port for p in wire.get(port, [])]
    policy = _policy_projection(value.get("policy"), nic_value, outside_packets)
    inside = _ran(by_role[QOS_INSIDE])
    outcomes = collections.Counter(_inside_outcome(a, wire.get(analysis._curl(a).get("local_port"), []))
                                   for a in inside)
    connects_input = value.get("gateway_by_role") if isinstance(value.get("gateway_by_role"), dict) else {}
    connects = {role: analysis._number(connects_input.get(role)) for role in by_role}
    outside_ok = [analysis.attempt_ok(a) for a in _ran(by_role[QOS_OUTSIDE])]
    if value.get("precondition") in analysis.PRECONDITIONS:
        verdict = value["precondition"]
    elif policy["status"] != "created":
        verdict = "INCONCLUSIVE_POLICY_NOT_APPLIED"
    else:
        verdict = _stopping_verdict(value, faults)
    if verdict is None:
        if not inside or not all(analysis.job_setup_ok(a.get("launch"), SHARED_DSCP) for a in inside):
            verdict = "INCONCLUSIVE_JOB_SETUP_FAILED"
        elif policy.get("applied") is not True:
            verdict = "INCONCLUSIVE_POLICY_NOT_APPLIED"
        elif not any(outside_ok):
            verdict = "INCONCLUSIVE_TARGET_UNREACHABLE"
        elif firewall != "added" and outcomes["failed"]:
            verdict = "INCONCLUSIVE_FIREWALL_RULE_FAILED"
        elif (outcomes["routed"] == len(inside) and connects[QOS_INSIDE] == len(inside)
              and connects[QOS_OUTSIDE] == 0 and gateway["other"] == 0 and all(outside_ok)):
            verdict = "JOB_TAG_WINS"
        elif outcomes["policy"] == len(inside) and connects[QOS_INSIDE] == 0 and connects[QOS_OUTSIDE] == 0:
            verdict = "POLICY_WINS"
        else:
            verdict = "MIXED"
    return dict(case=QOS, verdict=verdict, faults=faults, policy=policy,
                roles={QOS_OUTSIDE: analysis.role_stats(by_role[QOS_OUTSIDE], target),
                       QOS_INSIDE: analysis.role_stats(by_role[QOS_INSIDE], target, SHARED_DSCP)},
                inside_outcomes=dict(sorted(outcomes.items())), connects=connects, stopped_early=_stopped(value),
                gateway=gateway, bridge=bridge, engine=engine, firewall=firewall, nic=nic)


def _udp_record(attempt):
    record = attempt.get("udp")
    return record if isinstance(record, dict) else {}


def analyze_udp(value):
    target, gateway, engine, bridge, faults, firewall = _common(value)
    summary = (value.get("engine") or {}).get("summary") if isinstance(value.get("engine"), dict) else None
    for key in ("contained_udp", "contained_other"):
        if isinstance(summary, dict) and analysis._number(summary.get(key)) is not None:
            engine[key] = summary[key]
    attempts = _attempts(value)
    by_role = {role: _ran([a for a in attempts if a.get("role") == role]) for role in UDP_ROLES + (TCP_TAGGED,)}
    nic_value = value.get("nic") if isinstance(value.get("nic"), dict) else {}
    ports = {role: {_udp_record(a).get("local_port") for a in by_role[role]} - {None, 0} for role in UDP_ROLES}
    wire = _wire_by_port(nic_value, target, 17, set().union(*ports.values()))
    udp = {}
    for role in UDP_ROLES:
        packets = [p for port in ports[role] for p in wire.get(port, [])]
        udp[role] = dict(sends=len(by_role[role]),
                         sent=sum(_udp_record(a).get("sent") or 0 for a in by_role[role]
                                  if analysis._number(_udp_record(a).get("sent")) is not None),
                         on_wire=len(packets), dscp=analysis._histogram(_dscp(p) for p in packets))
    tcp = by_role[TCP_TAGGED]
    tcp_coexists = (all(analysis.attempt_ok(a) for a in tcp) and gateway["target"] == len(tcp)
                    and gateway["other"] == 0) if tcp else None
    baseline_reason = None
    if nic_value.get("status") != "ok":
        baseline_reason = "nic_unavailable"
    elif udp[UDP_BASELINE]["on_wire"] == 0:
        baseline_reason = "baseline_not_on_wire"
    elif str(SHARED_DSCP) not in udp[UDP_BASELINE]["dscp"]:
        baseline_reason = "baseline_unmarked"
    tagged = by_role[UDP_BASELINE] + by_role[UDP_TAGGED] + tcp
    verdict = _stopping_verdict(value, faults)
    if verdict is None:
        contained = engine.get("contained_udp")
        sent_tagged, sent_untagged = udp[UDP_TAGGED]["sent"], udp[UDP_UNTAGGED]["sent"]
        if not tagged or not all(analysis.job_setup_ok(a.get("launch"), SHARED_DSCP) for a in tagged):
            verdict = "INCONCLUSIVE_JOB_SETUP_FAILED"
        elif baseline_reason:
            verdict = "INCONCLUSIVE_NO_BASELINE"
        elif (sent_tagged > 0 and udp[UDP_TAGGED]["on_wire"] == 0 and contained == sent_tagged
              and sent_untagged > 0 and udp[UDP_UNTAGGED]["on_wire"] >= sent_untagged):
            verdict = "CONTAINED"
        elif sent_tagged > 0 and udp[UDP_TAGGED]["on_wire"] >= sent_tagged and contained == 0:
            verdict = "LEAKED"
        else:
            verdict = "PARTIAL"
    return dict(case=UDP, verdict=verdict, faults=faults, baseline_reason=baseline_reason, udp=udp,
                stopped_early=_stopped(value),
                tcp=analysis.role_stats(tcp, target, SHARED_DSCP), tcp_coexists=tcp_coexists, gateway=gateway,
                bridge=bridge, engine=engine, firewall=firewall,
                nic=dict(status=nic_value.get("status") if nic_value.get("status") in ("ok", "unavailable")
                         else "not_run"))
