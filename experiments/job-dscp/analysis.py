import collections
import ipaddress
import json
import math
import re

SCHEMA = "job-dscp-v1"
PROTOCOLS = {"tcp": 6, "udp": 17}
PRECONDITIONS = ("INCONCLUSIVE_TARGET_UNREACHABLE", "INCONCLUSIVE_NO_IPV6")
NET_RATE_REQUIRED_FLAGS = 0x1 | 0x4
JOB_STEPS = ("job_created", "kill_on_close_set", "dscp_set", "readback_ok", "process_created", "assigned", "resumed")
JOB_NUMBERS = ("job_error", "kill_on_close_error", "dscp_error", "readback_error", "process_error", "assign_error",
               "resume_error", "readback_flags", "readback_dscp")
SNIFFER_ERROR_COUNTS = ("open_error", "recv_errors", "parse_errors", "shutdown_error")
SNIFFER_NUMBERS = ("received", "records", "last_error", "param_errors") + SNIFFER_ERROR_COUNTS
SNIFFER_FLAGS = ("timed_out", "stop_timeout", "truncated")
OUTCOMES = ("connected", "timeout", "refused", "connect_error", "select_error", "ioctl_error", "socket_error",
            "bind_error", "getsockname_error", "sent", "send_error")
NIC_STEPS = ("filter_remove", "filter_add", "start", "stop", "convert", "parse", "no_capture", "exception")
QOS_STATUSES = ("created", "unavailable", "failed")
QOS_REASONS = ("cmdlet_missing", "create_failed", "not_elevated")
ENV_NUMBERS = ("os_major", "os_minor", "os_build", "os_ubr", "product_type")
ENV_FLAGS = ("version_ok", "elevated", "connection_policy_api", "in_job")
ENV_LABELS = ("image", "image_version", "runner_os")
LABEL = re.compile(r"[A-Za-z0-9._-]{1,64}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
FORBIDDEN_KEY_TOKENS = {"port", "ports", "pid", "addr", "address", "path", "src", "dst", "ip"}
ALLOWED_KEYS = {"port_collisions"}
HARNESS_FAULTS = ("HARNESS_ERROR", "SKIPPED_DEADLINE")
EVALUATED = ("MARK_AT_FIRST_PACKET", "NO_MARK", "PARTIAL_MARK", "INCONCLUSIVE_NO_NEGATIVE_CONTROL")


def dscp(tos):
    return (int(tos) & 0xFF) >> 2


def _address(value):
    try:
        return ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None


def _port(value):
    return value if type(value) is int and 1 <= value <= 65535 else None


def _number(value):
    return value if type(value) is int and not isinstance(value, bool) else None


def _histogram(values):
    return {str(key): count for key, count in sorted(collections.Counter(values).items())}


def _seq(packet):
    return packet.get("seq") if type(packet.get("seq")) is int else 0


def _attribute(packets, roles, proto, target_addr, target_port):
    number, target = PROTOCOLS[proto], _address(target_addr)
    owners, flows = {}, {}
    for role in roles:
        flows[role["name"]] = {}
        for attempt in role.get("attempts") or ():
            port = _port(attempt.get("local_port"))
            if port is not None:
                owners.setdefault(port, role["name"])
    unattributed = []
    for packet in sorted(packets, key=_seq):
        owner = owners.get(packet.get("sport"))
        if (owner is not None and packet.get("proto") == number and packet.get("dport") == target_port
                and target is not None and _address(packet.get("dst")) == target):
            flows[owner].setdefault(packet["sport"], []).append(packet)
        else:
            unattributed.append(packet)
    return flows, unattributed


def port_collisions(roles):
    claims = collections.defaultdict(set)
    for role in roles:
        for attempt in role.get("attempts") or ():
            port = _port(attempt.get("local_port"))
            if port is not None:
                claims[port].add(role["name"])
    return sum(1 for names in claims.values() if len(names) > 1)


def attribute(packets, roles, proto, target_addr, target_port):
    flows, unattributed = _attribute(packets, roles, proto, target_addr, target_port)
    return flows, len(unattributed)


def _identity(packet):
    return (packet.get("v"), packet.get("proto"), _address(packet.get("src")), _address(packet.get("dst")),
            packet.get("sport"), packet.get("dport"), packet.get("tos"), packet.get("syn"), packet.get("ack"),
            packet.get("fin"), packet.get("rst"), packet.get("len"))


def missing_from_marked(observe, marked):
    wanted = collections.Counter(_identity(p) for p in observe if dscp(p.get("tos", 0)) != 0)
    present = collections.Counter(_identity(p) for p in marked)
    return sum(max(0, count - present[key]) for key, count in wanted.items())


def job_setup_ok(launch, expected):
    if not isinstance(launch, dict):
        return False
    if not all(launch.get(step) is True for step in JOB_STEPS):
        return False
    flags = _number(launch.get("readback_flags"))
    return (flags is not None and flags & NET_RATE_REQUIRED_FLAGS == NET_RATE_REQUIRED_FLAGS
            and launch.get("readback_dscp") == expected)


def _job_projection(launch, expected):
    result = dict(ok=job_setup_ok(launch, expected), launch_record=isinstance(launch, dict))
    if isinstance(launch, dict):
        for key in JOB_STEPS:
            if type(launch.get(key)) is bool:
                result[key] = launch[key]
        for key in JOB_NUMBERS:
            if _number(launch.get(key)) is not None:
                result[key] = launch[key]
    return result


def _first_is_initial(proto, packet):
    return proto == "udp" or (packet.get("syn") is True and packet.get("ack") is not True)


def _role_stats(role, proto, flows, marked_flows):
    expected = role.get("expected_dscp", 0)
    attempts = role.get("attempts") or []
    first, syn, every = [], [], []
    fully = unmarked = mixed = unexpected = missing = 0
    for port, packets in flows.items():
        values = [dscp(p.get("tos", 0)) for p in packets]
        every.extend(values)
        if _first_is_initial(proto, packets[0]):
            first.append(values[0])
        if proto == "tcp":
            syn.extend(v for p, v in zip(packets, values) if p.get("syn") is True and p.get("ack") is not True)
        nonzero = sum(1 for v in values if v)
        if nonzero == len(values):
            fully += 1
        elif nonzero == 0:
            unmarked += 1
        else:
            mixed += 1
        unexpected += sum(1 for v in values if v != expected)
        missing += missing_from_marked(packets, marked_flows.get(port, []))
    if proto == "udp":
        syn = list(first)
    ports = [_port(a.get("local_port")) for a in attempts]
    complete = bool(attempts) and all(
        port is not None and port in flows and _first_is_initial(proto, flows[port][0]) for port in ports)
    stats = dict(expected_dscp=expected, attempts=len(attempts),
                 attempts_bound=sum(1 for p in ports if p is not None),
                 outcomes=_histogram(a.get("outcome") if a.get("outcome") in OUTCOMES else "other" for a in attempts),
                 exit_ok=role.get("exit_ok") is True, flows_observed=len(flows), first_packets_observed=len(first),
                 first_packet_every_attempt=complete, first_packet_dscp=_histogram(first),
                 first_packets_expected_dscp=sum(1 for v in first if v == expected), syn_packets=len(syn),
                 syn_dscp=_histogram(syn), packets=len(every), all_dscp=_histogram(every), flows_fully_marked=fully,
                 flows_unmarked=unmarked, flows_mixed=mixed, packets_unexpected_dscp=unexpected,
                 observe_missing_from_marked=missing,
                 marked_packets=sum(len(p) for p in marked_flows.values()))
    if role.get("kind") == "tagged":
        stats["job"] = _job_projection(role.get("launch"), expected)
    if role.get("skipped") in ("policy_unavailable",):
        stats["skipped"] = role["skipped"]
    return stats, every, first


def _sniffer_projection(sniffer):
    sniffer = sniffer if isinstance(sniffer, dict) else {}
    summary = sniffer.get("summary")
    result = dict(ready=sniffer.get("ready") is True, exit_code=_number(sniffer.get("exit_code")),
                  summary=isinstance(summary, dict), packets=len(sniffer.get("packets") or []))
    if isinstance(summary, dict):
        for key in SNIFFER_NUMBERS:
            if _number(summary.get(key)) is not None:
                result[key] = summary[key]
        for key in SNIFFER_FLAGS:
            if type(summary.get(key)) is bool:
                result[key] = summary[key]
    return result


def _sniffer_failed(sniffer):
    sniffer = sniffer if isinstance(sniffer, dict) else {}
    summary = sniffer.get("summary")
    if sniffer.get("ready") is not True or sniffer.get("exit_code") != 0 or not isinstance(summary, dict):
        return True
    return any(summary.get(key) not in (0, None) for key in SNIFFER_ERROR_COUNTS) or any(
        summary.get(key) is True for key in SNIFFER_FLAGS)


def _nic_projection(nic, roles, proto, target_addr, target_port):
    nic = nic if isinstance(nic, dict) else {}
    status = nic.get("status")
    if status == "ok":
        flows, unattributed = _attribute(nic.get("packets") or [], roles, proto, target_addr, target_port)
        return dict(status="ok", unattributed=len(unattributed), roles={
            name: dict(packets=sum(len(p) for p in role_flows.values()),
                       dscp=_histogram(dscp(packet.get("tos", 0)) for p in role_flows.values() for packet in p))
            for name, role_flows in flows.items()})
    if status == "unavailable":
        result = dict(status="unavailable", step=nic.get("step") if nic.get("step") in NIC_STEPS else "other")
        if _number(nic.get("exit_code")) is not None:
            result["exit_code"] = nic["exit_code"]
        return result
    return dict(status="not_applicable")


def _qos_verdict(precondition, sniffer_error, status, values):
    if precondition in PRECONDITIONS:
        return precondition
    if status != "created":
        return "QOS_POLICY_UNAVAILABLE"
    if sniffer_error:
        return "INCONCLUSIVE_SNIFFER_ERROR"
    if not values:
        return "QOS_NO_PACKETS"
    if all(v == 30 for v in values):
        return "QOS_MARK_VISIBLE"
    if not any(values):
        return "QOS_NO_MARK"
    return "QOS_PARTIAL_MARK"


def _case_name(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-z0-9-]{1,40}", value) else "invalid"


def analyze_case(value):
    proto = value["proto"]
    target = value["target"]
    roles = value.get("roles") or []
    sniffers = value.get("sniffers") or {}
    observe = sniffers.get("observe") or {}
    marked = sniffers.get("marked") or {}
    observe_flows, unattributed = _attribute(observe.get("packets") or [], roles, proto, target["addr"],
                                             target["port"])
    marked_flows, foreign = _attribute(marked.get("packets") or [], roles, proto, target["addr"], target["port"])
    stats, values, firsts = {}, {}, {}
    for role in roles:
        name = role["name"]
        stats[name], values[name], firsts[name] = _role_stats(role, proto, observe_flows[name], marked_flows[name])
    tagged = [r for r in roles if r.get("kind") == "tagged"]
    untagged = [r for r in roles if r.get("kind") == "untagged"]
    qos = [r for r in roles if r.get("kind") == "qos"]
    sniffer_error = _sniffer_failed(observe) or _sniffer_failed(marked)
    tagged_values = [v for r in tagged for v in values[r["name"]]]
    connected = any(a.get("outcome") == "connected" for r in tagged + untagged for a in r.get("attempts") or [])
    first_ok = all(stats[r["name"]]["first_packet_every_attempt"] and
                   stats[r["name"]]["first_packets_expected_dscp"] == stats[r["name"]]["attempts"] for r in tagged)
    control_complete = bool(untagged) and all(stats[r["name"]]["first_packet_every_attempt"] for r in untagged)
    precondition = value.get("precondition")
    if precondition in PRECONDITIONS:
        verdict = precondition
    elif sniffer_error:
        verdict = "INCONCLUSIVE_SNIFFER_ERROR"
    elif not tagged or not all(job_setup_ok(r.get("launch"), r.get("expected_dscp")) for r in tagged):
        verdict = "INCONCLUSIVE_JOB_SETUP_FAILED"
    elif value.get("require_connect") and not connected:
        verdict = "INCONCLUSIVE_TARGET_UNREACHABLE"
    elif not tagged_values:
        verdict = "INCONCLUSIVE_NO_PACKETS"
    elif not any(tagged_values):
        verdict = "NO_MARK"
    elif first_ok and all(stats[r["name"]]["packets_unexpected_dscp"] == 0 for r in tagged) and not any(
            v for r in untagged for v in values[r["name"]]):
        verdict = "MARK_AT_FIRST_PACKET" if control_complete else "INCONCLUSIVE_NO_NEGATIVE_CONTROL"
    else:
        verdict = "PARTIAL_MARK"
    if verdict not in EVALUATED:
        first_result = "NOT_EVALUATED"
    elif not any(v for r in tagged for v in firsts[r["name"]]):
        first_result = "FIRST_PACKET_UNMARKED"
    elif first_ok and not any(v for r in untagged for v in firsts[r["name"]]):
        first_result = "FIRST_PACKET_MARKED" if control_complete else "FIRST_PACKET_NO_NEGATIVE_CONTROL"
    else:
        first_result = "FIRST_PACKET_PARTIAL"
    missing = sum(s["observe_missing_from_marked"] for s in stats.values())
    result = dict(case=_case_name(value.get("case")), proto=proto if proto in PROTOCOLS else "invalid",
                  verdict=verdict, first_packet_result=first_result, marked_filter_complete=missing == 0,
                  marked_filter_selective=all(stats[r["name"]]["marked_packets"] == 0 for r in untagged),
                  negative_control_observed=any(stats[r["name"]]["packets"] for r in untagged),
                  port_collisions=port_collisions(roles), client_error_lines=_number(value.get("client_errors")),
                  unattributed_observe_packets=len(unattributed), foreign_marked_packets=len(foreign),
                  foreign_marked_dscp=_histogram(dscp(p.get("tos", 0)) for p in foreign),
                  sniffers=dict(observe=_sniffer_projection(observe), marked=_sniffer_projection(marked)),
                  roles={r["name"]: stats[r["name"]] for r in tagged + untagged},
                  nic=_nic_projection(value.get("nic"), roles, proto, target["addr"], target["port"]))
    if qos:
        status = value.get("qos_policy")
        control = dict(stats[qos[0]["name"]])
        control["verdict"] = _qos_verdict(precondition, sniffer_error, status, values[qos[0]["name"]])
        result["qos_control"] = control
    else:
        result["qos_control"] = dict(verdict="QOS_NOT_RUN")
    return result


def skipped_case(name):
    return dict(case=_case_name(name), verdict="SKIPPED_DEADLINE")


def harness_error_case(name, error_type):
    return dict(case=_case_name(name), verdict="HARNESS_ERROR",
                error_type=error_type if isinstance(error_type, str) and IDENTIFIER.fullmatch(error_type)
                else "Exception")


def _check_string(value):
    if len(value) > 200 or "\\" in value or "/" in value:
        raise ValueError("string is not an aggregate label")
    for token in re.findall(r"[0-9A-Fa-f:.%]+", value):
        if (":" in token or token.count(".") == 3) and _address(token.split("%")[0]) is not None:
            raise ValueError("string contains an address")


def validate_public(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non-string key")
            _check_string(key)
            if key not in ALLOWED_KEYS and FORBIDDEN_KEY_TOKENS & set(key.lower().split("_")):
                raise ValueError("identifier key")
            validate_public(item)
    elif isinstance(value, list):
        for item in value:
            validate_public(item)
    elif isinstance(value, str):
        _check_string(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
    elif value is not None and not isinstance(value, (bool, int)):
        raise ValueError("unsupported value")


def _env_projection(env):
    env = env if isinstance(env, dict) else {}
    result = {}
    for key in ENV_NUMBERS:
        if _number(env.get(key)) is not None:
            result[key] = env[key]
    for key in ENV_FLAGS:
        if type(env.get(key)) is bool:
            result[key] = env[key]
    for key in ENV_LABELS:
        if isinstance(env.get(key), str) and LABEL.fullmatch(env[key]):
            result[key] = env[key]
    return result


def _qos_policy_projection(policy):
    policy = policy if isinstance(policy, dict) else {}
    if policy.get("status") not in QOS_STATUSES:
        return dict(status="invalid")
    result = dict(status=policy["status"])
    if policy.get("reason") in QOS_REASONS:
        result["reason"] = policy["reason"]
    return result


def build_aggregate(env, qos_policy, cases):
    aggregate = dict(schema=SCHEMA, capture_only=True, env=_env_projection(env),
                     qos_policy=_qos_policy_projection(qos_policy),
                     verdicts={c["case"]: c["verdict"] for c in cases},
                     qos_verdicts={c["case"]: c["qos_control"]["verdict"] for c in cases if "qos_control" in c},
                     first_packet_results={c["case"]: c["first_packet_result"] for c in cases
                                           if "first_packet_result" in c},
                     harness_errors=[c["case"] for c in cases if c["verdict"] in HARNESS_FAULTS],
                     cases={c["case"]: c for c in cases})
    validate_public(aggregate)
    return aggregate


def compact_dumps(value, expand=3, expand_keys=("roles",), depth=0, key=None):
    if isinstance(value, dict) and value and (depth < expand or key in expand_keys):
        pad = " " * (depth + 1)
        limit = depth + 1 if key in expand_keys else expand
        items = [f"{pad}{json.dumps(name)}: {compact_dumps(item, limit, expand_keys, depth + 1, name)}"
                 for name, item in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + " " * depth + "}"
    return json.dumps(value, separators=(",", ":"))


def _cell(value):
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def markdown_summary(aggregate):
    env = aggregate.get("env", {})
    lines = ["### Job DSCP probe",
             "",
             f"OS build {_cell(env.get('os_build'))}.{_cell(env.get('os_ubr'))}, image {_cell(env.get('image'))} "
             f"{_cell(env.get('image_version'))}, elevated {_cell(env.get('elevated'))}, probe already in a job "
             f"{_cell(env.get('in_job'))}, FwpmConnectionPolicyAdd0 {_cell(env.get('connection_policy_api'))}, "
             f"QoS policy {aggregate.get('qos_policy', {}).get('status', '-')}",
             "",
             "| Case | Job verdict | First-packet result | First-packet DSCP per role | Marked filter complete "
             "| Marked filter selective | Foreign marked | Port collisions | QoS control | NIC |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for name, case in aggregate.get("cases", {}).items():
        roles = case.get("roles", {})
        first = "; ".join(f"{role} {json.dumps(stats.get('first_packet_dscp', {}), separators=(',', ':'))}"
                          for role, stats in roles.items()) or "-"
        lines.append(f"| {name} | {case['verdict']} | {case.get('first_packet_result', '-')} | {first} | "
                     f"{_cell(case.get('marked_filter_complete'))} | {_cell(case.get('marked_filter_selective'))} | "
                     f"{_cell(case.get('foreign_marked_packets'))} | {_cell(case.get('port_collisions'))} | "
                     f"{case.get('qos_control', {}).get('verdict', '-')} | {case.get('nic', {}).get('status', '-')} |")
    return "\n".join(lines) + "\n"
