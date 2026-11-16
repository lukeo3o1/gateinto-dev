import collections
import ipaddress
import json
import math
import re
import statistics

SCHEMA = "job-dscp-route-v2"
CASE = "https-external"
TARGET_PORT = 443
ROLE_NAMES = ("untagged", "tagged-a", "tagged-b")
TAGGED = ("tagged-a", "tagged-b")
BASELINE = "tagged-no-engine"
EXPECTED_DSCP = {"tagged-a": 10, "tagged-b": 20, BASELINE: 10}
PRECONDITIONS = ("INCONCLUSIVE_TARGET_UNREACHABLE",)
HARNESS_FAULTS = ("HARNESS_ERROR", "SKIPPED_DEADLINE")
NET_RATE_REQUIRED_FLAGS = 0x1 | 0x4
SETUP_STEPS = ("job_created", "kill_on_close_set", "dscp_set", "readback_ok", "redirect_ok", "process_created",
               "assigned", "resumed")
JOB_STEPS = SETUP_STEPS + ("child_ran",)
JOB_ERRORS = ("job_error", "kill_on_close_error", "dscp_error", "readback_error", "redirect_error", "process_error",
              "assign_error", "resume_error")
ENGINE_COUNTERS = ("captured", "new_flows", "reflected", "replies_restored", "syn_retransmits", "send_errors",
                   "recv_errors", "checksum_errors", "orphan_dropped", "key_collisions", "unknown_reply_dropped",
                   "fragment_dropped", "malformed_dropped", "table_full", "map_write_errors", "open_error",
                   "param_errors", "shutdown_error", "last_error")
ENGINE_FLAGS = ("timed_out", "stop_timeout")
ENGINE_FAULT_COUNTERS = ("recv_errors", "checksum_errors", "map_write_errors", "open_error", "shutdown_error")
BRIDGE_ERROR_KINDS = ("lookup", "proxy_connect", "proxy_refused", "proxy_closed", "relay", "other")
NIC_STEPS = ("filter_remove", "filter_add", "start", "stop", "convert", "parse", "exception")
FIREWALL_STATUSES = ("added", "failed", "not_run")
QOS_STATUSES = ("created", "failed", "unavailable")
QOS_REASONS = ("cmdlet_missing", "create_failed", "not_elevated", "copy_failed")
ENV_NUMBERS = ("os_major", "os_minor", "os_build", "os_ubr", "product_type")
ENV_FLAGS = ("version_ok", "elevated", "in_job")
ENV_LABELS = ("image", "image_version")
LABEL = re.compile(r"[A-Za-z0-9._-]{1,64}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
FORBIDDEN_KEY_TOKENS = {"port", "ports", "pid", "addr", "address", "path", "src", "dst", "ip"}
ALLOWED_KEYS = {"port_collisions"}
CURL_TIMES = ("time_connect", "time_appconnect", "time_total")


def _address(value):
    try:
        return ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None


def _number(value):
    return value if type(value) is int else None


def _integer_text(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,9}", value):
        return int(value)
    return None


def _seconds(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _histogram(values):
    return {str(key): count for key, count in sorted(collections.Counter(values).items(), key=lambda i: str(i[0]))}


def parse_curl_output(text):
    if not isinstance(text, str):
        return None
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        port = _integer_text(value.get("local_port"))
        remote = value.get("remote_ip")
        result = dict(http_code=_integer_text(value.get("http_code")),
                      local_port=port if port is not None and 1 <= port <= 65535 else None,
                      remote_ip=remote if _address(remote) is not None else None,
                      num_connects=_integer_text(value.get("num_connects")))
        result.update({name: _seconds(value.get(name)) for name in CURL_TIMES})
        return result
    return None


def status_class(code):
    if not code:
        return "none"
    return f"{code // 100}xx" if type(code) is int and 100 <= code <= 599 else "other"


def _curl(attempt):
    value = attempt.get("curl")
    return value if isinstance(value, dict) else {}


def attempt_ok(attempt):
    code = _curl(attempt).get("http_code")
    return attempt.get("exit_code") == 0 and type(code) is int and 200 <= code <= 399


def gateway_counts(gateway, target):
    gateway = gateway if isinstance(gateway, dict) else {}
    if gateway.get("read") is not True:
        return dict(read=False, total=0, target=0, other=0)
    lines = [line for line in gateway.get("lines") or [] if isinstance(line, str)]
    expected = f"CONNECT {target}:{TARGET_PORT} HTTP/1.1"
    matching = sum(1 for line in lines if line == expected)
    return dict(read=True, total=len(lines), target=matching, other=len(lines) - matching)


def _owners(attempts, role_names):
    claims = collections.defaultdict(set)
    for attempt in attempts:
        port = _curl(attempt).get("local_port")
        if attempt.get("role") in role_names and port is not None:
            claims[port].add(attempt["role"])
    return claims


def nic_projection(nic, attempts, target, bridge_port=None, role_names=ROLE_NAMES, control="untagged"):
    nic = nic if isinstance(nic, dict) else {}
    status = nic.get("status")
    if status == "unavailable":
        result = dict(status="unavailable", step=nic.get("step") if nic.get("step") in NIC_STEPS else "other")
        if _number(nic.get("exit_code")) is not None:
            result["exit_code"] = nic["exit_code"]
        return result
    if status != "ok":
        return dict(status="not_run")
    claims = _owners(attempts, role_names)
    owners = {port: next(iter(names)) for port, names in claims.items() if len(names) == 1}
    target_address = _address(target)
    per_port, syn_port = collections.Counter(), collections.Counter()
    other = bridge_segments = 0
    for packet in nic.get("packets") or []:
        if target_address is None or _address(packet.get("dst")) != target_address:
            continue
        if packet.get("proto") == 6 and bridge_port is not None and packet.get("sport") == bridge_port:
            bridge_segments += 1
        elif packet.get("proto") == 6 and packet.get("dport") == TARGET_PORT and packet.get("sport") in owners:
            per_port[packet["sport"]] += 1
            if packet.get("syn") is True and packet.get("ack") is not True:
                syn_port[packet["sport"]] += 1
        else:
            other += 1

    def by_role(counter):
        return {name: sum(count for port, count in counter.items() if owners[port] == name) for name in role_names}

    seen = sum(1 for attempt in attempts if attempt.get("role") == control
               and per_port.get(_curl(attempt).get("local_port"), 0) > 0)
    return dict(status="ok", roles=by_role(per_port), syns=by_role(syn_port), untagged_attempts_on_wire=seen,
                other_packets=other, bridge_segments_on_wire=bridge_segments,
                port_collisions=sum(1 for names in claims.values() if len(names) > 1))


def job_setup_ok(launch, expected):
    if not isinstance(launch, dict):
        return False
    steps = SETUP_STEPS if launch.get("kind") != "launch_setup" else tuple(s for s in SETUP_STEPS if s != "resumed")
    if not all(launch.get(step) is True for step in steps):
        return False
    flags = _number(launch.get("readback_flags"))
    return (flags is not None and flags & NET_RATE_REQUIRED_FLAGS == NET_RATE_REQUIRED_FLAGS
            and launch.get("readback_dscp") == expected)


def _job_projection(attempts, expected, setup_ok=job_setup_ok):
    launches = [a.get("launch") for a in attempts if isinstance(a.get("launch"), dict)]
    errors = {}
    for name in JOB_ERRORS:
        codes = [launch[name] for launch in launches if _number(launch.get(name))]
        if codes:
            errors[name] = _histogram(codes)
    return dict(setup_ok=sum(1 for a in attempts if setup_ok(a.get("launch"), expected)),
                launch_records=len(launches),
                steps={step: sum(1 for launch in launches if launch.get(step) is True) for step in JOB_STEPS},
                errors=errors,
                readback_dscp=_histogram(launch["readback_dscp"] for launch in launches
                                         if _number(launch.get("readback_dscp")) is not None))


def _median_ms(values):
    values = [v for v in values if v is not None]
    return round(statistics.median(values) * 1000, 1) if values else None


def role_stats(attempts, target, expected=None, setup_ok=job_setup_ok):
    ran = [a for a in attempts if not a.get("skipped")]
    succeeded = [a for a in ran if attempt_ok(a)]
    stats = dict(attempts=len(attempts), skipped=len(attempts) - len(ran),
                 timed_out=sum(1 for a in ran if a.get("timed_out") is True), succeeded=len(succeeded),
                 curl_exit_codes=_histogram(a["exit_code"] if _number(a.get("exit_code")) is not None else "none"
                                            for a in ran),
                 http_status_classes=_histogram(status_class(_curl(a).get("http_code")) for a in ran),
                 output_parsed=sum(1 for a in ran if isinstance(a.get("curl"), dict)),
                 remote_matches=sum(1 for a in ran if target is not None and _curl(a).get("remote_ip") == target))
    for name in CURL_TIMES:
        stats[f"median_{name}_ms"] = _median_ms(_curl(a).get(name) for a in succeeded)
    if expected is not None:
        stats["expected_dscp"] = expected
        stats["job"] = _job_projection(ran, expected, setup_ok)
    return stats


def engine_projection(engine):
    engine = engine if isinstance(engine, dict) else {}
    summary = engine.get("summary")
    result = dict(ready=engine.get("ready") is True, exit_code=_number(engine.get("exit_code")),
                  summary=isinstance(summary, dict))
    if isinstance(summary, dict):
        for key in ENGINE_COUNTERS:
            if _number(summary.get(key)) is not None:
                result[key] = summary[key]
        for key in ENGINE_FLAGS:
            if type(summary.get(key)) is bool:
                result[key] = summary[key]
    return result


def engine_faults(projection):
    faults = []
    if not projection["ready"]:
        faults.append("engine_not_ready")
    if not projection["summary"]:
        faults.append("engine_no_summary")
    if projection["exit_code"] != 0:
        faults.append("engine_exit")
    faults += [f"engine_{key}" for key in ENGINE_FAULT_COUNTERS if projection.get(key, 0) != 0]
    faults += [f"engine_{key}" for key in ENGINE_FLAGS if projection.get(key) is True]
    return faults


def bridge_projection(bridge):
    bridge = bridge if isinstance(bridge, dict) else {}
    kinds = bridge.get("error_kinds") if isinstance(bridge.get("error_kinds"), dict) else {}
    return dict(started=bridge.get("started") is True, close_ok=bridge.get("close_ok") is True,
                accepted=_number(bridge.get("accepted")), tunnels=_number(bridge.get("tunnels")),
                errors=_number(bridge.get("errors")),
                error_kinds={k: v for k, v in sorted(kinds.items()) if k in BRIDGE_ERROR_KINDS and _number(v)})


def bridge_faults(projection):
    return ([] if projection["started"] else ["bridge_not_started"]) + (
        [] if projection["close_ok"] else ["bridge_close"])


def _nic_confirmed(nic, untagged, tagged_names):
    if nic["status"] != "ok":
        return None
    return (not any(nic["syns"][name] for name in tagged_names) and nic["bridge_segments_on_wire"] == 0
            and bool(untagged) and nic["untagged_attempts_on_wire"] == len(untagged))


def analyze(value, case=CASE, role_names=ROLE_NAMES, tagged_names=TAGGED, expected=EXPECTED_DSCP,
            setup_ok=job_setup_ok, with_baseline=True):
    target = value.get("target_ip")
    runs = [a for a in value.get("attempts") or [] if isinstance(a, dict)]
    baseline_runs = [a for a in value.get("baseline") or [] if isinstance(a, dict)]
    by_role = {name: [a for a in runs if a.get("role") == name] for name in role_names}
    roles = {name: role_stats(by_role[name], target, expected.get(name), setup_ok) for name in role_names}
    gateway = gateway_counts(value.get("gateway"), target)
    engine = engine_projection(value.get("engine"))
    bridge = bridge_projection(value.get("bridge"))
    bridge_port = value.get("bridge_port") if type(value.get("bridge_port")) is int else None
    nic = nic_projection(value.get("nic"), runs, target, bridge_port, role_names)
    faults = engine_faults(engine) + bridge_faults(bridge) + ([] if gateway["read"] else ["gateway_log"])
    tagged = [(name, a) for name in tagged_names for a in by_role[name] if not a.get("skipped")]
    untagged = [a for a in by_role["untagged"] if not a.get("skipped")]
    nic_confirmed = _nic_confirmed(nic, untagged, tagged_names)
    firewall = value.get("firewall") if value.get("firewall") in FIREWALL_STATUSES else "invalid"
    precondition = value.get("precondition")
    if precondition in PRECONDITIONS:
        verdict = precondition
    elif any(a.get("skipped") == "deadline" for a in runs + baseline_runs):
        verdict = "SKIPPED_DEADLINE"
    elif faults:
        verdict = "HARNESS_ERROR"
    elif not tagged or not all(setup_ok(a.get("launch"), expected[name]) for name, a in tagged):
        verdict = "INCONCLUSIVE_JOB_SETUP_FAILED"
    elif not any(attempt_ok(a) for a in untagged):
        verdict = "INCONCLUSIVE_TARGET_UNREACHABLE"
    elif firewall != "added" and not all(attempt_ok(a) for _, a in tagged):
        verdict = "INCONCLUSIVE_FIREWALL_RULE_FAILED"
    else:
        tagged_ok = [attempt_ok(a) for _, a in tagged]
        untagged_ok = all(attempt_ok(a) for a in untagged)
        routed = (all(tagged_ok) and untagged_ok and gateway["target"] == len(tagged) and gateway["other"] == 0
                  and engine.get("new_flows") == len(tagged)
                  and all(engine.get(key) == 0 for key in ("send_errors", "key_collisions")))
        if routed:
            verdict = "PARTIAL" if nic_confirmed is False else "ROUTED_VIA_GATEWAY"
        elif all(tagged_ok) and gateway["total"] == 0:
            verdict = "NOT_ROUTED"
        elif untagged_ok and not any(tagged_ok):
            verdict = "ROUTING_BROKE_TAGGED"
        else:
            verdict = "PARTIAL"
    result = dict(case=case, verdict=verdict, nic_confirmed=nic_confirmed, faults=faults, tagged_attempts=len(tagged),
                  roles=roles)
    if with_baseline:
        result["baseline"] = role_stats(baseline_runs, target, expected[BASELINE], setup_ok)
    result.update(gateway=gateway, bridge=bridge, engine=engine, firewall=firewall, nic=nic)
    return result


def skipped_case(case=CASE):
    return dict(case=case, verdict="SKIPPED_DEADLINE")


def harness_error_case(error_type, case=CASE):
    return dict(case=case, verdict="HARNESS_ERROR",
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
    status = policy.get("status") if policy.get("status") in QOS_STATUSES else "invalid"
    result = dict(status=status)
    if policy.get("reason") in QOS_REASONS:
        result["reason"] = policy["reason"]
    return result


def build_report(env, cases, qos_policy=None):
    report = dict(schema=SCHEMA, env=_env_projection(env), qos_policy=_qos_policy_projection(qos_policy),
                  verdicts={c["case"]: c["verdict"] for c in cases},
                  harness_errors=[c["case"] for c in cases if c["verdict"] in HARNESS_FAULTS],
                  cases={c["case"]: c for c in cases})
    validate_public(report)
    return report


def compact_dumps(value, expand=3, depth=0):
    if isinstance(value, dict) and value and depth < expand:
        pad = " " * (depth + 1)
        items = [f"{pad}{json.dumps(name)}: {compact_dumps(item, expand, depth + 1)}" for name, item in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + " " * depth + "}"
    return json.dumps(value, separators=(",", ":"))


def _cell(value):
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":")) if value else "-"
    return str(value)


def _case_detail(case):
    parts = []
    if "error_type" in case:
        parts.append(f"error {case['error_type']}")
    if case.get("faults"):
        parts.append(f"faults {', '.join(case['faults'])}")
    roles = case.get("roles") or {}
    if "tagged_attempts" in case:
        tagged = [stats for name, stats in roles.items() if name != "untagged"]
        parts.append(f"tagged ok {sum(s.get('succeeded') or 0 for s in tagged)}/{case['tagged_attempts']}")
        parts.append(f"CONNECTs to target {_cell((case.get('gateway') or {}).get('target'))}")
        parts.append(f"NIC confirmed {_cell(case.get('nic_confirmed'))}")
    if "attribution" in case:
        sessions = case["attribution"].values()
        parts.append(f"attributed {sum(s['attributed_correct'] for s in sessions)}/"
                     f"{sum(s['attempts'] for s in sessions)}")
    if "policy" in case:
        parts.append(f"policy applied {_cell(case['policy'].get('applied'))}")
        parts.append(f"inside {_cell(case.get('inside_outcomes'))}")
    if "udp" in case:
        parts.append(f"contained {_cell((case.get('engine') or {}).get('contained_udp'))}, tagged on wire "
                     f"{_cell(case['udp'].get('udp-tagged', {}).get('on_wire'))}, baseline "
                     f"{_cell(case.get('baseline_reason')) if case.get('baseline_reason') else 'ok'}")
    if "firewall" in case and case["firewall"] != "added":
        parts.append(f"firewall rule {case['firewall']}")
    return "; ".join(parts) or "-"


def markdown_summary(report):
    env = report.get("env", {})
    cases = report.get("cases") or {}
    lines = ["### Job DSCP route", "",
             f"OS build {_cell(env.get('os_build'))}.{_cell(env.get('os_ubr'))}, image {_cell(env.get('image'))} "
             f"{_cell(env.get('image_version'))}, elevated {_cell(env.get('elevated'))}, QoS policy "
             f"{(report.get('qos_policy') or {}).get('status', '-')}", "",
             "| Case | Verdict | Detail |", "|---|---|---|"]
    for name, case in cases.items():
        lines.append(f"| {name} | {case.get('verdict', '-')} | {_case_detail(case)} |")
    core = cases.get(CASE) or {}
    roles = dict(core.get("roles") or {})
    if "baseline" in core:
        roles[BASELINE] = core["baseline"]
    if roles:
        nic_roles = (core.get("nic") or {}).get("roles") or {}
        lines += ["", f"`{CASE}` roles:", "",
                  "| Role | Attempts | Succeeded | curl exit codes | HTTP classes | Median connect / TLS / total ms "
                  "| On-wire packets |", "|---|---|---|---|---|---|---|"]
        for name, stats in roles.items():
            lines.append(f"| {name} | {_cell(stats.get('attempts'))} | {_cell(stats.get('succeeded'))} | "
                         f"{_cell(stats.get('curl_exit_codes'))} | {_cell(stats.get('http_status_classes'))} | "
                         f"{_cell(stats.get('median_time_connect_ms'))} / "
                         f"{_cell(stats.get('median_time_appconnect_ms'))} / "
                         f"{_cell(stats.get('median_time_total_ms'))} | {_cell(nic_roles.get(name))} |")
    latency = (cases.get("load") or {}).get("latency") or {}
    if latency:
        lines += ["", "`load` time_total p50 / p95 ms:", "", "| Role | Sequential | Burst |", "|---|---|---|"]
        for name, phases in latency.items():
            cells = [f"{_cell(p.get('p50_time_total_ms'))} / {_cell(p.get('p95_time_total_ms'))} (n={p.get('n')})"
                     for p in (phases.get("sequential", {}), phases.get("burst", {}))]
            lines.append(f"| {name} | {cells[0]} | {cells[1]} |")
    return "\n".join(lines) + "\n"
