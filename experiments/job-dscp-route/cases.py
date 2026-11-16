import json
import pathlib
import secrets
import subprocess
import time

import analysis
import analysis_extra as extra
import bridge
import harness

LOAD_SEQUENTIAL = 10
LOAD_BURST = 10
SHARED_SEQUENTIAL = 3
SHARED_BURST = 3
QOS_ATTEMPTS = 3
UDP_SENDS = 1
UDP_DATAGRAMS = 3
UDP_INTERVAL_MS = 100
OWNER_TIMEOUT_SECONDS = 10
STOP_AFTER_FAILURES = 3
HOLDER_STOP_SECONDS = 10
GATEWAY_SNAPSHOT_SECONDS = 0.5
SESSION_PREFIX = "Local\\gateinto-job-dscp-route-"
EXACT_ENGINE = ["--match-dscp", str(extra.SHARED_DSCP)]
CONTAIN_ENGINE = EXACT_ENGINE + ["--contain"]


def child_command(ctx, role, out, err, payload):
    if role["kind"] != "tagged":
        return list(payload)
    command = [str(ctx.route), "launch", "--dscp", str(role["dscp"]), "--stdout", str(out), "--stderr", str(err)]
    if role.get("job"):
        command += ["--job-name", role["job"]]
    return command + ["--"] + list(payload)


def udp_payload(route, target):
    return [str(route), "udp-send", "--target", target, "--port", str(harness.TARGET_PORT), "--count",
            str(UDP_DATAGRAMS), "--interval-ms", str(UDP_INTERVAL_MS)]


def parse_udp(text):
    for line in reversed((text or "").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("kind") == "udp_send":
            fields = {key: value.get(key) for key in ("local_port", "sent", "error")}
            return fields if all(type(v) is int for v in fields.values()) else None
    return None


def _read(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def start_attempt(ctx, role, index, phase, payload, kind="curl"):
    attempt = dict(role=role["name"], index=index, phase=phase, exit_code=None, timed_out=False, skipped=None,
                   launch=None)
    attempt[kind] = None
    handle = dict(attempt=attempt, process=None, kind=kind, tagged=role["kind"] == "tagged")
    if ctx.deadline is not None and time.monotonic() >= ctx.deadline:
        ctx.deadline_hit = True
        attempt["skipped"] = "deadline"
        return handle
    stem = pathlib.Path(ctx.private) / f"{role['name']}-{phase}-{index}"
    out, err, log = stem.with_suffix(".out"), stem.with_suffix(".err"), stem.with_suffix(".launch")
    for path in (out, err, log):
        if path.exists():
            path.unlink()
    command = child_command(ctx, role, out, err, payload)
    if handle["tagged"]:
        with open(log, "wb") as stdout, open(stem.with_suffix(".launch.err"), "wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    else:
        with open(out, "wb") as stdout, open(err, "wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    handle.update(process=process, out=out, log=log, started=time.monotonic())
    return handle


def finish_attempt(handle):
    attempt, process = handle["attempt"], handle["process"]
    if process is None:
        return attempt
    remaining = harness.ATTEMPT_TIMEOUT_SECONDS - (time.monotonic() - handle["started"])
    try:
        code = process.wait(timeout=max(0.1, remaining))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        attempt["timed_out"] = True
        code = None
    if handle["tagged"]:
        launch = harness.launch_record(_read(handle["log"]))
        attempt["launch"] = launch
        if (launch and launch.get("kind") == "launch" and launch.get("child_ran") is True
                and type(launch.get("child_exit_code")) is int):
            attempt["exit_code"] = launch["child_exit_code"]
    else:
        attempt["exit_code"] = code
    text = _read(handle["out"])
    attempt[handle["kind"]] = analysis.parse_curl_output(text) if handle["kind"] == "curl" else parse_udp(text)
    return attempt


def _failed(attempt, kind):
    if attempt.get("skipped"):
        return False
    if kind == "curl":
        return not analysis.attempt_ok(attempt)
    return attempt.get("exit_code") != 0 or attempt.get(kind) is None


def sequential(ctx, role, count, phase, payload, kind="curl", first=0):
    attempts, failures = [], 0
    for index in range(count):
        attempt = finish_attempt(start_attempt(ctx, role, first + index, phase, payload, kind))
        attempts.append(attempt)
        failures = failures + 1 if _failed(attempt, kind) else 0
        if failures >= STOP_AFTER_FAILURES and index + 1 < count:
            return attempts, True
    return attempts, False


def burst(ctx, specs):
    handles = [start_attempt(ctx, role, index, "burst", payload) for role, index, payload in specs]
    return [finish_attempt(handle) for handle in handles]


def owner_lookup(route, jobs):
    def lookup(connection):
        command = [str(route), "owner", "--local", connection["local_ip"], "--local-port",
                   str(connection["local_port"]), "--remote", connection["remote_ip"], "--remote-port",
                   str(connection["remote_port"]), "--jobs", ",".join(jobs)]
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       timeout=OWNER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise bridge.AttributionError("owner_timeout")
        if completed.returncode != 0:
            code = completed.returncode
            raise bridge.AttributionError(f"owner_exit_{code}" if 0 < code < 1000 else "owner_exit_other")
        for line in reversed(completed.stdout.decode("utf-8", errors="replace").splitlines()):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get("kind") == "owner":
                return value
        raise bridge.AttributionError("owner_output")
    return lookup


def holder_command(ctx, name, stop):
    return [str(ctx.route), "session", "--dscp", str(extra.SHARED_DSCP), "--job-name", name, "--stop-file", str(stop),
            "--max-seconds", str(harness.ENGINE_MAX_SECONDS)]


def start_holders(ctx, names, command=None):
    command = command or (lambda name, stop: holder_command(ctx, name, stop))
    private = pathlib.Path(ctx.private)
    holders, outputs = {}, {}
    for session, name in names.items():
        stop, out = private / f"{session}.stop", private / f"{session}.holder.jsonl"
        for path in (stop, out):
            if path.exists():
                path.unlink()
        with open(out, "wb") as stdout, open(private / f"{session}.holder.err", "wb") as stderr:
            holders[session] = subprocess.Popen(command(name, stop), stdout=stdout, stderr=stderr)
        outputs[session] = out
    records = {}
    deadline = time.monotonic() + harness.READY_SECONDS
    while len(records) < len(holders) and time.monotonic() < deadline:
        for session, process in holders.items():
            if session in records:
                continue
            found = [r for r in harness.read_jsonl(outputs[session])[0] if r.get("kind") == "session"]
            if found:
                records[session] = found[-1]
            elif process.poll() is not None:
                records[session] = None
        time.sleep(0.05)
    return holders, records


def stop_holders(holders, private):
    for session in holders:
        (pathlib.Path(private) / f"{session}.stop").write_text("stop")
    for process in holders.values():
        try:
            process.wait(timeout=HOLDER_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_segment(ctx, engine_args, plan, before_engine=None, attribute=None):
    private = pathlib.Path(ctx.private)
    state = dict(firewall="not_run", gateway=dict(read=False, lines=[]), nic=dict(status="not_run"),
                 engine=dict(ready=False, exit_code=None, summary=None), bridge={}, attributions=[], attempts=[],
                 bridge_port=None)
    lab = relay = engine = gateway_path = None
    nic_running = firewall_attempted = False

    def gateway_target():
        time.sleep(GATEWAY_SNAPSHOT_SECONDS)
        return analysis.gateway_counts(harness.read_gateway(gateway_path), ctx.target_ip)["target"]

    try:
        lab, manifest, gateway_path = harness.start_lab(ctx)
        relay = bridge.Bridge("0.0.0.0", (manifest["proxy_host"], manifest["proxy_port"]),
                              manifest["proxy_authorization"], private / "translations.jsonl",
                              private / "bridge.jsonl", attribute=attribute)
        relay.start()
        state["bridge_port"] = relay.port
        firewall_attempted = True
        state["firewall"] = harness.add_firewall(private, relay.port, ctx.target_ip)
        failure = harness.guarded_nic(harness.nic_start, private, ctx.target_ip, private)
        nic_running = failure is None
        state["nic"] = failure or state["nic"]
        if before_engine is not None:
            state["attempts"] += before_engine(ctx)
            time.sleep(harness.BASELINE_SETTLE_SECONDS)
        engine = harness.start_engine(ctx, relay.port, engine_args)
        if engine["ready"]:
            result = plan(ctx, gateway_target)
            state["attempts"] += result.pop("attempts", [])
            state.update(result)
        time.sleep(harness.SETTLE_SECONDS)
        if nic_running:
            nic_running = False
            state["nic"] = harness.guarded_nic(harness.nic_finish, private, private)
        current, engine = engine, None
        state["engine"] = harness.stop_engine(current)
    finally:
        actions = []
        if engine is not None:
            actions.append(("engine", lambda: state.update(engine=harness.stop_engine(engine))))
        if nic_running:
            actions.append(("nic", lambda: harness.nic_cleanup(private)))
        if relay is not None:
            actions.append(("bridge", lambda: (relay.close(), state.update(bridge=relay.stats(),
                                                                          attributions=relay.attributions()))))
        if gateway_path is not None:
            actions.append(("gateway", lambda: state.update(gateway=harness.final_gateway(gateway_path))))
        if lab is not None:
            actions.append(("lab", lambda: harness.stop_process(lab)))
        actions.append(("manifest", lambda: (private / "lab" / "manifest.json").unlink(missing_ok=True)))
        if firewall_attempted:
            actions.append(("firewall", lambda: harness.remove_firewall(private, state["firewall"])))
        ctx.cleanup_failures += len(harness.run_all(actions, private))
    return state


def segment_value(ctx, state):
    return dict(precondition=None, target_ip=ctx.target_ip, bridge_port=state["bridge_port"],
                attempts=state["attempts"], gateway=state["gateway"], bridge=state["bridge"],
                engine=state["engine"], firewall=state["firewall"], nic=state["nic"],
                stopped_early=state.get("stopped_early", {}), burst_skipped=state.get("burst_skipped") is True)


UNREACHABLE = dict(precondition="INCONCLUSIVE_TARGET_UNREACHABLE", target_ip=None)


def run_load(ctx):
    if ctx.target_ip is None:
        return extra.analyze_load(dict(UNREACHABLE))
    payload = harness.curl_command(ctx.curl, ctx.target_ip)

    def plan(ctx, gateway_target):
        attempts, stopped = [], {}
        for role in harness.ROLES:
            made, stopped[role["name"]] = sequential(ctx, role, LOAD_SEQUENTIAL, "sequential", payload)
            attempts += made
        skip = any(stopped.values())
        if not skip:
            attempts += burst(ctx, [(role, LOAD_SEQUENTIAL + index, payload) for index in range(LOAD_BURST)
                                    for role in harness.ROLES])
        return dict(attempts=attempts, stopped_early=stopped, burst_skipped=skip)

    return extra.analyze_load(segment_value(ctx, run_segment(ctx, [], plan)))


def run_shared(ctx):
    if ctx.target_ip is None:
        return extra.analyze_shared(dict(UNREACHABLE))
    names = {session: SESSION_PREFIX + secrets.token_hex(8) for session in extra.SESSIONS}
    holders = {}
    try:
        holders, records = start_holders(ctx, names)
        if not all(isinstance(records.get(s), dict) and records[s].get("ready") is True for s in extra.SESSIONS):
            return extra.analyze_shared(dict(precondition=None, target_ip=ctx.target_ip, holders=records))
        roles = {s: dict(name=s, kind="tagged", dscp=extra.SHARED_DSCP, job=names[s]) for s in extra.SESSIONS}
        payload = harness.curl_command(ctx.curl, ctx.target_ip)

        def plan(ctx, gateway_target):
            attempts, stopped = [], {}
            for role in [harness.ROLES[0]] + [roles[s] for s in extra.SESSIONS]:
                made, stopped[role["name"]] = sequential(ctx, role, SHARED_SEQUENTIAL, "sequential", payload)
                attempts += made
            attempts += burst(ctx, [(roles[s], SHARED_SEQUENTIAL + index, payload) for index in range(SHARED_BURST)
                                    for s in extra.SESSIONS])
            return dict(attempts=attempts, stopped_early=stopped)

        state = run_segment(ctx, EXACT_ENGINE, plan,
                            attribute=owner_lookup(ctx.route, [names[s] for s in extra.SESSIONS]))
    finally:
        stop_holders(holders, ctx.private)
    value = segment_value(ctx, state)
    value.update(holders=records, attributions=state["attributions"])
    return extra.analyze_shared(value)


def run_qos(ctx, qos):
    policy = dict(status=qos.get("status"), reason=qos.get("reason"))
    if ctx.target_ip is None:
        return extra.analyze_qos(dict(UNREACHABLE, policy=policy))
    copy = qos.get("curl")
    if policy["status"] == "created" and (not copy or not pathlib.Path(copy).is_file()):
        policy = dict(status="failed", reason="copy_failed")
    if policy["status"] != "created":
        return extra.analyze_qos(dict(precondition=None, target_ip=ctx.target_ip, policy=policy))
    payload = harness.curl_command(copy, ctx.target_ip)
    outside = dict(name=extra.QOS_OUTSIDE, kind="untagged")
    inside = dict(name=extra.QOS_INSIDE, kind="tagged", dscp=extra.SHARED_DSCP)

    def plan(ctx, gateway_target):
        before = gateway_target()
        attempts, outside_stopped = sequential(ctx, outside, QOS_ATTEMPTS, "sequential", payload)
        middle = gateway_target()
        made, inside_stopped = sequential(ctx, inside, QOS_ATTEMPTS, "sequential", payload)
        after = gateway_target()
        return dict(attempts=attempts + made, gateway_by_role={extra.QOS_OUTSIDE: middle - before,
                                                               extra.QOS_INSIDE: after - middle},
                    stopped_early={extra.QOS_OUTSIDE: outside_stopped, extra.QOS_INSIDE: inside_stopped})

    state = run_segment(ctx, EXACT_ENGINE, plan)
    value = segment_value(ctx, state)
    value.update(policy=policy, gateway_by_role=state.get("gateway_by_role"))
    return extra.analyze_qos(value)


def run_udp(ctx):
    if ctx.target_ip is None:
        return extra.analyze_udp(dict(UNREACHABLE))
    payload = udp_payload(ctx.route, ctx.target_ip)
    roles = {name: dict(name=name, kind="untagged" if name == extra.UDP_UNTAGGED else "tagged",
                        dscp=extra.SHARED_DSCP) for name in extra.UDP_ROLES + (extra.TCP_TAGGED,)}

    def baseline(ctx):
        return sequential(ctx, roles[extra.UDP_BASELINE], UDP_SENDS, "sequential", payload, kind="udp")[0]

    def plan(ctx, gateway_target):
        attempts, stopped = [], {}
        for name, kind, count, role_payload in (
                (extra.UDP_UNTAGGED, "udp", UDP_SENDS, payload), (extra.UDP_TAGGED, "udp", UDP_SENDS, payload),
                (extra.TCP_TAGGED, "curl", 1, harness.curl_command(ctx.curl, ctx.target_ip))):
            made, stopped[name] = sequential(ctx, roles[name], count, "sequential", role_payload, kind=kind)
            attempts += made
        return dict(attempts=attempts, stopped_early=stopped)

    return extra.analyze_udp(segment_value(ctx, run_segment(ctx, CONTAIN_ENGINE, plan, before_engine=baseline)))
