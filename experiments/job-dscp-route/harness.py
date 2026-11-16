import argparse
import ipaddress
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import time
import traceback

import analysis
import bridge
import pcapng

TARGET_HOST = "github.com"
TARGET_PORT = 443
ATTEMPTS = 3
FIREWALL_RULE = "gateinto-job-dscp-route-bridge"
HARNESS_DEADLINE_SECONDS = 20 * 60
PENDING = "PENDING"
INTERMEDIATE_WRITE = "intermediate-write"
NOT_RUN_CORE_NOT_ROUTED = "NOT_RUN_CORE_NOT_ROUTED"
CORE_GATES = {"load": ("ROUTED_VIA_GATEWAY", "PARTIAL")}
CASE_BUDGETS = {"https-external": 420, "load": 300, "shared-dscp": 180, "qos-policy": 120, "udp-containment": 120}
LAB_SECONDS = 25 * 60
ENGINE_MAX_SECONDS = 25 * 60
ATTEMPT_TIMEOUT_SECONDS = 45
READY_SECONDS = 20
STOP_SECONDS = 25
PKTMON_TIMEOUT_SECONDS = 30
SETTLE_SECONDS = 1.0
BASELINE_SETTLE_SECONDS = 3.0
GATEWAY_READS = 3
GATEWAY_READ_INTERVAL_SECONDS = 0.3
CURL_FORMAT = ('{"http_code":"%{http_code}","local_port":"%{local_port}","remote_ip":"%{remote_ip}",'
               '"num_connects":"%{num_connects}","time_connect":"%{time_connect}",'
               '"time_appconnect":"%{time_appconnect}","time_total":"%{time_total}"}')

ROLES = [dict(name="untagged", kind="untagged", dscp=0), dict(name="tagged-a", kind="tagged", dscp=10),
         dict(name="tagged-b", kind="tagged", dscp=20)]
BASELINE_ROLE = dict(name=analysis.BASELINE, kind="tagged", dscp=10)


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("port")
    return value


def _ipv4(value):
    return str(ipaddress.IPv4Address(value))


def engine_filter(port):
    return f"outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == {_port(port)})"


def curl_command(curl, target_ip):
    return [str(curl), "--noproxy", "*", "--resolve", f"{TARGET_HOST}:{TARGET_PORT}:{_ipv4(target_ip)}",
            "--ssl-no-revoke", "-sS", "-o", "NUL", "--connect-timeout", "10", "--max-time", "25", "-w", CURL_FORMAT,
            f"https://{TARGET_HOST}/"]


def attempt_command(role, route, curl, target_ip, stdout, stderr):
    command = curl_command(curl, target_ip)
    if role["kind"] != "tagged":
        return command
    return [str(route), "launch", "--dscp", str(role["dscp"]), "--stdout", str(stdout), "--stderr", str(stderr),
            "--"] + command


def engine_command(route, port, map_path, stop, extra=()):
    return [str(route), "engine", "--listener-port", str(_port(port)), "--map", str(map_path), "--stop-file",
            str(stop), "--max-seconds", str(ENGINE_MAX_SECONDS)] + list(extra)


def lab_command(lab, manifest, out):
    return [str(lab), "--manifest", str(manifest), "--out", str(out), "--seconds", str(LAB_SECONDS)]


def firewall_add_command(port, remote):
    return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={FIREWALL_RULE}", "dir=in", "action=allow",
            "protocol=TCP", f"localport={_port(port)}", f"remoteip={_ipv4(remote)}"]


def firewall_delete_command():
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_RULE}"]


def pktmon_start_steps(addr, etl):
    return [("filter_remove", ["pktmon", "filter", "remove"]),
            ("filter_add", ["pktmon", "filter", "add", "job-dscp-route", "-i", str(addr)]),
            ("start", ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "96", "--file-name",
                       str(etl)])]


def pktmon_convert_commands(etl, pcap):
    return [["pktmon", "etl2pcap", str(etl), "--out", str(pcap)],
            ["pktmon", "pcapng", str(etl), "-o", str(pcap)]]


def resolve_target(host):
    try:
        infos = socket.getaddrinfo(host, TARGET_PORT, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    return infos[0][4][0] if infos else None


def local_address_for(target):
    if target is None:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((target, TARGET_PORT))
            return probe.getsockname()[0]
    except OSError:
        return None


def read_jsonl(path):
    records, invalid = [], 0
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            invalid += 1
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            invalid += 1
    return records, invalid


def launch_record(stdout):
    found = {}
    for line in (stdout or "").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("kind") in ("launch", "launch_setup"):
            found[value["kind"]] = value
    return found.get("launch") or found.get("launch_setup")


def engine_result(path, exit_code):
    records, _ = read_jsonl(path)
    summaries = [r for r in records if r.get("kind") == "summary"]
    return dict(ready=any(r.get("kind") == "ready" for r in records), exit_code=exit_code,
                summary=summaries[-1] if summaries else None)


def read_gateway(path):
    if not pathlib.Path(path).is_file():
        return dict(read=False, lines=[])
    records, _ = read_jsonl(path)
    return dict(read=True, lines=[r["request_line"] for r in records
                                  if r.get("kind") == "gateway_connect" and isinstance(r.get("request_line"), str)])


def log_exception(private):
    try:
        pathlib.Path(private).mkdir(parents=True, exist_ok=True)
        with open(pathlib.Path(private) / "harness-errors.log", "a", encoding="utf-8") as stream:
            stream.write(traceback.format_exc())
    except Exception:
        pass


def run_all(actions, private=None):
    failed = []
    for label, action in actions:
        try:
            action()
        except Exception:
            if private is not None:
                log_exception(private)
            failed.append(label)
    return failed


def run_quiet(command, log, timeout=PKTMON_TIMEOUT_SECONDS):
    try:
        with open(log, "ab") as stream:
            return subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout).returncode
    except FileNotFoundError:
        return -1
    except Exception:
        return None


def stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


class Context:
    def __init__(self, route, curl, lab, private, target_ip, local_ip, deadline=None):
        self.route = route
        self.curl = curl
        self.lab = lab
        self.private = private
        self.target_ip = target_ip
        self.local_ip = local_ip
        self.deadline = deadline
        self.deadline_hit = False
        self.cleanup_failures = 0


def run_attempt(ctx, role, index):
    attempt = dict(role=role["name"], index=index, exit_code=None, timed_out=False, skipped=None, launch=None,
                   curl=None)
    if ctx.deadline is not None and time.monotonic() >= ctx.deadline:
        ctx.deadline_hit = True
        attempt["skipped"] = "deadline"
        return attempt
    stem = pathlib.Path(ctx.private) / f"{role['name']}-{index}"
    out, err = stem.with_suffix(".out"), stem.with_suffix(".err")
    for path in (out, err):
        if path.exists():
            path.unlink()
    command = attempt_command(role, ctx.route, ctx.curl, ctx.target_ip, out, err)
    try:
        if role["kind"] == "tagged":
            with open(stem.with_suffix(".launch.log"), "ab") as log:
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=log,
                                           timeout=ATTEMPT_TIMEOUT_SECONDS)
            launch = launch_record(completed.stdout.decode("utf-8", errors="replace"))
            attempt["launch"] = launch
            if launch and launch.get("child_ran") is True and type(launch.get("child_exit_code")) is int:
                attempt["exit_code"] = launch["child_exit_code"]
        else:
            with open(out, "wb") as stdout, open(err, "wb") as stderr:
                completed = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=ATTEMPT_TIMEOUT_SECONDS)
            attempt["exit_code"] = completed.returncode
    except subprocess.TimeoutExpired as error:
        attempt["timed_out"] = True
        if role["kind"] == "tagged":
            output = error.stdout if isinstance(error.stdout, bytes) else b""
            attempt["launch"] = launch_record(output.decode("utf-8", errors="replace"))
    try:
        attempt["curl"] = analysis.parse_curl_output(out.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        attempt["curl"] = None
    return attempt


def run_role(ctx, role):
    return [run_attempt(ctx, role, index) for index in range(ATTEMPTS)]


def wait_ready(process, path):
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        records, _ = read_jsonl(path)
        if any(r.get("kind") == "ready" for r in records):
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def start_lab(ctx):
    directory = pathlib.Path(ctx.private) / "lab"
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    manifest_path, out, log = directory / "manifest.json", directory / "out", directory / "lab.log"
    with open(log, "ab") as stream:
        process = subprocess.Popen(lab_command(ctx.lab, manifest_path, out), stdout=stream,
                                   stderr=subprocess.STDOUT)
    deadline = time.monotonic() + READY_SECONDS
    while True:
        try:
            if "ready" in log.read_text(encoding="utf-8", errors="replace"):
                return process, json.loads(manifest_path.read_text(encoding="utf-8")), out / "gateway.jsonl"
        except (OSError, ValueError):
            pass
        if process.poll() is not None or time.monotonic() >= deadline:
            stop_process(process)
            raise RuntimeError("lab fixture not ready")
        time.sleep(0.05)


def start_engine(ctx, port, extra=()):
    private = pathlib.Path(ctx.private)
    out, stop, map_path = private / "engine.jsonl", private / "engine.stop", private / "translations.jsonl"
    for path in (out, stop):
        if path.exists():
            path.unlink()
    with open(private / "engine.log", "ab") as log, open(out, "wb") as stdout:
        process = subprocess.Popen(engine_command(ctx.route, port, map_path, stop, extra), stdout=stdout, stderr=log)
    return dict(process=process, out=out, stop=stop, map=map_path, ready=wait_ready(process, out))


def stop_engine(engine):
    process = engine["process"]
    try:
        engine["stop"].write_text("stop")
        exit_code = process.wait(timeout=STOP_SECONDS)
    except Exception:
        process.kill()
        process.wait()
        exit_code = None
    result = engine_result(engine["out"], exit_code)
    result["ready"] = result["ready"] and engine["ready"]
    return result


def add_firewall(private, port, remote):
    log = pathlib.Path(private) / "firewall.log"
    run_quiet(firewall_delete_command(), log)
    return "added" if run_quiet(firewall_add_command(port, remote), log) == 0 else "failed"


def remove_firewall(private, status):
    if run_quiet(firewall_delete_command(), pathlib.Path(private) / "firewall.log") != 0 and status == "added":
        raise RuntimeError("firewall rule removal failed")


def final_gateway(path):
    best = dict(read=False, lines=[])
    for _ in range(GATEWAY_READS):
        time.sleep(GATEWAY_READ_INTERVAL_SECONDS)
        current = read_gateway(path)
        if current["read"] and (not best["read"] or len(current["lines"]) > len(best["lines"])):
            best = current
    return best


def _nic_failure(step, code):
    if code is None:
        return dict(status="unavailable", step="exception")
    return dict(status="unavailable", step=step, exit_code=code)


def nic_start(addr, private):
    log = pathlib.Path(private) / "pktmon.log"
    for step, command in pktmon_start_steps(addr, pathlib.Path(private) / "nic.etl"):
        code = run_quiet(command, log)
        if code is None or (code != 0 and step != "filter_remove"):
            return _nic_failure(step, code)
    return None


def nic_finish(private):
    private = pathlib.Path(private)
    log, etl, pcap = private / "pktmon.log", private / "nic.etl", private / "nic.pcapng"
    code = run_quiet(["pktmon", "stop"], log)
    if code != 0:
        return _nic_failure("stop", code)
    for command in pktmon_convert_commands(etl, pcap):
        code = run_quiet(command, log)
        if code == 0 and pcap.exists():
            break
    else:
        return _nic_failure("convert", code)
    try:
        return dict(status="ok", packets=pcapng.parse_pcapng(pcap.read_bytes()))
    except (OSError, ValueError, IndexError, struct.error):
        return dict(status="unavailable", step="parse")


def guarded_nic(action, private, *args):
    try:
        return action(*args)
    except Exception:
        log_exception(private)
        return dict(status="unavailable", step="exception")


def nic_cleanup(private):
    log = pathlib.Path(private) / "pktmon.log"
    run_quiet(["pktmon", "stop"], log)
    run_quiet(["pktmon", "filter", "remove"], log)


def run_case(ctx):
    if ctx.target_ip is None or ctx.local_ip is None:
        return analysis.analyze(dict(precondition="INCONCLUSIVE_TARGET_UNREACHABLE", target_ip=None))
    private = pathlib.Path(ctx.private)
    state = dict(firewall="not_run", gateway=dict(read=False, lines=[]), nic=dict(status="not_run"),
                 engine=dict(ready=False, exit_code=None, summary=None), bridge={})
    lab = relay = engine = gateway_path = None
    nic_running = firewall_attempted = False
    bridge_port = None
    baseline, attempts = [], []
    try:
        lab, manifest, gateway_path = start_lab(ctx)
        relay = bridge.Bridge("0.0.0.0", (manifest["proxy_host"], manifest["proxy_port"]),
                              manifest["proxy_authorization"], private / "translations.jsonl",
                              private / "bridge.jsonl")
        relay.start()
        bridge_port = relay.port
        firewall_attempted = True
        state["firewall"] = add_firewall(private, relay.port, ctx.target_ip)
        baseline = run_role(ctx, BASELINE_ROLE)
        time.sleep(BASELINE_SETTLE_SECONDS)
        failure = guarded_nic(nic_start, private, ctx.target_ip, private)
        nic_running = failure is None
        state["nic"] = failure or state["nic"]
        engine = start_engine(ctx, relay.port)
        if engine["ready"]:
            for role in ROLES:
                attempts += run_role(ctx, role)
        time.sleep(SETTLE_SECONDS)
        if nic_running:
            nic_running = False
            state["nic"] = guarded_nic(nic_finish, private, private)
        current, engine = engine, None
        state["engine"] = stop_engine(current)
    finally:
        actions = []
        if engine is not None:
            actions.append(("engine", lambda: state.update(engine=stop_engine(engine))))
        if nic_running:
            actions.append(("nic", lambda: nic_cleanup(private)))
        if relay is not None:
            actions.append(("bridge", lambda: (relay.close(), state.update(bridge=relay.stats()))))
        if gateway_path is not None:
            actions.append(("gateway", lambda: state.update(gateway=final_gateway(gateway_path))))
        if lab is not None:
            actions.append(("lab", lambda: stop_process(lab)))
        actions.append(("manifest", lambda: (private / "lab" / "manifest.json").unlink(missing_ok=True)))
        if firewall_attempted:
            actions.append(("firewall", lambda: remove_firewall(private, state["firewall"])))
        ctx.cleanup_failures += len(run_all(actions, private))
    return analysis.analyze(dict(precondition=None, target_ip=ctx.target_ip, bridge_port=bridge_port,
                                 attempts=attempts, baseline=baseline,
                                 gateway=state["gateway"], bridge=state["bridge"], engine=state["engine"],
                                 firewall=state["firewall"], nic=state["nic"]))


def probe_env(route, private):
    with open(pathlib.Path(private) / "env.log", "ab") as stream:
        completed = subprocess.run([str(route), "env"], stdout=subprocess.PIPE, stderr=stream, timeout=60)
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("kind") == "env":
            return value
    return {}


def case_runners(qos):
    import cases
    return [(analysis.CASE, run_case), ("load", cases.run_load), ("shared-dscp", cases.run_shared),
            ("qos-policy", lambda ctx: cases.run_qos(ctx, qos)), ("udp-containment", cases.run_udp)]


def run_one(name, runner, ctx):
    try:
        result = runner(ctx)
        analysis.validate_public(result)
        return result if result.get("case") == name else analysis.harness_error_case("ValueError", name)
    except Exception as error:
        log_exception(ctx.private)
        return analysis.harness_error_case(type(error).__name__, name)


def pending_case(name):
    return dict(case=name, verdict=PENDING)


def print_case(result):
    name = result["case"]
    print(f"=== JOB-DSCP-ROUTE CASE {name} BEGIN ===\n{json.dumps(result, separators=(',', ':'))}\n"
          f"=== JOB-DSCP-ROUTE CASE {name} END ===", flush=True)


def write_results(args, env, qos, results, pending, faults):
    report = analysis.build_report(env, results + [pending_case(name) for name in pending], qos)
    (args.results / "aggregate-evidence.json").write_text(analysis.compact_dumps(report) + "\n", encoding="utf-8")
    (args.results / "environment.json").write_text(
        json.dumps(dict(schema=report["schema"], env=report["env"], qos_policy=report["qos_policy"]), indent=1)
        + "\n", encoding="utf-8")
    (args.results / "summary.md").write_text(analysis.markdown_summary(report), encoding="utf-8")
    summary = dict(schema=report["schema"], verdicts=report["verdicts"],
                   harness_ok=not faults and not report["harness_errors"] and not pending,
                   harness_errors=report["harness_errors"], harness_faults=list(faults), pending=list(pending))
    analysis.validate_public(summary)
    (args.results / "ci-summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return summary


def intermediate_failure(private, error, faults):
    log_exception(private)
    print(f"Intermediate output failed: {type(error).__name__}", flush=True)
    if INTERMEDIATE_WRITE not in faults:
        faults.append(INTERMEDIATE_WRITE)


def run(args):
    deadline = time.monotonic() + HARNESS_DEADLINE_SECONDS
    args.results.mkdir(parents=True, exist_ok=True)
    args.private.mkdir(parents=True, exist_ok=True)
    private = args.private.resolve()
    route = (args.bin / "route.exe").resolve()
    faults = []
    try:
        env = probe_env(route, private)
    except Exception as error:
        log_exception(private)
        print(f"Environment probe failed: {type(error).__name__}", flush=True)
        env = {}
        faults.append("env")
    env.update(image=os.environ.get("ImageOS"), image_version=os.environ.get("ImageVersion"))
    target = resolve_target(args.target_host)
    local = local_address_for(target)
    qos = dict(status=args.qos_policy_status, reason=args.qos_policy_reason or None, curl=args.qos_curl)
    runners = case_runners(qos)
    names = [name for name, _ in runners]
    results, verdicts, cleanup_failures = [], {}, 0
    for position, (name, runner) in enumerate(runners):
        now = time.monotonic()
        gate = CORE_GATES.get(name)
        if now >= deadline:
            result = analysis.skipped_case(name)
        elif gate is not None and verdicts.get(analysis.CASE) not in gate:
            result = dict(case=name, verdict=NOT_RUN_CORE_NOT_ROUTED)
        else:
            case_private = private / name
            case_private.mkdir(parents=True, exist_ok=True)
            ctx = Context(route, args.curl, args.lab, case_private, target, local,
                          deadline=min(deadline, now + CASE_BUDGETS.get(name, 0)))
            print(f"Running case {name}", flush=True)
            result = run_one(name, runner, ctx)
            cleanup_failures += ctx.cleanup_failures
        print(f"Case {name}: {result['verdict']}", flush=True)
        try:
            print_case(result)
        except Exception as error:
            intermediate_failure(private, error, faults)
        results.append(result)
        verdicts[name] = result["verdict"]
        try:
            write_results(args, env, qos, results, names[position + 1:],
                          faults + (["cleanup"] if cleanup_failures else []))
        except Exception as error:
            intermediate_failure(private, error, faults)
    if cleanup_failures:
        faults.append("cleanup")
    summary = write_results(args, env, qos, results, [], faults)
    return 0 if summary["harness_ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=pathlib.Path, required=True)
    parser.add_argument("--lab", type=pathlib.Path, required=True)
    parser.add_argument("--curl", default=os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32",
                                                       "curl.exe"))
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument("--private", type=pathlib.Path, required=True)
    parser.add_argument("--target-host", default=TARGET_HOST)
    parser.add_argument("--qos-curl", default=None)
    parser.add_argument("--qos-policy-status", default="unavailable")
    parser.add_argument("--qos-policy-reason", default="")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Exception as error:
        log_exception(args.private)
        print(f"Harness failure: {type(error).__name__}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
