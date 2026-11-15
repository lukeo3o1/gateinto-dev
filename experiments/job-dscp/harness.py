import argparse
import ipaddress
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

import analysis
import pcapng

MARKED_FILTER = "outbound and ((ip and ip.TOS >= 4) or (ipv6 and ipv6.TrafficClass >= 4))"
TEST_NET = "192.0.2.1"
COMPLETE_HOST = "api.github.com"
READY_SECONDS = 20
STOP_SECONDS = 25
SNIFF_MAX_SECONDS = 900
PKTMON_TIMEOUT_SECONDS = 30
HARNESS_DEADLINE_SECONDS = 11 * 60

CASES = [
    dict(name="tcp-external-syn", proto="tcp", target="test-net", port=443, timeout_ms=1500, count=3, nic=True,
         require_connect=False),
    dict(name="udp-external", proto="udp", target="test-net", port=443, timeout_ms=1500, count=3, nic=True,
         require_connect=False),
    dict(name="tcp-external-complete", proto="tcp", target="github", port=443, timeout_ms=5000, count=3, nic=True,
         require_connect=True),
    dict(name="tcp-loopback", proto="tcp", target="loopback4", port=None, timeout_ms=1500, count=3, nic=False,
         require_connect=False),
    dict(name="udp-loopback", proto="udp", target="loopback4", port=None, timeout_ms=1500, count=3, nic=False,
         require_connect=False),
    dict(name="tcp6-loopback", proto="tcp", target="loopback6", port=None, timeout_ms=1500, count=3, nic=False,
         require_connect=False),
]

ROLES = [
    dict(name="tagged-a", kind="tagged", dscp=10, spawn_depth=0),
    dict(name="tagged-b", kind="tagged", dscp=20, spawn_depth=0),
    dict(name="tagged-child", kind="tagged", dscp=10, spawn_depth=2),
    dict(name="untagged", kind="untagged", dscp=0, spawn_depth=0),
    dict(name="qos-policy", kind="qos", dscp=30, spawn_depth=0),
]


def observe_filter(proto, addr, port):
    if proto not in ("tcp", "udp"):
        raise ValueError("protocol")
    address = ipaddress.ip_address(addr)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port")
    family = "ip" if address.version == 4 else "ipv6"
    return f"outbound and {family} and {family}.DstAddr == {address} and {proto} and {proto}.DstPort == {port}"


def role_command(role, case, addr, port, out, log, probe, probe_qos):
    client = ["client", "--role", role["name"], "--proto", case["proto"], "--target", str(addr), "--port", str(port),
              "--count", str(case["count"]), "--timeout-ms", str(case["timeout_ms"]), "--out", str(out),
              "--log", str(log)]
    if role["spawn_depth"]:
        client += ["--spawn-depth", str(role["spawn_depth"])]
    if role["kind"] == "tagged":
        return [str(probe), "launch", "--dscp", str(role["dscp"]), "--", str(probe)] + client
    if role["kind"] == "qos":
        return [str(probe_qos)] + client
    return [str(probe)] + client


def sniff_command(probe, filter_text, label, out, stop):
    return [str(probe), "sniff", "--filter", filter_text, "--label", label, "--out", str(out), "--stop-file",
            str(stop), "--max-seconds", str(SNIFF_MAX_SECONDS)]


def pktmon_start_steps(addr, etl):
    return [("filter_remove", ["pktmon", "filter", "remove"]),
            ("filter_add", ["pktmon", "filter", "add", "job-dscp", "-i", str(addr)]),
            ("start", ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "96", "--file-name",
                       str(etl)])]


def pktmon_convert_commands(etl, pcap):
    return [["pktmon", "etl2pcap", str(etl), "--out", str(pcap)],
            ["pktmon", "pcapng", str(etl), "-o", str(pcap)]]


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
    found = None
    for line in (stdout or "").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("kind") == "launch":
            found = value
    return found


def sniffer_result(path, exit_code):
    records, _ = read_jsonl(path)
    summaries = [r for r in records if r.get("kind") == "summary"]
    return dict(ready=any(r.get("kind") == "ready" for r in records), exit_code=exit_code,
                summary=summaries[-1] if summaries else None,
                packets=[r for r in records if r.get("kind") == "packet"])


def role_input(role, attempts, run):
    return dict(name=role["name"], kind=role["kind"], expected_dscp=role["dscp"], skipped=run.get("skipped"),
                exit_ok=run.get("returncode") == 0,
                launch=launch_record(run.get("stdout")) if role["kind"] == "tagged" else None,
                attempts=[a for a in attempts if a.get("kind", "attempt") == "attempt" and a.get("role") == role["name"]])


def case_input(case, addr, port, roles, sniffers, nic, precondition, qos_policy, client_errors=0):
    return dict(case=case["name"], proto=case["proto"], target=dict(addr=addr, port=port), precondition=precondition,
                require_connect=case["require_connect"], roles=roles, sniffers=sniffers, nic=nic,
                qos_policy=qos_policy, client_errors=client_errors)


def client_error_count(path):
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


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


class Listener:
    def __init__(self, proto, addr):
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        self.sock = socket.socket(family, kind)
        try:
            self.sock.bind((addr, 0))
            if proto == "tcp":
                self.sock.listen(16)
            self.sock.settimeout(0.2)
        except OSError:
            self.sock.close()
            raise
        self.port = self.sock.getsockname()[1]
        self.proto = proto
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopping.is_set():
            try:
                if self.proto == "tcp":
                    connection, _ = self.sock.accept()
                    connection.close()
                else:
                    self.sock.recvfrom(2048)
            except OSError:
                continue

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=5)
        self.sock.close()


class Context:
    def __init__(self, probe, probe_qos, private, qos_status, github_addr, deadline=None):
        self.probe = probe
        self.probe_qos = probe_qos
        self.private = private
        self.qos_status = qos_status
        self.github_addr = github_addr
        self.deadline = deadline
        self.deadline_hit = False
        self.role_failures = {}
        self.cleanup_failures = 0


def run_quiet(command, log, timeout=PKTMON_TIMEOUT_SECONDS):
    try:
        with open(log, "ab") as stream:
            return subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout).returncode
    except FileNotFoundError:
        return -1
    except Exception:
        return None


def wait_ready(process, path):
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        records, _ = read_jsonl(path)
        if any(r.get("kind") == "ready" for r in records):
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.1)
    return False


def start_sniffer(ctx, private, label, filter_text):
    out, stop, log = private / f"{label}.jsonl", private / f"{label}.stop", private / f"{label}.log"
    for path in (out, stop):
        if path.exists():
            path.unlink()
    with open(log, "ab") as stream:
        process = subprocess.Popen(sniff_command(ctx.probe, filter_text, label, out, stop), stdout=stream,
                                   stderr=subprocess.STDOUT)
    return dict(label=label, process=process, out=out, stop=stop, ready=wait_ready(process, out))


def stop_sniffer(sniffer):
    process = sniffer["process"]
    try:
        sniffer["stop"].write_text("stop")
        exit_code = process.wait(timeout=STOP_SECONDS)
    except Exception:
        process.kill()
        process.wait()
        exit_code = None
    result = sniffer_result(sniffer["out"], exit_code)
    result["ready"] = result["ready"] and sniffer["ready"]
    return result


def _nic_failure(step, code):
    if code is None:
        return dict(status="unavailable", step="exception")
    return dict(status="unavailable", step=step, exit_code=code)


def nic_start(addr, private):
    log = private / "pktmon.log"
    for step, command in pktmon_start_steps(addr, private / "nic.etl"):
        code = run_quiet(command, log)
        if code != 0:
            return _nic_failure(step, code)
    return None


def nic_finish(private):
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
    log = private / "pktmon.log"
    run_quiet(["pktmon", "stop"], log)
    run_quiet(["pktmon", "filter", "remove"], log)


def run_role(ctx, role, case, addr, port, clients, log, private):
    if role["kind"] == "qos" and ctx.qos_status != "created":
        return dict(returncode=None, stdout="", skipped="policy_unavailable")
    if ctx.deadline is not None and time.monotonic() >= ctx.deadline:
        ctx.deadline_hit = True
        return dict(returncode=None, stdout="", skipped="deadline")
    timeout = case["count"] * (2 * case["timeout_ms"] + 200) / 1000 + 15
    command = role_command(role, case, addr, port, clients, log, ctx.probe, ctx.probe_qos)
    with open(private / f"{role['name']}.log", "ab") as stream:
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=stream, timeout=timeout)
        except subprocess.TimeoutExpired:
            return dict(returncode=None, stdout="")
    return dict(returncode=completed.returncode, stdout=completed.stdout.decode("utf-8", errors="replace"))


def case_target(ctx, case):
    if case["target"] == "test-net":
        return TEST_NET, case["port"], None, None
    if case["target"] == "github":
        if ctx.github_addr is None:
            return None, None, None, "INCONCLUSIVE_TARGET_UNREACHABLE"
        return ctx.github_addr, case["port"], None, None
    addr = "127.0.0.1" if case["target"] == "loopback4" else "::1"
    try:
        listener = Listener(case["proto"], addr)
    except OSError:
        return None, None, None, "INCONCLUSIVE_NO_IPV6" if case["target"] == "loopback6" else None
    return addr, listener.port, listener, None


def run_case(ctx, case):
    private = ctx.private / case["name"]
    private.mkdir(parents=True, exist_ok=True)
    addr, port, listener, precondition = case_target(ctx, case)
    empty = dict(ready=False, exit_code=None, summary=None, packets=[])
    if addr is None:
        if precondition is None:
            raise RuntimeError("loopback listener unavailable")
        return analysis.analyze_case(case_input(case, TEST_NET, 1, [], dict(observe=empty, marked=empty),
                                                dict(status="not_applicable"), precondition, ctx.qos_status))
    clients, client_log = private / "clients.jsonl", private / "clients.log"
    for path in (clients, client_log):
        if path.exists():
            path.unlink()
    sniffers, results, runs = [], {}, {}
    nic = dict(status="not_applicable")
    try:
        sniffers.append(start_sniffer(ctx, private, "observe", observe_filter(case["proto"], addr, port)))
        if sniffers[0]["ready"]:
            sniffers.append(start_sniffer(ctx, private, "marked", MARKED_FILTER))
        if all(s["ready"] for s in sniffers) and len(sniffers) == 2:
            nic_running = False
            if case["nic"]:
                failure = guarded_nic(nic_start, private, addr, private)
                nic_running = failure is None
                nic = failure or nic
            for role in ROLES:
                runs[role["name"]] = run_role(ctx, role, case, addr, port, clients, client_log, private)
            time.sleep(1.0)
            if nic_running:
                nic = guarded_nic(nic_finish, private, private)
        else:
            for role in ROLES:
                runs[role["name"]] = dict(returncode=None, stdout="", skipped="sniffer_not_ready")
    finally:
        actions = [("nic", lambda: nic_cleanup(private))] if case["nic"] else []
        for sniffer in sniffers:
            actions.append((sniffer["label"], lambda sniffer=sniffer: results.update(
                {sniffer["label"]: stop_sniffer(sniffer)})))
        if listener is not None:
            actions.append(("listener", listener.close))
        ctx.cleanup_failures += len(run_all(actions, private))
    attempts, _ = read_jsonl(clients)
    roles = [role_input(role, attempts, runs.get(role["name"], dict(returncode=None, stdout="")))
             for role in ROLES]
    ctx.role_failures[case["name"]] = sum(1 for r in roles if not r["exit_ok"] and not r["skipped"])
    return analysis.analyze_case(case_input(case, addr, port, roles,
                                            dict(observe=results.get("observe", empty),
                                                 marked=results.get("marked", empty)),
                                            nic, precondition, ctx.qos_status, client_error_count(client_log)))


def probe_env(probe, private):
    with open(private / "env.log", "ab") as stream:
        completed = subprocess.run([str(probe), "env"], stdout=subprocess.PIPE, stderr=stream, timeout=60)
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("kind") == "env":
            return value
    return {}


def resolve_github():
    try:
        infos = socket.getaddrinfo(COMPLETE_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    return infos[0][4][0] if infos else None


def run(args):
    args.results.mkdir(parents=True, exist_ok=True)
    args.private.mkdir(parents=True, exist_ok=True)
    probe = (args.bin / "probe.exe").resolve()
    ctx = Context(probe, (args.bin / "probe-qos.exe").resolve(), args.private.resolve(), args.qos_policy_status,
                  resolve_github(), deadline=time.monotonic() + HARNESS_DEADLINE_SECONDS)
    faults = []
    try:
        env = probe_env(probe, ctx.private)
    except Exception as error:
        log_exception(ctx.private)
        print(f"Environment probe failed: {type(error).__name__}", flush=True)
        env = {}
        faults.append("env")
    env.update(image=os.environ.get("ImageOS"), image_version=os.environ.get("ImageVersion"))
    cases = []
    for case in CASES:
        if time.monotonic() >= ctx.deadline:
            result = analysis.skipped_case(case["name"])
        else:
            print(f"Running case {case['name']}", flush=True)
            try:
                result = run_case(ctx, case)
            except Exception as error:
                log_exception(ctx.private)
                result = analysis.harness_error_case(case["name"], type(error).__name__)
        print(f"Case {result['case']}: {result['verdict']}", flush=True)
        cases.append(result)
    if ctx.deadline_hit:
        faults.append("deadline")
    if ctx.cleanup_failures:
        faults.append("cleanup")
    aggregate = analysis.build_aggregate(env, dict(status=args.qos_policy_status, reason=args.qos_policy_reason),
                                         cases)
    (args.results / "aggregate-evidence.json").write_text(analysis.compact_dumps(aggregate) + "\n", encoding="utf-8")
    (args.results / "environment.json").write_text(
        json.dumps(dict(schema=aggregate["schema"], env=aggregate["env"], qos_policy=aggregate["qos_policy"]),
                   indent=1) + "\n", encoding="utf-8")
    (args.results / "summary.md").write_text(analysis.markdown_summary(aggregate), encoding="utf-8")
    failed = sorted(set(aggregate["harness_errors"]) | {name for name, verdict in aggregate["verdicts"].items()
                                                        if verdict == "INCONCLUSIVE_SNIFFER_ERROR"}
                    | {name for name, count in ctx.role_failures.items() if count})
    summary = dict(schema=aggregate["schema"], harness_ok=not failed and not faults, failed_cases=failed,
                   harness_faults=faults, role_failures=sum(ctx.role_failures.values()), capture_only=True)
    analysis.validate_public(summary)
    (args.results / "ci-summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return 0 if summary["harness_ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=pathlib.Path, required=True)
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument("--private", type=pathlib.Path, required=True)
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
