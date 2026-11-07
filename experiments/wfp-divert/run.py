import argparse
import ctypes
import datetime
import ipaddress
import json
import math
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


class NoOwnershipConfirmation(RuntimeError):
    pass


def normalized_path(value):
    return str(value).replace("/", "\\").lower().removeprefix("\\??\\")


def tuple_key(value):
    try:
        key = (value["local_ip"], int(value["local_port"]), value["remote_ip"],
               int(value["remote_port"]), int(value["protocol"]))
        if not key[0] or not key[2] or min(key[1], key[3]) <= 0:
            return None
        return key
    except (KeyError, ValueError, TypeError):
        return None


def valid_client_result(value, connect_only=False):
    return (value.get("kind") == "client" and tuple_key(value) is not None and
            value.get("status") == ("connected" if connect_only else "echo_ok"))


def retransmissions_verified(records):
    dropped = [p for p in records if p.get("kind") == "packet" and p.get("syn") and
               p.get("reason") == "injected_first_syn_drop"]
    return bool(dropped) and all(any(
        p.get("kind") == "packet" and p.get("syn") and p.get("action") in ["direct", "proxy"]
        and tuple_key(p) == tuple_key(first) and p.get("generation") == first.get("generation")
        and p.get("sequence") == first.get("sequence") and p.get("capture_qpc", 0) > first.get("capture_qpc", 0)
        for p in records) for first in dropped)


def reuse_rejection_verified(records, key, launched_qpc, original_sequence):
    return any(p.get("kind") == "packet" and tuple_key(p) == key and p.get("syn") and
               p.get("capture_qpc", 0) >= launched_qpc and p.get("sequence") is not None and
               p["sequence"] != original_sequence and p.get("action") == "drop" and
               p.get("reason") == "ambiguous_reuse_of_proxy_tuple" for p in records)


def timing_summary(clients, packets, events, decisions, frequency):
    rows = []
    for app, client in clients:
        key = tuple_key(client)
        matching = [p for p in packets if p.get("kind") == "packet" and tuple_key(p) == key]
        evidence = [e for e in events if tuple_key(e) == key]
        if not matching or not evidence:
            continue
        first = min(matching, key=lambda p: p["capture_qpc"])
        event = min(evidence, key=lambda e: e["recv_qpc"])
        decision = next((d for d in decisions if tuple_key(d) == key), None)
        rows.append(dict(app=app, nonce=client["nonce"], tuple=list(key),
                         packet_capture_qpc=first["capture_qpc"], packet_receive_qpc=first["recv_qpc"],
                         event_filetime=event.get("event_filetime"), occurrence_qpc=event.get("occurrence_qpc"),
                         native_receive_qpc=event["recv_qpc"], decision_ready_qpc=decision.get("decision_qpc") if decision else None,
                         notification_minus_capture_ms=(event["recv_qpc"] - first["capture_qpc"]) * 1000 / frequency,
                         decision_minus_capture_ms=(decision["decision_qpc"] - first["capture_qpc"]) * 1000 / frequency if decision else None))

    def distribution(values):
        values = sorted(v for v in values if v is not None)
        if not values:
            return None
        return dict(count=len(values), min=min(values), max=max(values),
                    p50=values[max(0, math.ceil(len(values) * .5) - 1)],
                    p95=values[max(0, math.ceil(len(values) * .95) - 1)])

    return dict(matched_client_tuples=len(rows), unmatched_client_tuples=len(clients) - len(rows),
                native_after_packet_capture=sum(r["native_receive_qpc"] > r["packet_capture_qpc"] for r in rows),
                native_after_packet_receive=sum(r["native_receive_qpc"] > r["packet_receive_qpc"] for r in rows),
                notification_minus_capture_ms=distribution(r["notification_minus_capture_ms"] for r in rows),
                decision_minus_capture_ms=distribution(r["decision_minus_capture_ms"] for r in rows), rows=rows)


def native_command(bin_dir, out_dir, seconds, wfp_api):
    return [bin_dir / "native-events.exe", "--seconds", seconds, "--out", (out_dir / "native.jsonl").resolve(),
            "--stop-file", (out_dir / "native.stop").resolve(), "--state-out", (out_dir / "bfe-state.json").resolve(),
            "--wfp-api", wfp_api]


def inproc_command(bin_dir, out_dir, manifest, selected_app, args):
    port = manifest["target_port"]
    command = [bin_dir / "inproc.exe", "--target", manifest["target_ip"], "--port", port,
               "--out", (out_dir / "packets.jsonl").resolve(),
               "--summary", (out_dir / "engine-summary.json").resolve(),
               "--state-out", (out_dir / "bfe-state.json").resolve(),
               "--stop-file", (out_dir / "inproc.stop").resolve(),
               "--selected-app", selected_app, "--mode", args.mode,
               "--hold-ms", args.hold_ms, "--seconds", args.seconds,
               "--window-before-ms", args.window_before_ms, "--window-after-ms", args.window_after_ms,
               "--leak-ms", args.leak_ms, "--send-rst", 1 if args.send_rst else 0]
    if args.protocol == "udp":
        command += ["--udp-port", manifest["udp_ports"][0]]
    if args.quic:
        command += ["--udp-port", manifest["udp_ports"][0], "--quic-port", manifest["udp_ports"][0]]
    return command


def inproc_evaluate(summary, mode, protocol, quic, expected_proxy_clients, gateway_count):
    if not summary or summary.get("engine") != "inproc" or not summary.get("success"):
        return "FAIL", "inproc engine summary missing or reported failure"
    redirecting = mode == "redirect" and protocol == "tcp"
    expected = expected_proxy_clients if redirecting else 0
    if summary.get("decided_proxy") != expected:
        return "FAIL", f"decided_proxy {summary.get('decided_proxy')} != expected {expected}"
    if gateway_count != expected:
        return "FAIL", f"gateway CONNECT count {gateway_count} != expected {expected}"
    if quic and not summary.get("quic_drops"):
        return "FAIL", "QUIC case dropped no selected UDP/443 flow"
    return "PASS_RESTRICTED_CASE", None


def wrong_app_redirected(decisions, selected_tuples):
    return any(d.get("kind") == "decision" and d.get("action") == "proxy" and
               tuple_key(d) not in selected_tuples for d in decisions)


def collector_errors(records):
    return any(r.get("kind") == "error" for r in records)


def clean_native_summary(native_summary):
    return bool(native_summary) and not native_summary.get("errors") and not native_summary.get("queue_dropped")


def native_evidence_status(status, source, native_summary):
    if (status not in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION"] or source != "wfp" or
            (native_summary or {}).get("wfp_count")):
        return status, None
    return ("INCONCLUSIVE_NO_NATIVE_EVENTS",
            "native summary reported wfp_count 0; WFP produced no CLASSIFY_ALLOW events, so this result does not exercise WFP attribution")


def poll_evidence_status(status, error, wfp_api, native_summary):
    if wfp_api != "poll" or native_summary is None or native_summary.get("wfp_polls", 0):
        return status, error
    reason = "native summary reported wfp_polls 0; the poll thread never completed an enumeration, so poll mode was not exercised"
    return "FAIL", f"{error}; {reason}" if error else reason


def security_fields(value):
    if "raw_xml" not in value:
        return value
    value = value.copy()
    try:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        root = ET.fromstring(value["raw_xml"])
        fields = {x.attrib["Name"]: x.text for x in root.findall("e:EventData/e:Data", ns)}
        direction = {"%%14592": "inbound", "%%14593": "outbound"}.get(fields["Direction"], "unknown")
        source, dest = ("Source", "Dest") if direction == "outbound" else ("Dest", "Source")
        value.update(app_path=fields["Application"], protocol=int(fields["Protocol"]),
                     local_ip=fields[source + "Address"], local_port=int(fields[source + "Port"]),
                     remote_ip=fields[dest + "Address"], remote_port=int(fields[dest + "Port"]),
                     direction=direction, pid=int(fields["ProcessID"], 16 if fields["ProcessID"].startswith("0x") else 10))
        value["complete"] = bool(tuple_key(value)) and direction != "unknown" and bool(value["app_path"])
        stamp = root.find("e:System/e:TimeCreated", ns)
        if stamp is not None:
            instant = datetime.datetime.fromisoformat(stamp.attrib["SystemTime"].replace("Z", "+00:00"))
            value["event_filetime"] = round((instant.timestamp() + 11644473600) * 10_000_000)
    except (ET.ParseError, KeyError, TypeError, ValueError):
        value["complete"] = False
    return value


class Attribution:
    def __init__(self, source, selected_path, frequency, hold_ms, delay_ms=0, skip_all=False, mode="redirect"):
        self.source = source
        self.selected = normalized_path(selected_path)
        self.frequency = frequency
        self.hold = frequency * hold_ms / 1000
        self.delay = frequency * delay_ms / 1000
        self.skip_all = skip_all
        self.mode = mode
        self.pending = {}
        self.events = {}
        self.generations = {}
        self.ambiguous = set()
        self.issued = set()

    def packet(self, value):
        key = tuple_key(value)
        if key is None or value.get("kind") != "packet" or value.get("action") != "pending":
            return
        generation = int(value["generation"])
        if key in self.generations and self.generations[key] != generation:
            self.ambiguous.add(key)
        self.generations[key] = generation
        self.pending[(key, generation)] = value

    def event(self, value):
        if self.skip_all or value.get("kind") != self.source:
            return
        value = security_fields(value)
        key = tuple_key(value)
        if key is None or not value.get("complete") or value.get("direction") != "outbound" or not value.get("app_path"):
            return
        if "occurrence_qpc" not in value or "recv_qpc" not in value:
            return
        self.events.setdefault(key, []).append(value)

    def decisions(self, now):
        output = []
        for (key, generation), packet in list(self.pending.items()):
            if (key, generation) in self.issued or key in self.ambiguous:
                continue
            if now >= generation + self.hold:
                self.pending.pop((key, generation), None)
                continue
            evidence = [e for e in self.events.get(key, [])
                        if e["recv_qpc"] + self.delay <= now
                        and abs(e["occurrence_qpc"] - generation) <= self.frequency * 2
                        and e["recv_qpc"] <= generation + self.hold]
            if not evidence:
                continue
            paths = {normalized_path(e["app_path"]) for e in evidence}
            if len(paths) != 1:
                self.ambiguous.add(key)
                continue
            selected = paths == {self.selected}
            result = dict(packet)
            result.update(kind="decision", action="proxy" if selected and self.mode == "redirect" and key[4] == 6 else "direct",
                          selected=selected, source=self.source, evidence_recv_qpc=evidence[-1]["recv_qpc"],
                          decision_qpc=now, reason="native_confirmation", app_path=evidence[-1]["app_path"])
            output.append(result)
            self.issued.add((key, generation))
        return output


class JsonTail:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.offset = 0
        self.partial = ""

    def read(self):
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as stream:
            stream.seek(self.offset)
            chunk = stream.read()
            self.offset = stream.tell()
        lines = (self.partial + chunk).split("\n")
        self.partial = lines.pop()
        output = []
        for line in lines:
            if line.strip():
                output.append(json.loads(line))
        return output


def native_path(path):
    path = str(pathlib.Path(path).resolve())
    drive, suffix = os.path.splitdrive(path)
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):
        raise ctypes.WinError()
    return buffer.value + suffix


def windows_clock():
    frequency = ctypes.c_longlong()
    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))
    before, after = ctypes.c_longlong(), ctypes.c_longlong()
    filetime = ctypes.c_ulonglong()
    ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(before))
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(filetime))
    ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(after))
    return frequency.value, filetime.value, (before.value + after.value) // 2, after.value - before.value


def qpc():
    result = ctypes.c_longlong()
    ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(result))
    return result.value


def run_inproc(args, parser):
    if args.seconds < 15 or args.hold_ms < 1:
        parser.error("require --seconds >= 15 and --hold-ms >= 1")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("--out must be empty to avoid stale evidence")
    args.out.mkdir(parents=True, exist_ok=True)
    args.bin = args.bin.resolve()
    redirecting = args.mode == "redirect" and not args.quic
    processes, logs = [], []
    private = tempfile.TemporaryDirectory(prefix="gateinto-wfp-private-", dir=args.private_dir)
    bridge = None
    summary = dict(status="NOT_COMPLETED", engine="inproc", mode=args.mode, protocol=args.protocol,
                   quic=args.quic, concurrency=args.concurrency, topology="single-host-local")

    def start(command, name):
        output = (args.out / (name + ".stdout.txt")).open("w", encoding="utf-8")
        logs.append(output)
        process = subprocess.Popen([str(x) for x in command], stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        processes.append(process)
        return process

    def alive(process, label):
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}; see its log")

    try:
        manifest_path = pathlib.Path(private.name) / "private-manifest.json"
        fixture = start([args.fixture.resolve(), "--manifest", manifest_path.resolve(), "--out", args.out.resolve(),
                         "--seconds", args.seconds + 15, "--bind-ip", args.bind_ip], "fixture")
        deadline = time.monotonic() + 15
        while True:
            alive(fixture, "fixture")
            try:
                manifest = json.loads(manifest_path.read_text())
                break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError("fixture manifest missing")
            time.sleep(.02)
        manifest_path.chmod(0o600)
        selected_app = native_path(args.bin / "app-a.exe")
        summary["selected_app"] = selected_app
        packet_file = args.out / "packets.jsonl"
        packet_tail = JsonTail(packet_file)
        if redirecting:
            from bridge import Bridge
            bridge = Bridge(manifest, packet_file, args.out / "bridge.jsonl")
            bridge.start()
        engine_args = inproc_command(args.bin, args.out, manifest, selected_app, args)
        if redirecting:
            engine_args += ["--listener-port", bridge.port]
        engine = start(engine_args, "inproc")
        packet_ready = False
        deadline = time.monotonic() + 10
        while not packet_ready:
            alive(engine, "inproc engine")
            for record in packet_tail.read():
                if record.get("kind") == "ready":
                    packet_ready = True
            if time.monotonic() > deadline:
                raise TimeoutError("inproc engine readiness missing")
            time.sleep(.01)

        quic_port = manifest["udp_ports"][0]
        clients = []

        def launch(app, iteration, protocol, port):
            command = [args.bin / f"app-{app}.exe", "--target", manifest["target_ip"], "--port", port,
                       "--protocol", protocol, "--nonce", f"inproc-{args.mode}-{app}-{protocol}-{iteration}"]
            clients.append((app, protocol, start(command, f"client-{app}-{protocol}-{iteration}")))

        if args.quic:
            for iteration in range(3):
                launch("a", iteration, "udp", quic_port)
        elif args.concurrency:
            for index in range(args.concurrency):
                launch("a" if index % 2 == 0 else "b", index, "tcp", manifest["target_port"])
        else:
            for iteration in range(3):
                for app in ["a", "b"]:
                    launch(app, iteration, "tcp", manifest["target_port"])

        deadline = time.monotonic() + min(args.seconds - 5, 40)
        while any(p.poll() is None for _, _, p in clients):
            alive(engine, "inproc engine")
            if time.monotonic() > deadline:
                raise TimeoutError("client timeout")
            time.sleep(.01)

        (args.out / "inproc.stop").touch()
        try:
            engine.wait(timeout=args.seconds + 15)
        except subprocess.TimeoutExpired:
            engine.terminate()
            raise RuntimeError("inproc engine did not exit")
        packet_records = JsonTail(packet_file).read()
        decisions = [r for r in packet_records if r.get("kind") == "decision"]

        selected_tuples = set()
        dropped_client_fail = 0
        client_results = []
        for stdout in sorted(args.out.glob("client-*.stdout.txt")):
            client_results.extend(JsonTail(stdout).read())

        for app, protocol, process in clients:
            if args.quic and app == "a":
                if process.returncode == 0:
                    raise RuntimeError("selected QUIC UDP flow was not dropped; client unexpectedly echoed")
                dropped_client_fail += 1
            elif process.returncode != 0:
                raise RuntimeError(f"client app-{app}/{protocol} failed; trace retained")
        for record in client_results:
            if record.get("status") == "echo_ok" and record.get("nonce", "").split("-")[2] == "a" \
                    and record.get("protocol") == 6:
                key = tuple_key(record)
                if key:
                    selected_tuples.add(key)

        if wrong_app_redirected(decisions, selected_tuples):
            raise RuntimeError("a non-selected client tuple was redirected to the proxy")

        gateway_records = []
        gateway_path = args.out / "gateway.jsonl"
        expected_proxy = len(selected_tuples) if redirecting and args.protocol == "tcp" else 0
        for _ in range(20):
            try:
                gateway_records = [json.loads(line) for line in gateway_path.read_text().splitlines() if line.strip()]
                if len(gateway_records) == expected_proxy:
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(.05)
        expected_line = f"CONNECT {manifest['target_ip']}:{manifest['target_port']} HTTP/1.1"
        if any(r.get("kind") != "gateway_connect" or r.get("request_line") != expected_line for r in gateway_records):
            raise RuntimeError("gateway CONNECT destination differs from expected transparent tunnels")

        try:
            engine_summary = json.loads((args.out / "engine-summary.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            engine_summary = None
        summary["engine_summary"] = engine_summary
        if any(r.get("kind") == "error" for r in packet_records):
            raise RuntimeError("inproc engine reported an error")
        complete = [r for r in packet_records if r.get("kind") == "complete"]
        if not complete or not complete[-1].get("success"):
            raise RuntimeError("inproc engine did not complete successfully")
        if engine.returncode != 0:
            raise RuntimeError("inproc engine exit code was nonzero")
        status, error = inproc_evaluate(engine_summary, args.mode, "udp" if args.quic else args.protocol,
                                        args.quic, expected_proxy, len(gateway_records))
        summary["status"] = status
        if error:
            summary["error"] = error
        summary["selected_tuple_count"] = len(selected_tuples)
        summary["gateway_connect_count"] = len(gateway_records)
        summary["quic_dropped_clients"] = dropped_client_fail
    except Exception as error:
        summary.update(status="FAIL", error=str(error))
    finally:
        for name in ["inproc.stop"]:
            (args.out / name).touch()
        if bridge:
            bridge.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in logs:
            stream.close()
        private.cleanup()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))
    return 0 if summary["status"] == "PASS_RESTRICTED_CASE" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--private-dir", type=pathlib.Path)
    parser.add_argument("--source", choices=["wfp", "security5156"], default="wfp")
    parser.add_argument("--wfp-api", choices=["subscribe2", "subscribe4", "poll"], default="subscribe2")
    parser.add_argument("--mode", choices=["hold", "redirect"], default="hold")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--scenario", choices=["baseline", "retransmit", "reuse"], default="baseline")
    parser.add_argument("--hold-ms", type=int, default=1000)
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--skip-all", action="store_true")
    parser.add_argument("--bind-ip", default="127.0.0.1")
    parser.add_argument("--external-target")
    parser.add_argument("--external-port", type=int, default=443)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=35)
    parser.add_argument("--engine", choices=["external", "inproc"], default="external")
    parser.add_argument("--concurrency", type=int, default=0)
    parser.add_argument("--quic", action="store_true")
    parser.add_argument("--window-before-ms", type=int, default=500)
    parser.add_argument("--window-after-ms", type=int, default=50)
    parser.add_argument("--leak-ms", type=int, default=2000)
    parser.add_argument("--send-rst", action="store_true")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows is required; pure attribution tests run on other hosts")
    if args.engine == "inproc":
        return run_inproc(args, parser)
    if args.seconds < 15 or args.iterations < 1 or args.hold_ms < 1 or args.delay_ms < 0:
        parser.error("require --seconds >= 15, --iterations >= 1, --hold-ms >= 1 and --delay-ms >= 0")
    if args.scenario != "baseline" and args.protocol != "tcp":
        parser.error("retransmit and reuse scenarios require TCP")
    if args.scenario == "reuse" and (args.mode != "redirect" or args.iterations != 1 or args.skip_all or args.delay_ms >= args.hold_ms):
        parser.error("reuse requires redirect mode, one iteration and normal native attribution")
    if args.external_target:
        try:
            external = ipaddress.IPv4Address(args.external_target)
        except ipaddress.AddressValueError:
            parser.error("--external-target must be an IPv4 literal")
        if external.is_loopback or external.is_unspecified or not 1 <= args.external_port <= 65535:
            parser.error("external target must not be loopback/unspecified and port must be 1..65535")
        if args.mode != "hold" or args.protocol != "tcp" or args.scenario != "baseline":
            parser.error("external target is valid only for baseline TCP hold mode")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("--out must be empty to avoid stale evidence")
    args.out.mkdir(parents=True, exist_ok=True)
    args.bin = args.bin.resolve()
    processes, logs = [], []
    private = tempfile.TemporaryDirectory(prefix="gateinto-wfp-private-", dir=args.private_dir)
    bridge = None
    summary = dict(status="NOT_COMPLETED", source=args.source, wfp_api=args.wfp_api, mode=args.mode,
                   protocol=args.protocol, scenario=args.scenario, topology="single-host-local", decisions=0,
                   selected_confirmed=0, redirected=0, clients=[])
    if args.external_target:
        summary.update(topology="external-connect-only", controlled_echo=False,
                       qualification="Outbound TCP connection and native attribution only; no controlled payload/echo or proxy validation",
                       external_target=args.external_target, external_port=args.external_port)

    def start(command, name):
        output = (args.out / (name + ".stdout.txt")).open("w", encoding="utf-8")
        logs.append(output)
        process = subprocess.Popen([str(x) for x in command], stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        processes.append(process)
        return process

    def alive(process, label):
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}; see its log")

    try:
        manifest_path = pathlib.Path(private.name) / "private-manifest.json"
        fixture = start([args.fixture.resolve(), "--manifest", manifest_path.resolve(), "--out", args.out.resolve(),
                         "--seconds", args.seconds + 15, "--bind-ip", args.bind_ip], "fixture")
        deadline = time.monotonic() + 15
        while True:
            alive(fixture, "fixture")
            try:
                manifest = json.loads(manifest_path.read_text())
                break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError("fixture manifest missing")
            time.sleep(.02)
        manifest_path.chmod(0o600)
        if args.external_target:
            manifest.update(target_ip=args.external_target, target_port=args.external_port)
        frequency, anchor_filetime, anchor_qpc, uncertainty = windows_clock()
        summary.update(qpc_frequency=frequency, anchor_filetime=anchor_filetime,
                       anchor_qpc=anchor_qpc, anchor_uncertainty_ticks=uncertainty,
                       selected_path=native_path(args.bin / "app-a.exe"))
        engine = Attribution(args.source, summary["selected_path"], frequency, args.hold_ms,
                             args.delay_ms, args.skip_all, args.mode)
        native_file, packet_file = args.out / "native.jsonl", args.out / "packets.jsonl"
        native_tail, packet_tail = JsonTail(native_file), JsonTail(packet_file)
        control = args.out / "control.txt"
        control.touch()
        native = start(native_command(args.bin, args.out, args.seconds, args.wfp_api), "native")
        native_ready = False
        deadline = time.monotonic() + 10
        while not native_ready:
            alive(native, "native collector")
            for event in native_tail.read():
                if event.get("kind") == "ready":
                    native_ready = True
            if time.monotonic() > deadline:
                raise TimeoutError("native subscription readiness missing")
            time.sleep(.01)
        port = manifest["target_port"] if args.protocol == "tcp" else manifest["udp_ports"][0]
        packet_args = [args.bin / "packets.exe", "--target", manifest["target_ip"], "--port", port,
                       "--seconds", args.seconds, "--out", packet_file.resolve(),
                       "--hold-ms", args.hold_ms, "--control", control.resolve(),
                       "--stop-file", (args.out / "packets.stop").resolve()]
        if args.mode == "redirect":
            from bridge import Bridge
            bridge = Bridge(manifest, packet_file, args.out / "bridge.jsonl")
            bridge.start()
            packet_args += ["--listener-port", bridge.port]
        if args.protocol == "udp":
            packet_args += ["--second-port", manifest["udp_ports"][1]]
        if args.scenario == "retransmit":
            packet_args += ["--drop-first-syn", "1"]
        packet_process = start(packet_args, "packet")
        pending_clients, packet_ready, packet_records, decision_records, ownership_observations = [], False, [], [], []
        decision_log = (args.out / "decisions.jsonl").open("w", encoding="utf-8")
        logs.append(decision_log)
        control_stream = control.open("a", encoding="ascii", buffering=1)
        logs.append(control_stream)
        deadline = time.monotonic() + 10

        def pump():
            nonlocal packet_ready
            for event in native_tail.read():
                event = security_fields(event)
                if "event_filetime" in event:
                    event["occurrence_qpc"] = anchor_qpc + (event["event_filetime"] - anchor_filetime) * frequency / 10_000_000
                if event.get("kind") == args.source and event.get("direction") == "outbound" and event.get("complete"):
                    ownership_observations.append(event)
                engine.event(event)
            for packet in packet_tail.read():
                packet_records.append(packet)
                if packet.get("kind") == "ready":
                    packet_ready = True
                engine.packet(packet)
            for decision in engine.decisions(qpc()):
                decision_records.append(decision)
                key = tuple_key(decision)
                control_stream.write("decision " + " ".join(str(x) for x in (*key, decision["generation"], decision["action"])) + "\n")
                decision_log.write(json.dumps(decision) + "\n")
                decision_log.flush()
                summary["decisions"] += 1
                summary["selected_confirmed"] += int(decision["selected"])
                summary["redirected"] += int(decision["action"] == "proxy")

        while not packet_ready:
            alive(packet_process, "packet collector")
            pump()
            if time.monotonic() > deadline:
                raise TimeoutError("NETWORK handle readiness missing")
            time.sleep(.01)
        def launch(app, iteration, extra=()):
            command = [args.bin / f"app-{app}.exe", "--target", manifest["target_ip"],
                       "--port", port, "--protocol", args.protocol,
                       "--nonce", f"{args.source}-{args.mode}-{app}-{iteration}"]
            if args.protocol == "udp":
                command += ["--second-port", manifest["udp_ports"][1]]
            if args.external_target:
                command += ["--connect-only", "1"]
            command += list(extra)
            label = f"client-{app}-{iteration}"
            entry = (app, label, start(command, label))
            pending_clients.append(entry)
            return entry

        def wait_clients(entries, seconds=20, rejection=None):
            deadline = time.monotonic() + min(args.seconds - 5, seconds)
            while any(p.poll() is None for _, _, p in entries):
                alive(packet_process, "packet collector")
                alive(native, "native collector")
                pump()
                if rejection and rejection():
                    for _, _, process in entries:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=5)
                    return
                if time.monotonic() > deadline:
                    raise TimeoutError("client timeout")
                time.sleep(.002)

        reuse_key, reuse_started = None, None
        if args.scenario == "reuse":
            first = launch("a", 0, ["--close-mode", "reset"])
            wait_clients([first])
            if first[2].returncode:
                raise RuntimeError("initial selected client failed before tuple reuse")
            first_records = JsonTail(args.out / (first[1] + ".stdout.txt")).read()
            if len(first_records) != 1 or first_records[0].get("status") != "echo_ok":
                raise RuntimeError("initial client did not record a single echo tuple")
            reuse_key = tuple_key(first_records[0])
            original_syns = [p for p in packet_records if p.get("kind") == "packet" and tuple_key(p) == reuse_key and p.get("syn")]
            if not original_syns:
                raise RuntimeError("initial selected client SYN sequence missing")
            original_sequence = min(original_syns, key=lambda p: p["capture_qpc"])["sequence"]
            reuse_started = qpc()
            attempt_file = args.out / "client-b-attempt.jsonl"
            second = launch("b", 0, ["--source-port", reuse_key[1], "--close-mode", "reset",
                                      "--local-ip", reuse_key[0],
                                      "--attempt-out", attempt_file.resolve()])

            def verified_reuse():
                try:
                    attempts = [json.loads(line) for line in attempt_file.read_text().splitlines() if line.strip()]
                except (FileNotFoundError, json.JSONDecodeError):
                    return False
                valid = [attempt for attempt in attempts if attempt.get("kind") == "client_attempt" and
                         tuple_key(attempt) == reuse_key and attempt.get("pid") == second[2].pid and
                         attempt.get("attempt_qpc", 0) >= reuse_started]
                return bool(valid) and reuse_rejection_verified(packet_records, reuse_key,
                                                                 valid[-1]["attempt_qpc"], original_sequence)

            wait_clients([second], seconds=8, rejection=verified_reuse)
            pump()
            if not verified_reuse():
                raise RuntimeError("same full tuple reuse not observed and rejected; bind failure is not coverage")
        else:
            for iteration in range(args.iterations):
                for app in ["a", "b"]:
                    launch(app, iteration)
            wait_clients(pending_clients)
        for _ in range(30):
            pump()
            time.sleep(.01)
        summary["clients"] = [dict(app=app, exit_code=p.returncode) for app, _, p in pending_clients]
        if any(p.returncode != 0 for app, _, p in pending_clients if not (args.scenario == "reuse" and app == "b")):
            raise RuntimeError("one or more clients failed; trace retained")
        records = []
        for app, label, _ in pending_clients:
            if args.scenario == "reuse" and app == "b":
                continue
            client_records = JsonTail(args.out / (label + ".stdout.txt")).read()
            if not client_records or any(not valid_client_result(c, connect_only=bool(args.external_target)) for c in client_records):
                raise RuntimeError(f"{label} has no valid {'connection' if args.external_target else 'echo'} result")
            records.extend((app, c) for c in client_records)
        summary["timing"] = timing_summary(records, packet_records,
                                             ownership_observations, decision_records, frequency)
        summary["timing"]["anchor_uncertainty_ms"] = uncertainty * 1000 / frequency
        summary["timing"]["occurrence_semantics"] = "WFP occurrence or audit TimeCreated; not exact classifyFn execution time"
        client_keys = {tuple_key(client) for _, client in records}
        summary["source_target_complete_outbound_events"] = sum(tuple_key(event) in client_keys for event in ownership_observations)
        controls = [p for p in packet_records if p.get("kind") == "control" and p.get("accepted")]
        effective = [p for p in packet_records if p.get("kind") == "packet" and p.get("action") == "proxy"]
        negative = args.skip_all or args.delay_ms >= args.hold_ms
        for app, client in records:
            key = tuple_key(client)
            if key is None:
                raise RuntimeError("client ground-truth tuple incomplete")
            matching = [c for c in controls if tuple_key(c) == key]
            proxied = [p for p in effective if tuple_key(p) == key]
            expected_proxy = args.mode == "redirect" and args.protocol == "tcp" and app == "a" and not negative
            if expected_proxy:
                if not any(c.get("action") == "proxy" for c in matching) or not proxied:
                    raise RuntimeError(f"selected client {client['nonce']} did not receive effective native-authorized proxying")
            elif proxied or any(c.get("action") == "proxy" for c in matching):
                raise RuntimeError(f"unexpected proxying of {client['nonce']}")
            if not negative and not matching:
                raise NoOwnershipConfirmation(f"client {client['nonce']} lacked accepted native ownership control")
        expected_count = sum(app == "a" for app, _ in records) if args.mode == "redirect" and not negative and args.protocol == "tcp" else 0
        if bridge and bridge.successful_tunnels != expected_count:
            raise RuntimeError("transparent bridge tunnel count differs from selected client count")
        gateway_records = []
        gateway_path = args.out / "gateway.jsonl"
        for attempt in range(20):
            try:
                gateway_records = [json.loads(line) for line in gateway_path.read_text().splitlines() if line.strip()]
                if len(gateway_records) == expected_count:
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(.05)
        expected_line = f"CONNECT {manifest['target_ip']}:{manifest['target_port']} HTTP/1.1"
        if len(gateway_records) != expected_count or any(r.get("kind") != "gateway_connect" or r.get("request_line") != expected_line for r in gateway_records):
            raise RuntimeError("gateway CONNECT count or original destination differs from expected transparent tunnels")
        if collector_errors(packet_records):
            raise RuntimeError("packet component reported an error")
        if args.scenario == "retransmit" and not retransmissions_verified(packet_records):
            raise RuntimeError("injected SYN drop did not produce a same-generation same-sequence retransmission")
        if args.scenario == "reuse":
            if any(p.get("kind") == "packet" and tuple_key(p) == reuse_key and p.get("syn") and
                   p.get("recv_qpc", 0) >= reuse_started and p.get("action") == "proxy" for p in packet_records):
                raise RuntimeError("reused unconfirmed SYN was proxied")
            summary.update(reuse_tuple=list(reuse_key), reused_syn_rejected=True,
                           nonselected_client_disrupted=True,
                           rejection_semantics="Characterized conservative rejection; not normal application connectivity")
        summary.update(client_tuple_count=len(records), accepted_controls=len(controls), effective_proxy_packets=len(effective),
                       bridge_tunnels=bridge.successful_tunnels if bridge else 0)
        summary["gateway_connect_count"] = len(gateway_records)
        summary["status"] = "CHARACTERIZED_REUSE_REJECTION" if args.scenario == "reuse" else "PASS_RESTRICTED_CASE"
    except NoOwnershipConfirmation as error:
        missing_ownership = args.external_target and "lacked accepted native ownership control" in str(error)
        summary.update(status="NO_OWNERSHIP_CONFIRMATION" if missing_ownership else "FAIL", error=str(error))
    except Exception as error:
        summary.update(status="FAIL", error=str(error))
    finally:
        for name in ["packets.stop", "native.stop"]:
            (args.out / name).touch()
        forced = []
        for process in processes:
            if process.poll() is None and process not in ([fixture] if "fixture" in locals() else []):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    forced.append(process.pid)
        if forced:
            summary.update(status="FAIL", cleanup_forced_pids=forced)
        if forced or ("native" in locals() and native.poll() != 0):
            state = args.out / "bfe-state.json"
            if state.exists():
                try:
                    restore = subprocess.run([str(args.bin / "native-events.exe"), "--restore-state", str(state.resolve()),
                                              "--out", str((args.out / "restore.jsonl").resolve())],
                                             capture_output=True, text=True, timeout=10)
                    (args.out / "restore.stdout.txt").write_text(restore.stdout + restore.stderr, encoding="utf-8")
                    summary["fallback_restore_exit_code"] = restore.returncode
                except Exception as error:
                    summary["fallback_restore_error"] = str(error)
        try:
            summaries = [r for r in JsonTail(args.out / "native.jsonl").read() if r.get("kind") == "summary"]
            if summaries:
                summary["native_summary"] = summaries[-1]
        except Exception as error:
            summary["native_summary_read_error"] = str(error)
        if summary["status"] in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION"]:
            try:
                native_records = JsonTail(args.out / "native.jsonl").read()
                packet_records = JsonTail(args.out / "packets.jsonl").read()
                native_summary = [r for r in native_records if r.get("kind") == "summary"]
                packet_complete = [r for r in packet_records if r.get("kind") == "complete"]
                if not native_summary or not clean_native_summary(native_summary[-1]):
                    raise RuntimeError("native collector missing clean final summary or reported event loss")
                if not packet_complete or not packet_complete[-1].get("success"):
                    raise RuntimeError("packet collector did not complete successfully")
                if collector_errors(native_records + packet_records):
                    raise RuntimeError("collector reported an error")
                if native.returncode != 0 or packet_process.returncode != 0:
                    raise RuntimeError("collector exit code was nonzero")
                summary["native_summary"] = native_summary[-1]
            except Exception as error:
                summary.update(status="FAIL", error=str(error))
        status, error = native_evidence_status(summary["status"], args.source, summary.get("native_summary"))
        if error:
            summary.update(status=status, error=error)
        status, error = poll_evidence_status(summary["status"], summary.get("error"), args.wfp_api, summary.get("native_summary"))
        summary.update(status=status)
        if error:
            summary["error"] = error
        if bridge:
            bridge.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in logs:
            stream.close()
        private.cleanup()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))
    return 0 if summary["status"] in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION"] else 1


if __name__ == "__main__":
    sys.exit(main())
