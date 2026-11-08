import argparse
import csv
import ctypes
import ipaddress
import json
import math
import pathlib
import re
import subprocess
import sys
import tempfile
import time

import run as lab


STATUSES = ("NOT_COMPLETED", "PASS_SOCKET_OBSERVATION", "INCONCLUSIVE_SOCKET_PROBE", "FAIL_SOCKET_PROBE")
REASONS = ("complete_fresh_pid_and_native_reference", "client_evidence_invalid", "clock_invalid",
           "socket_collector_unclean", "native_reference_unclean", "native_reference_missing",
           "fresh_tuple_ambiguous", "socket_identity_conflict", "socket_or_packet_missing",
           "event_timing_invalid", "cleanup_failed", "runtime_failure", "probe_unavailable")
COUNT_KEYS = ("client_total", "client_success", "fresh_tuples", "native_reference_matches",
              "native_reference_missing", "native_reference_conflicts", "socket_connect_pid_matches",
              "socket_connect_missing", "socket_pid_mismatch_clients", "socket_identity_ambiguous_clients",
              "socket_stale_events", "socket_tuple_incomplete_events", "network_first_matches",
              "network_missing", "app_path_usable_clients", "app_path_missing_clients",
              "app_path_mismatch_clients", "app_process_reused_clients", "expected_creation_missing_clients",
              "observed_creation_missing_clients", "process_generation_verified_clients", "invalid_timing_clients")
SOCKET_COUNTS = ("errors", "queue_dropped", "output_errors", "socket_received", "socket_relevant",
                 "network_received", "network_relevant", "lookup_failures", "records_written")
NATIVE_COUNTS = ("errors", "queue_dropped", "wfp_count", "wfp_polls", "wfp_poll_errors", "wfp_enum_errors")
TIMING_BASES = ("socket_event", "socket_recv", "socket_app_ready")
TIMING_REFERENCES = ("network_capture", "network_recv")
DISTRIBUTIONS = tuple(f"{source}_minus_{reference}_ms" for source in TIMING_BASES for reference in TIMING_REFERENCES) + (
    "socket_recv_minus_event_ms", "socket_app_ready_minus_recv_ms", "native_occurrence_minus_network_capture_ms",
    "native_recv_minus_network_capture_ms")
FRACTIONS = tuple(f"{source}_before_{reference}" for source in TIMING_BASES for reference in TIMING_REFERENCES)


def socket_public_summary(summary):
    if not isinstance(summary, dict):
        summary = {}
    result = dict(status=summary.get("status") if summary.get("status") in STATUSES else "NOT_COMPLETED",
                  engine="socket-observation", capture_only=True, routing_authority=False,
                  packet_interception=False, driver_queue_loss_known=False, driver_queue_loss_observable=False,
                  network_reference="first_observed_initial_syn_or_udp")
    for key, choices in (("protocol", ("tcp", "udp")),
                         ("mode", ("short_sequential", "held_sequential", "short_burst", "held_burst")),
                         ("reason", REASONS)):
        if summary.get(key) in choices:
            result[key] = summary[key]

    def numbers(value, keys, integers=False):
        if not isinstance(value, dict):
            return {}
        return {key: value[key] for key in keys if type(value.get(key)) in ((int,) if integers else (int, float))
                and math.isfinite(value[key]) and (not integers or 0 <= value[key] <= 1_000_000_000)}

    result.update(numbers(summary, ("iterations", "concurrency", "client_hold_ms", "drain_ms"), True))
    result["counts"] = numbers(summary.get("counts"), COUNT_KEYS, True)
    for name, keys in (("socket_summary", SOCKET_COUNTS), ("native_summary", NATIVE_COUNTS)):
        value = summary.get(name)
        if not isinstance(value, dict):
            continue
        result[name] = numbers(value, keys, True)
        for key in ("success", "truncated", "wfp_enum_truncated"):
            if type(value.get(key)) is bool:
                result[name][key] = value[key]
    timing = summary.get("timing")
    if isinstance(timing, dict):
        result["timing"] = numbers(timing, ("anchor_uncertainty_ms",))
        for key in DISTRIBUTIONS:
            if isinstance(timing.get(key), dict):
                result["timing"][key] = numbers(timing[key], ("count", "min", "p50", "p95", "max"))
        for key in FRACTIONS:
            if isinstance(timing.get(key), dict):
                value = numbers(timing[key], ("count", "eligible"), True)
                fraction = timing[key].get("fraction")
                if type(fraction) in (int, float) and math.isfinite(fraction) and 0 <= fraction <= 1:
                    value["fraction"] = fraction
                result["timing"][key] = value
    return result


def client_plan(iterations, concurrency):
    if not 1 <= iterations <= 100 or concurrency not in (0, *range(2, 101)):
        raise ValueError("invalid client plan")
    return [("a" if i % 2 == 0 else "b", i // 2) for i in range(concurrency or iterations * 2)]


def fixture_port(manifest, protocol):
    port = manifest["udp_ports"][0] if protocol == "udp" else manifest["target_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid fixture port")
    return port


def normalized_path(value):
    if not isinstance(value, str):
        return ""
    value = value.replace("/", "\\").casefold()
    for prefix in ("\\\\?\\", "\\??\\"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def full_tuple(value):
    if not isinstance(value, dict):
        return None
    try:
        local, remote = ipaddress.ip_address(value["local_ip"]), ipaddress.ip_address(value["remote_ip"])
        if local.version != 4 or remote.version != 4 or local.is_unspecified or remote.is_unspecified:
            return None
        if any(type(value[key]) is not int or not 1 <= value[key] <= 65535 for key in ("local_port", "remote_port")):
            return None
        if type(value["protocol"]) is not int or value["protocol"] not in (6, 17):
            return None
        return str(local), value["local_port"], str(remote), value["remote_port"], value["protocol"]
    except (KeyError, ValueError, TypeError):
        return None


def positive(value):
    return type(value) is int and value > 0


def distribution(values):
    values = sorted(value for value in values if type(value) in (int, float) and math.isfinite(value))
    if not values:
        return dict(count=0)
    return dict(count=len(values), min=values[0], max=values[-1],
                p50=values[math.ceil(len(values) * .5) - 1], p95=values[math.ceil(len(values) * .95) - 1])


def evaluate_probe(clients, socket_records, native_records, app_paths, frequency,
                   anchor_filetime, anchor_qpc, clock_uncertainty, native_exit=0, probe_exit=0):
    result = dict(status="INCONCLUSIVE_SOCKET_PROBE", reason="socket_or_packet_missing",
                  routing_authority=False, capture_only=True, packet_interception=False,
                  driver_queue_loss_known=False, driver_queue_loss_observable=False,
                  network_reference="first_observed_initial_syn_or_udp", rows=[],
                  counts={key: 0 for key in COUNT_KEYS})
    counts = result["counts"]
    counts["client_total"] = len(clients)

    def finish(status, reason):
        result.update(status=status, reason=reason)
        return result

    if (not all(positive(value) for value in (frequency, anchor_filetime, anchor_qpc))
            or type(clock_uncertainty) is not int or clock_uncertainty < 0):
        return finish("FAIL_SOCKET_PROBE", "clock_invalid")
    natives = [r for r in native_records if r.get("kind") == "summary"]
    native = natives[0] if len(natives) == 1 else None
    result["native_summary"] = native
    if (native_exit != 0 or not native or native.get("wfp_api") != "poll"
            or not positive(native.get("wfp_polls"))
            or any(native.get(key) != 0 for key in ("errors", "queue_dropped", "wfp_poll_errors", "wfp_enum_errors"))
            or native.get("wfp_enum_truncated") is not False
            or any(r.get("kind") in ("error", "wfp_poll_error", "wfp_enum_error") for r in native_records)):
        return finish("FAIL_SOCKET_PROBE", "native_reference_unclean")
    summaries = [r for r in socket_records if r.get("kind") == "summary" and r.get("source") == "socket_probe"]
    ready = [r for r in socket_records if r.get("kind") == "ready" and r.get("source") == "socket_probe"]
    socket_summary = summaries[0] if len(summaries) == 1 else None
    result["socket_summary"] = socket_summary
    if (probe_exit != 0 or not socket_summary or socket_summary.get("success") is not True
            or any(socket_summary.get(key) != 0 for key in ("errors", "queue_dropped", "output_errors"))
            or socket_summary.get("truncated") is not False
            or socket_summary.get("capture_only") is not True or socket_summary.get("routing_authority") is not False
            or any(r.get("kind") == "error" for r in socket_records)):
        return finish("FAIL_SOCKET_PROBE", "socket_collector_unclean")
    if (len(ready) != 1 or ready[0].get("socket_ready") is not True or ready[0].get("network_ready") is not True
            or ready[0].get("capture_only") is not True or ready[0].get("routing_authority") is not False
            or ready[0].get("qpc_frequency") != frequency):
        return finish("INCONCLUSIVE_SOCKET_PROBE", "probe_unavailable")
    subjects = []
    pid_owners = {}
    for client in clients:
        attempts = [a for a in client.get("attempts", []) if a.get("kind") == "client_attempt"]
        replies = [r for r in client.get("results", []) if r.get("kind") == "client"]
        if not client.get("app") in app_paths or not positive(client.get("pid")) or client.get("returncode") != 0:
            return finish("FAIL_SOCKET_PROBE", "client_evidence_invalid")
        if len(attempts) != 1 or len(replies) != 1:
            return finish("FAIL_SOCKET_PROBE", "client_evidence_invalid")
        attempt, reply = attempts[0], replies[0]
        key = full_tuple(attempt)
        begin, end = attempt.get("attempt_qpc"), reply.get("done_qpc")
        echo, hold_end = reply.get("echo_qpc"), reply.get("hold_end_qpc")
        if (not key or full_tuple(reply) != key or reply.get("status") != "echo_ok"
                or attempt.get("pid") != client["pid"] or reply.get("pid") != client["pid"]
                or not client.get("nonce") or attempt.get("nonce") != client["nonce"] or reply.get("nonce") != client["nonce"]
                or not all(positive(value) for value in (begin, end, echo, hold_end))
                or not begin <= echo <= hold_end <= end or reply.get("start_qpc") != begin
                or reply.get("hold_open_ms") != client.get("expected_hold_ms", 0)):
            return finish("FAIL_SOCKET_PROBE", "client_evidence_invalid")
        counts["client_success"] += 1
        subjects.append((client, key, begin, end))
        pid_owners.setdefault(client["pid"], []).append(client)
    counts["fresh_tuples"] = len({subject[1] for subject in subjects})
    if not subjects:
        return finish("FAIL_SOCKET_PROBE", "client_evidence_invalid")
    if counts["fresh_tuples"] != len(subjects):
        return finish("INCONCLUSIVE_SOCKET_PROBE", "fresh_tuple_ambiguous")
    socket_events = [r for r in socket_records if r.get("kind") == "socket_event" and r.get("event_name") == "connect"]
    counts["socket_tuple_incomplete_events"] = sum(full_tuple(r) is None for r in socket_events)
    metrics = {key: [] for key in DISTRIBUTIONS}
    comparisons = {key: [] for key in FRACTIONS}
    for client, key, begin, end in subjects:
        paths = app_paths[client["app"]]
        expected_creation = client.get("process_creation_filetime")
        counts["expected_creation_missing_clients"] += not positive(expected_creation)
        row = dict(app=client["app"], pid=client["pid"], tuple=list(key), nonce=client["nonce"],
                   attempt_qpc=begin, done_qpc=end, expected_dos_path=paths["dos"], expected_native_path=paths["native"])
        matching = [r for r in socket_events if full_tuple(r) == key]
        fresh = [r for r in matching if positive(r.get("event_qpc")) and begin <= r["event_qpc"] <= end]
        counts["socket_stale_events"] += len(matching) - len(fresh)
        wrong_pid = any(r.get("pid") != client["pid"] for r in fresh)
        counts["socket_pid_mismatch_clients"] += wrong_pid
        connected = [r for r in fresh if r.get("pid") == client["pid"]]
        valid_times = [r for r in connected if positive(r.get("recv_qpc")) and r["recv_qpc"] >= r["event_qpc"]]
        bad_timing = len(valid_times) != len(connected)
        counts["socket_connect_pid_matches"] += bool(valid_times)
        counts["socket_connect_missing"] += not valid_times
        ambiguous = wrong_pid
        reused = False
        generation_verified = False
        usable_paths = []
        for event in valid_times:
            successful_lookup = (event.get("identity_valid") is True and event.get("app_path_status") == "ok"
                                 and event.get("lookup_error") == 0 and bool(event.get("app_path")))
            if successful_lookup and (not positive(event.get("app_ready_qpc"))
                                      or event["app_ready_qpc"] < event["recv_qpc"]):
                bad_timing = True
            observed_creation = event.get("process_creation_filetime")
            if positive(observed_creation):
                created_ticks = anchor_qpc * 10_000_000 + (observed_creation - anchor_filetime) * frequency
                if (created_ticks > (event["event_qpc"] + clock_uncertainty) * 10_000_000
                        or positive(expected_creation) and observed_creation != expected_creation):
                    reused = True
            if event.get("app_path_status") == "pid_reused":
                reused = True
            verified = positive(expected_creation) and observed_creation == expected_creation and not reused
            generation_verified |= verified
            if (verified and event.get("identity_valid") is True and event.get("app_path_status") == "ok"
                    and event.get("lookup_error") == 0 and event.get("app_path")
                    and positive(event.get("app_ready_qpc")) and event["app_ready_qpc"] >= event["recv_qpc"]):
                usable_paths.append(event)
        ambiguous |= reused or len(pid_owners[client["pid"]]) > 1 and not generation_verified
        path_mismatch = any(normalized_path(event["app_path"]) != normalized_path(paths["dos"]) for event in usable_paths)
        ambiguous |= path_mismatch
        counts["app_process_reused_clients"] += reused
        counts["socket_identity_ambiguous_clients"] += ambiguous
        counts["process_generation_verified_clients"] += generation_verified and not reused
        counts["observed_creation_missing_clients"] += bool(valid_times) and not any(
            positive(event.get("process_creation_filetime")) for event in valid_times)
        path_ready = min(usable_paths, key=lambda event: event["app_ready_qpc"]) if usable_paths and not ambiguous else None
        counts["app_path_mismatch_clients"] += path_mismatch
        counts["app_path_usable_clients"] += path_ready is not None
        counts["app_path_missing_clients"] += path_ready is None
        packets = [r for r in socket_records if r.get("kind") == "packet" and full_tuple(r) == key
                   and r.get("outbound") is True and not r.get("ipv6")
                   and positive(r.get("capture_qpc")) and begin <= r["capture_qpc"] <= end
                   and (key[-1] == 17 or r.get("tcp_syn") in (True, 1) and r.get("tcp_ack") in (False, 0))]
        packet = min(packets, key=lambda event: event["capture_qpc"]) if packets else None
        if any(not positive(event.get("recv_qpc")) or event["recv_qpc"] < event["capture_qpc"] for event in packets):
            bad_timing = True
            packet = None
        first_network_recv = min(event["recv_qpc"] for event in packets) if packet else None
        counts["network_first_matches"] += packet is not None
        counts["network_missing"] += packet is None
        counts["invalid_timing_clients"] += bad_timing
        native_events = []
        for event in native_records:
            if (event.get("kind") != "wfp" or full_tuple(event) != key or event.get("complete") is not True
                    or event.get("direction") != "outbound" or event.get("layer_id") != 48
                    or not event.get("app_path") or not positive(event.get("event_filetime"))
                    or not positive(event.get("recv_qpc"))):
                continue
            occurrence = anchor_qpc * 10_000_000 + (event["event_filetime"] - anchor_filetime) * frequency
            if (begin - clock_uncertainty) * 10_000_000 <= occurrence <= (end + clock_uncertainty) * 10_000_000:
                native_events.append((event, occurrence / 10_000_000))
        native_conflict = any(normalized_path(event["app_path"]) != normalized_path(paths["native"])
                              for event, _ in native_events)
        references = [(event, occurred) for event, occurred in native_events
                      if normalized_path(event["app_path"]) == normalized_path(paths["native"])]
        counts["native_reference_conflicts"] += native_conflict
        counts["native_reference_matches"] += bool(references) and not native_conflict
        counts["native_reference_missing"] += not references or native_conflict
        first = min(valid_times, key=lambda event: event["event_qpc"]) if valid_times else None
        if first:
            row["socket_event"] = first
        if packet:
            row["first_observed_network_packet"] = packet
            row["first_observed_network_recv_qpc"] = first_network_recv
        row.update(native_reference=bool(references) and not native_conflict, path_usable=path_ready is not None,
                   generation_verified=bool(generation_verified), identity_ambiguous=bool(ambiguous))
        result["rows"].append(row)
        if not first or not packet or ambiguous or bad_timing:
            continue
        clocks = dict(socket_event=first["event_qpc"], socket_recv=min(event["recv_qpc"] for event in valid_times))
        if path_ready:
            clocks["socket_app_ready"] = path_ready["app_ready_qpc"]
            metrics["socket_app_ready_minus_recv_ms"].append((path_ready["app_ready_qpc"] - path_ready["recv_qpc"]) * 1000 / frequency)
        metrics["socket_recv_minus_event_ms"].append((first["recv_qpc"] - first["event_qpc"]) * 1000 / frequency)
        for source, value in clocks.items():
            for reference, reference_qpc in (("network_capture", packet["capture_qpc"]), ("network_recv", first_network_recv)):
                metrics[f"{source}_minus_{reference}_ms"].append((value - reference_qpc) * 1000 / frequency)
                comparisons[f"{source}_before_{reference}"].append(value < reference_qpc)
        if references:
            event, occurred = min(references, key=lambda entry: entry[0]["recv_qpc"])
            metrics["native_occurrence_minus_network_capture_ms"].append((occurred - packet["capture_qpc"]) * 1000 / frequency)
            metrics["native_recv_minus_network_capture_ms"].append((event["recv_qpc"] - packet["capture_qpc"]) * 1000 / frequency)
    result["timing"] = {key: distribution(values) for key, values in metrics.items()}
    result["timing"].update({key: dict(count=sum(values), eligible=len(values), fraction=sum(values) / len(values) if values else None)
                             for key, values in comparisons.items()})
    result["timing"]["anchor_uncertainty_ms"] = clock_uncertainty * 1000 / frequency
    if counts["invalid_timing_clients"]:
        return finish("INCONCLUSIVE_SOCKET_PROBE", "event_timing_invalid")
    if counts["socket_identity_ambiguous_clients"] or counts["native_reference_conflicts"]:
        return finish("INCONCLUSIVE_SOCKET_PROBE", "socket_identity_conflict")
    if counts["native_reference_missing"]:
        return finish("INCONCLUSIVE_SOCKET_PROBE", "native_reference_missing")
    if counts["socket_connect_missing"] or counts["network_missing"]:
        return finish("INCONCLUSIVE_SOCKET_PROBE", "socket_or_packet_missing")
    return finish("PASS_SOCKET_OBSERVATION", "complete_fresh_pid_and_native_reference")


def restrict_directory(path):
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, timeout=10, check=True)
    fields = next(csv.reader(identity.stdout.splitlines()))
    if len(fields) != 2 or not re.fullmatch(r"S-1-\d+(?:-\d+)+", fields[1]):
        raise RuntimeError("cannot determine private directory principal")
    acl = subprocess.run(["icacls.exe", str(path), "/inheritance:r", "/grant:r",
                          f"*{fields[1]}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                         capture_output=True, text=True, timeout=10)
    if acl.returncode:
        raise RuntimeError("cannot restrict private directory")


def process_creation_filetime(process):
    created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
    handle = ctypes.c_void_p(int(process._handle))
    if not ctypes.windll.kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                                ctypes.byref(kernel), ctypes.byref(user)):
        return None
    return created.value


def json_records(path, client_stdout=False):
    path = pathlib.Path(path)
    if not path.exists():
        return []
    if path.stat().st_size > 64 * 1024 * 1024:
        raise RuntimeError("local evidence byte limit")
    records = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip() or client_stdout and not line.lstrip().startswith("{"):
            continue
        record = json.loads(line)
        if not isinstance(record, dict) or len(records) >= 65536:
            raise RuntimeError("local evidence record limit")
        records.append(record)
    return records


def stop_collectors(native, socket, bin_dir, out_dir):
    report = dict(cleanup_forced_pids=[])
    for name in ("native.stop", "socket.stop"):
        (out_dir / name).touch()
    if socket is not None and socket.poll() is None:
        try:
            socket.wait(timeout=10)
        except subprocess.TimeoutExpired:
            report["cleanup_forced_pids"].append(socket.pid)
            socket.terminate()
            try:
                socket.wait(timeout=5)
            except subprocess.TimeoutExpired:
                socket.kill()
                socket.wait(timeout=5)
    native_report = lab.stop_inproc_collectors(native, None, bin_dir, out_dir)
    report["cleanup_forced_pids"].extend(native_report.pop("cleanup_forced_pids"))
    report.update(native_report)
    return report


def run_probe(args):
    args.out.mkdir(parents=True, exist_ok=True)
    restrict_directory(args.out)
    args.bin = args.bin.resolve()
    if args.private_dir:
        args.private_dir.mkdir(parents=True, exist_ok=True)
    private = tempfile.TemporaryDirectory(prefix="gateinto-socket-private-", dir=args.private_dir)
    restrict_directory(pathlib.Path(private.name))
    processes, streams, clients = [], [], []
    native = socket = fixture = None
    cleanup = None
    mode = ("held" if args.client_hold_ms else "short") + ("_burst" if args.concurrency else "_sequential")
    summary = dict(status="NOT_COMPLETED", protocol=args.protocol, mode=mode, iterations=args.iterations,
                   concurrency=args.concurrency, client_hold_ms=args.client_hold_ms, drain_ms=args.drain_ms,
                   capture_only=True, routing_authority=False, packet_interception=False,
                   driver_queue_loss_known=False, driver_queue_loss_observable=False)

    def start(command, name):
        stream = (args.out / (name + ".stdout.txt")).open("w", encoding="utf-8")
        streams.append(stream)
        process = subprocess.Popen([str(value) for value in command], stdout=stream, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        processes.append(process)
        return process

    def alive(process):
        if process.poll() is not None:
            raise RuntimeError("observation process exited early")

    def ready(process, path, source=None):
        tail = lab.JsonTail(path)
        deadline = time.monotonic() + 12
        while True:
            for record in tail.read():
                if record.get("kind") == "ready" and (source is None or record.get("source") == source):
                    return record
            alive(process)
            if time.monotonic() >= deadline:
                raise TimeoutError("observation readiness timeout")
            time.sleep(.01)

    try:
        manifest_path = pathlib.Path(private.name) / "manifest.json"
        fixture = start([args.fixture.resolve(), "--manifest", manifest_path.resolve(), "--out", args.out.resolve(),
                         "--seconds", args.seconds + 60, "--bind-ip", "127.0.0.1"], "fixture")
        deadline = time.monotonic() + 15
        while True:
            alive(fixture)
            try:
                manifest = json.loads(manifest_path.read_text())
                break
            except (FileNotFoundError, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("private fixture readiness timeout")
                time.sleep(.02)
        manifest_path.chmod(0o600)
        paths = {app: dict(dos=str((args.bin / f"app-{app}.exe").resolve()),
                           native=lab.native_path(args.bin / f"app-{app}.exe")) for app in ("a", "b")}
        native = start(lab.native_command(args.bin, args.out, args.seconds + 30, "poll"), "native")
        summary["native_ready"] = ready(native, args.out / "native.jsonl")
        port = fixture_port(manifest, args.protocol)
        socket = start([args.bin / "socket-events.exe", "--target", manifest["target_ip"], "--port", port,
                        "--protocol", args.protocol, "--out", (args.out / "socket.jsonl").resolve(),
                        "--stop-file", (args.out / "socket.stop").resolve(), "--seconds", args.seconds + 30], "socket")
        summary["socket_ready"] = ready(socket, args.out / "socket.jsonl", "socket_probe")
        frequency, anchor_filetime, anchor_qpc, uncertainty = lab.windows_clock()
        summary.update(qpc_frequency=frequency, anchor_filetime=anchor_filetime,
                       anchor_qpc=anchor_qpc, clock_uncertainty_ticks=uncertainty)
        deadline = time.monotonic() + args.seconds

        def wait_client(client):
            while client["process"].poll() is None:
                alive(native)
                alive(socket)
                alive(fixture)
                if time.monotonic() >= deadline:
                    raise TimeoutError("client observation timeout")
                time.sleep(.01)

        for app, iteration in client_plan(args.iterations, args.concurrency):
            alive(native)
            alive(socket)
            label = f"client-{app}-{iteration}"
            nonce = f"socket-{app}-{args.protocol}-{iteration}"
            attempt_file = args.out / (label + ".attempt.jsonl")
            launched = lab.qpc()
            process = start([args.bin / f"app-{app}.exe", "--target", manifest["target_ip"], "--port", port,
                             "--protocol", args.protocol, "--nonce", nonce, "--attempt-out", attempt_file.resolve(),
                             "--hold-open-ms", args.client_hold_ms], label)
            client = dict(app=app, nonce=nonce, pid=process.pid, process_creation_filetime=process_creation_filetime(process),
                          expected_hold_ms=args.client_hold_ms, launched_qpc=launched, process=process,
                          attempt_file=attempt_file, stdout_file=args.out / (label + ".stdout.txt"))
            clients.append(client)
            if not args.concurrency:
                wait_client(client)
        for client in clients:
            wait_client(client)
        drain_until = time.monotonic() + args.drain_ms / 1000
        while time.monotonic() < drain_until:
            alive(native)
            alive(socket)
            time.sleep(min(.02, max(0, drain_until - time.monotonic())))
        cleanup = stop_collectors(native, socket, args.bin, args.out)
        evidence = [dict(app=client["app"], nonce=client["nonce"], pid=client["pid"],
                         process_creation_filetime=client["process_creation_filetime"],
                         expected_hold_ms=client["expected_hold_ms"], launched_qpc=client["launched_qpc"],
                         returncode=client["process"].returncode,
                         attempts=json_records(client["attempt_file"]),
                         results=json_records(client["stdout_file"], client_stdout=True)) for client in clients]
        summary["clients"] = evidence
        summary.update(evaluate_probe(evidence, json_records(args.out / "socket.jsonl"),
            json_records(args.out / "native.jsonl"), paths, frequency, anchor_filetime,
            anchor_qpc, uncertainty, native.returncode, socket.returncode))
    except Exception as error:
        summary.update(status="FAIL_SOCKET_PROBE", reason="runtime_failure", error=str(error))
    finally:
        for client in clients:
            if client["process"].poll() is None:
                client["process"].terminate()
        try:
            if cleanup is None:
                cleanup = stop_collectors(native, socket, args.bin, args.out)
            summary["cleanup"] = cleanup
            if (cleanup["cleanup_forced_pids"] or cleanup.get("fallback_restore_exit_code", 0)
                    or cleanup.get("fallback_restore_error")):
                summary.update(status="FAIL_SOCKET_PROBE", reason="cleanup_failed")
        except Exception as error:
            summary.update(status="FAIL_SOCKET_PROBE", reason="cleanup_failed", cleanup_error=str(error))
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for stream in streams:
            stream.close()
        private.cleanup()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        public = socket_public_summary(summary)
        (args.out / "public-summary.json").write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(public))
    return 0 if public["status"] == "PASS_SOCKET_OBSERVATION" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--private-dir", type=pathlib.Path)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=0)
    parser.add_argument("--client-hold-ms", type=int, choices=(0, 500), default=0)
    parser.add_argument("--seconds", type=int, default=35)
    parser.add_argument("--drain-ms", type=int, default=1000)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows is required; evaluator tests are portable")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("output directory must be empty")
    if not 15 <= args.seconds <= 300 or not 0 <= args.drain_ms <= 5000:
        parser.error("require seconds 15..300 and drain-ms 0..5000")
    try:
        client_plan(args.iterations, args.concurrency)
    except ValueError:
        parser.error("require iterations 1..100 and concurrency 0 or 2..100")
    try:
        return run_probe(args)
    except Exception:
        print(json.dumps(socket_public_summary(dict(status="FAIL_SOCKET_PROBE", reason="runtime_failure",
                                                    protocol=args.protocol))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
