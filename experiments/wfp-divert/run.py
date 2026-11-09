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


VALIDATION_STAGES = ("startup", "clients", "collectors", "client_evidence", "client_attestation",
                     "client_latency", "native_reference", "gateway", "engine_complete",
                     "engine_evaluation", "ale_shadow", "cleanup", "complete")
REFERENCE_MISSING_CAUSES = ("collector_unclean", "invalid_clock", "invalid_client", "no_polled_tuple",
                            "no_original_app", "incomplete_original_app", "wrong_direction", "wrong_layer",
                            "invalid_event_time", "before_attempt", "after_capture", "outside_window",
                            "fresh_app_conflict")
REFERENCE_POLL_INTERVAL_MS = 100
REFERENCE_DIAGNOSTIC_COUNTS = ("original_app_outbound_layer48_clients", "engine_event_clients",
                              "engine_event_seen_in_poll_clients", "engine_event_missing_from_poll_clients",
                              "engine_event_seen_in_final_enum_clients", "fresh_final_enum_only_clients")
SOCKET_DIAGNOSTIC_LABELS = dict(
    connect_changes=("new", "exact_duplicate", "timestamp_changed", "pid_changed", "endpoint_changed", "tuple_changed", "invalid"),
    identity_failures=("process_open_access_denied", "process_open_other", "process_times", "creation_guard", "image_name", "utf8"),
    close_context=("unknown_endpoint", "original_endpoint", "other_known_endpoint", "remote_unspecified", "quarantined_endpoint"),
    post_capture_connect=("total", "same_endpoint", "different_endpoint", "same_pid", "different_pid",
        "parent_matches", "parent_other", "parent_missing", "system_process", "other_process",
        "identity_available", "identity_unavailable", "identity_not_requested", "injection_known", "injection_unknown",
        "event_after_injection_start", "event_after_injection_success", "receive_after_injection_success"))
SOCKET_GUARD_LABELS = ("missing", "matched", "closed", "ambiguous", "stale", "invalid", "poisoned", "malformed", "drop_state")


def public_summary(summary):
    if not isinstance(summary, dict):
        summary = {}
    enums = dict(
        status=("NOT_COMPLETED", "FAIL", "NO_OWNERSHIP_CONFIRMATION", "PASS_RESTRICTED_CASE",
                "CHARACTERIZED_REUSE_REJECTION", "PASS_BLOCKED_EVENT_CONTROL",
                "INCONCLUSIVE_ALE_ENDPOINT_PROBE", "INCONCLUSIVE_ENDPOINT_CONTROL",
                "INCONCLUSIVE_NO_NATIVE_EVENTS", "INCONCLUSIVE_NO_USABLE_NATIVE_EVENTS",
                "INCONCLUSIVE_NO_NATIVE_REFERENCE", "FAIL_CONTROL_CLIENT", "FAIL_ENDPOINT_CONTROL",
                "OBSERVED_WHILE_HELD", "OBSERVED_ALE_ORIGINAL_APP", "CHARACTERIZED_ALE_APP_MISMATCH"),
        source=("wfp", "security5156"), mode=("hold", "redirect"), protocol=("tcp", "udp"),
        engine=("external", "inproc", "endpoint-control"), lookup_mode=("inline", "async"),
        enum_scope=("legacy", "destination"), filter_cache=("on", "off"), ownership_source=("wfp", "socket"),
        wfp_api=("subscribe2", "subscribe3", "subscribe4", "poll"),
        scenario=("baseline", "retransmit", "reuse"),
        topology=("single-host-local", "external-connect-only"),
        validation_stage=VALIDATION_STAGES, failure_stage=VALIDATION_STAGES)
    result = {key: summary[key] for key, choices in enums.items()
              if key in summary and summary[key] in choices}
    result.setdefault("status", "UNKNOWN")

    def numeric_fields(value, keys, integers=False):
        if not isinstance(value, dict):
            return {}
        return {key: value[key] for key in keys if key in value and
                type(value[key]) in ((int,) if integers else (int, float)) and
                math.isfinite(value[key])}

    count_keys = ("decisions", "selected_confirmed", "redirected", "client_tuple_count",
                  "accepted_controls", "effective_proxy_packets", "bridge_tunnels", "gateway_connect_count",
                  "source_target_complete_outbound_events", "matching_native_drops", "client_exit",
                  "restore_exit", "fallback_restore_exit_code", "concurrency", "window_before_ms",
                  "window_after_ms", "client_hold_ms", "benchmark_round", "delay_ms",
                  "selected_tuple_count", "quic_dropped_clients", "barrier_client_count")
    result.update(numeric_fields(summary, count_keys, integers=True))
    for key in ("controlled_echo", "reused_syn_rejected", "nonselected_client_disrupted", "restore_failed",
                "quic", "expect_leak", "cleanup_failed", "routing_authority", "packet_interception",
                "native_reference", "sequential", "synchronized_start"):
        if type(summary.get(key)) is bool:
            result[key] = summary[key]
    if isinstance(summary.get("clients"), list):
        clients = summary["clients"]
        success = sum(isinstance(client, dict) and type(client.get("exit_code", client.get("returncode"))) is int and
                      client.get("exit_code", client.get("returncode")) == 0 for client in clients)
        result["clients"] = dict(total=len(clients), success=success, failure=len(clients) - success)
    elif isinstance(summary.get("clients"), dict):
        result["clients"] = numeric_fields(summary["clients"], ("total", "success", "failure"), integers=True)
    if isinstance(summary.get("native_summary"), dict):
        result["native_summary"] = numeric_fields(summary["native_summary"],
            ("wfp_count", "wfp_raw_count", "wfp_callback_count", "wfp_drop_count", "wfp_other_count",
             "security5156_count", "queue_dropped", "errors", "wfp_polls", "wfp_poll_errors",
             "wfp_enum_errors", "wfp_enum_count", "wfp_enum5_count", "wfp_enum5_errors",
             "wfp_enum_total", "wfp_enum_emitted", "wfp_poll_missed", "wfp_poll_interval_ms",
             "wfp_poll_overlap_ms"), integers=True)
        types = summary["native_summary"].get("wfp_type_counts")
        api = summary["native_summary"].get("wfp_api")
        if api in enums["wfp_api"]:
            result["native_summary"]["wfp_api"] = api
        if isinstance(types, dict):
            result["native_summary"]["wfp_type_counts"] = {
                str(int(key)): value for key, value in types.items()
                if isinstance(key, str) and key.isascii() and key.isdecimal() and len(key) <= 3
                and 0 <= int(key) <= 255 and type(value) is int}
    if isinstance(summary.get("timing"), dict):
        timing = summary["timing"]
        projected = numeric_fields(timing, ("matched_client_tuples", "unmatched_client_tuples",
                                            "native_after_packet_capture", "native_after_packet_receive"), integers=True)
        projected.update(numeric_fields(timing, ("anchor_uncertainty_ms",)))
        for key in ("notification_minus_capture_ms", "decision_minus_capture_ms"):
            if isinstance(timing.get(key), dict):
                projected[key] = numeric_fields(timing[key], ("count", "min", "max", "p50", "p95"))
        result["timing"] = projected
    def booleans(value, keys):
        return {key: value[key] for key in keys if type(value.get(key)) is bool}

    def phases(value, keys):
        return {key: numeric_fields(value[key], ("calls", "total_ms", "max_ms"))
                for key in keys if isinstance(value.get(key), dict)}

    if isinstance(summary.get("engine_summary"), dict):
        engine = summary["engine_summary"]
        projected = numeric_fields(engine, (
            "lookup_calls", "lookup_errors", "lookup_query_count", "lookup_query_completed",
            "lookup_query_cancelled", "lookup_query_backpressure", "lookup_query_max_subjects",
            "lookup_stale_subjects", "lookup_incomplete_results", "lookup_query_cpu_samples",
            "lookup_query_cpu_errors", "lookup_query_cpu_error_code", "lookup_returned_events",
            "filter_cache_hits", "filter_cache_misses", "filter_cache_rejections", "bfe_errors",
            "decided_proxy", "decided_direct", "unattributed", "leaked", "rst_count", "quic_drops",
            "window_before_ms", "window_after_ms", "delay_ms",
            "socket_received", "socket_connect_received", "socket_close_received", "socket_identity_ready",
            "socket_identity_missing", "socket_source_errors", "socket_queue_overflow", "socket_history_overflow",
            "socket_output_errors", "socket_matches", "socket_rejected", "socket_ambiguous", "socket_closed",
            "socket_missing", "socket_reuse_rejected", "socket_history_entries",
            "socket_quarantined_connects", "socket_quarantined_pairs", "socket_quarantined_endpoints",
            "socket_quarantined_syn_rejections", "socket_identity_skipped_quarantine"), integers=True)
        projected.update(numeric_fields(engine, ("lookup_query_busy_ms", "lookup_query_cpu_ms",
                                                  "lookup_runtime_ms", "lookup_busy_share")))
        projected.update(booleans(engine, ("lookup_worker_error", "filter_cache", "lookup_query_cpu_valid",
                                           "nonselected_client_disrupted", "send_rst", "success",
                                           "socket_clean_shutdown", "driver_queue_loss_known")))
        for key in ("lookup_mode", "enum_scope", "ownership_source"):
            if engine.get(key) in enums[key]:
                projected[key] = engine[key]
        for key in ("first_packet_decision_latency_ms", "lookup_result_apply_ms", "lookup_calls_per_flow",
                    "lookup_duration_ms", "added_latency_held_ms", "added_latency_direct_ms", "added_latency_proxy_ms",
                    "socket_event_to_recv_ms", "socket_event_to_identity_ready_ms", "socket_identity_lookup_ms",
                    "socket_identity_ready_to_apply_ms"):
            if isinstance(engine.get(key), dict):
                projected[key] = numeric_fields(engine[key], ("count", "min", "max", "p50", "p95"))
        projected.update(phases(engine, ("lookup_create", "lookup_enum", "lookup_destroy", "lookup_process")))
        def count_map(value, labels):
            return {key: count for key, count in numeric_fields(value, labels, integers=True).items()
                    if 0 <= count <= 1_000_000_000}

        if isinstance(engine.get("socket_diagnostics"), dict):
            projected["socket_diagnostics"] = {key: count_map(engine["socket_diagnostics"][key], labels)
                for key, labels in SOCKET_DIAGNOSTIC_LABELS.items()
                if isinstance(engine["socket_diagnostics"].get(key), dict)}
        for key in ("socket_forward_guard_verdicts", "socket_reverse_guard_verdicts"):
            if isinstance(engine.get(key), dict):
                projected[key] = count_map(engine[key], SOCKET_GUARD_LABELS)
        filters = engine.get("enum_filter")
        allowed_filters = {"none", "time_window_only", "type", "type+protocol", "type+protocol+local_port",
                           "type+protocol+remote_port", "type+protocol+remote_port+local_port",
                           "type+protocol+remote_address", "type+protocol+remote_address+local_port",
                           "type+protocol+remote_address+remote_port",
                           "type+protocol+remote_address+remote_port+local_port"}
        if isinstance(filters, str) and all(value in allowed_filters for value in filters.split("|")):
            projected["enum_filter"] = filters
        if isinstance(engine.get("enum_condition_shapes"), list):
            projected["enum_condition_shapes"] = [numeric_fields(shape, ("mask", "count"), integers=True)
                                                   for shape in engine["enum_condition_shapes"] if isinstance(shape, dict)]
        result["engine_summary"] = projected
        result["engine_summary"]["first_packet_decision_population"] = "all_engine_flows_including_fixture"
    if isinstance(summary.get("client_latency"), dict):
        result["client_latency"] = dict(start_boundary="after_bind_before_connect_or_send")
        for group in ("selected", "direct"):
            value = summary["client_latency"].get(group)
            if not isinstance(value, dict):
                continue
            projected = numeric_fields(value, ("clients", "echo_matches", "reset_observed"), integers=True)
            for key in ("start_to_echo_ms", "start_to_done_ms"):
                if isinstance(value.get(key), dict):
                    projected[key] = numeric_fields(value[key], ("count", "min", "p50", "p95", "max"))
            result["client_latency"][group] = projected
    for name, fields in (("socket_attestation", ("client_total", "matched_clients", "pid_creation_matches",
                                                "deadline_checked_clients", "late_leak_clients")),
                         ("native_reference_audit", ("client_total", "matched_clients", "missing_clients",
                                                     "conflicting_clients", "poll_interval_ms", "drain_ms"))):
        value = summary.get(name)
        if isinstance(value, dict):
            projected = numeric_fields(value, fields, integers=True)
            projected.update(booleans(value, ("success",)))
            if isinstance(value.get("native_summary"), dict):
                projected["native_summary"] = public_summary(dict(native_summary=value["native_summary"]))["native_summary"]
            if name == "native_reference_audit":
                for key, fields in (("missing_causes", REFERENCE_MISSING_CAUSES),
                                    ("diagnostic_counts", REFERENCE_DIAGNOSTIC_COUNTS)):
                    if isinstance(value.get(key), dict):
                        projected[key] = numeric_fields(value[key], fields, integers=True)
                timing = value.get("missing_reference_timing")
                if isinstance(timing, dict):
                    projected["missing_reference_timing"] = numeric_fields(timing, ("anchor_uncertainty_ms",))
                    for key in ("nearest_original_minus_capture_ms", "nearest_original_minus_attempt_ms"):
                        if isinstance(timing.get(key), dict):
                            projected["missing_reference_timing"][key] = numeric_fields(
                                timing[key], ("count", "min", "p50", "p95", "max"))
            result[name] = projected
    if isinstance(summary.get("native_reference_cleanup"), dict):
        cleanup = summary["native_reference_cleanup"]
        forced = len(cleanup["cleanup_forced_pids"]) if isinstance(cleanup.get("cleanup_forced_pids"), list) else cleanup.get("forced_processes", 0)
        forced = forced if type(forced) is int and forced >= 0 else 0
        failed = bool(cleanup.get("fallback_restore_exit_code", 0) or cleanup.get("fallback_restore_error")
                      or cleanup.get("fallback_restore_failed"))
        result["native_reference_cleanup"] = dict(forced_processes=forced, fallback_restore_failed=failed,
                                                   success=forced == 0 and not failed)
    for name in ("endpoint_control", "ale_probe"):
        if not isinstance(summary.get(name), dict):
            continue
        control = summary[name]
        projected = numeric_fields(control, ("native_reference_matches", "endpoint_observed_clients",
            "original_app_matches", "system_app_clients", "shared_endpoint_groups", "observed_while_held"), integers=True)
        projected.update(booleans(control, ("routing_authority", "packet_interception")))
        if control.get("status") in enums["status"]:
            projected["status"] = control["status"]
        for key in ("native_summary", "ale_summary"):
            native = control.get(key)
            if not isinstance(native, dict):
                continue
            if native.get("source") == "ale_endpoint" or key == "ale_summary":
                counts = numeric_fields(native, ("queries", "complete_snapshots", "incomplete_snapshots",
                    "endpoint_records", "distinct_endpoints", "errors", "interval_ms"), integers=True)
                counts.update(booleans(native, ("available", "success", "truncated")))
                counts["source"] = "ale_endpoint"
                counts.update(phases(native, ("phase_create", "phase_enum", "phase_destroy", "phase_decode", "query")))
                projected[key] = counts
            else:
                projected[key] = public_summary(dict(native_summary=native))["native_summary"]
        result[name] = projected
    if isinstance(summary.get("ale_ready"), dict):
        ready = summary["ale_ready"]
        projected = {}
        abi = ready.get("abi")
        if isinstance(abi, dict):
            layout = numeric_fields(abi, ("pointer_bits", "expected_pointer_bits", "endpoint_properties_size",
                "endpoint_properties_alignment", "byte_blob_size"), integers=True)
            for key in ("architecture", "expected_architecture"):
                if abi.get(key) in ("x64", "x86", "arm64", "unknown"):
                    layout[key] = abi[key]
            for key, fields in (("endpoint_properties_offsets", ("endpointId", "ipVersion", "localV4Address",
                "localV6Address", "remoteV4Address", "remoteV6Address", "ipProtocol", "localPort", "remotePort",
                "localTokenModifiedId", "mmSaId", "qmSaId", "ipsecStatus", "flags", "appId")),
                ("byte_blob_offsets", ("size", "data"))):
                if isinstance(abi.get(key), dict):
                    layout[key] = numeric_fields(abi[key], fields, integers=True)
            projected["abi"] = layout
        if isinstance(ready.get("runtime_os"), dict):
            projected["runtime_os"] = numeric_fields(ready["runtime_os"], ("major", "minor", "build"), integers=True)
            projected["runtime_os"].update(booleans(ready["runtime_os"], ("available",)))
        result["ale_ready"] = projected
    purpose = "blocked-flow positive control, never an allow ownership source"
    if summary.get("purpose") == purpose:
        result["purpose"] = purpose
    if isinstance(summary.get("diagnostic_events"), list):
        diagnostics = []
        for event in summary["diagnostic_events"]:
            projected = numeric_fields(event, ("event_type", "flags", "protocol"), integers=True)
            for key in ("app_path_matches", "bound_port_matches"):
                if isinstance(event, dict) and type(event.get(key)) is bool:
                    projected[key] = event[key]
            if projected:
                diagnostics.append(projected)
        result["diagnostic_events"] = diagnostics
    if result["status"] == "NO_OWNERSHIP_CONFIRMATION":
        result["reason"] = "native_source_unconfirmed"
    elif (result["status"] in ("FAIL", "FAIL_ENDPOINT_CONTROL", "FAIL_CONTROL_CLIENT", "UNKNOWN", "NOT_COMPLETED")
            or summary.get("reason") == "inspect_local_records" or any(
                key in summary for key in ("error", "restore_error", "fallback_restore_error", "native_summary_read_error"))):
        result["reason"] = "inspect_local_records"
    return result


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


def native_command(bin_dir, out_dir, seconds, wfp_api, callback_drain_ms=0):
    return [bin_dir / "native-events.exe", "--seconds", seconds, "--out", (out_dir / "native.jsonl").resolve(),
            "--stop-file", (out_dir / "native.stop").resolve(), "--state-out", (out_dir / "bfe-state.json").resolve(),
            "--wfp-api", wfp_api, "--callback-drain-ms", callback_drain_ms]


def native_reference_command(bin_dir, out_dir, seconds):
    return native_command(bin_dir, out_dir / "native-reference", seconds, "poll") + ["--poll-interval-ms", REFERENCE_POLL_INTERVAL_MS]


def inproc_command(bin_dir, out_dir, manifest, selected_app, args):
    port = manifest["target_port"]
    command = [bin_dir / "inproc.exe", "--target", manifest["target_ip"], "--port", port,
               "--out", (out_dir / "packets.jsonl").resolve(),
               "--summary", (out_dir / "engine-summary.json").resolve(),
               "--state-out", (out_dir / "bfe-state.json").resolve(),
               "--stop-file", (out_dir / "inproc.stop").resolve(),
               "--selected-app", selected_app, "--mode", "hold" if args.protocol == "udp" or args.quic else args.mode,
               "--hold-ms", args.hold_ms, "--seconds", args.seconds,
               "--window-before-ms", args.window_before_ms, "--window-after-ms", args.window_after_ms,
               "--leak-ms", args.leak_ms, "--send-rst", 1 if args.send_rst else 0,
               "--delay-ms", args.delay_ms,
               "--lookup-mode", getattr(args, "lookup_mode", "inline"),
               "--filter-cache", getattr(args, "filter_cache", "on"),
               "--enum-scope", getattr(args, "enum_scope", "legacy"),
               "--ownership-source", getattr(args, "ownership_source", "wfp")]
    if args.protocol == "udp" or args.quic:
        command += ["--udp-port", manifest["udp_ports"][0]]
    if args.quic:
        command += ["--quic-port", manifest["udp_ports"][0]]
    return command


def inproc_client_plan(args, manifest):
    protocol = "udp" if args.quic else args.protocol
    port = manifest["udp_ports"][0] if protocol == "udp" else manifest["target_port"]
    apps = [("a" if index % 2 == 0 else "b", index) for index in range(args.concurrency)] \
        if args.concurrency else [(app, iteration) for iteration in range(getattr(args, "iterations", 3)) for app in ["a", "b"]]
    return [dict(app=app, iteration=iteration, protocol=protocol, port=port) for app, iteration in apps]


def ale_probe_command(bin_dir, out_dir, manifest, args):
    protocol = "udp" if args.quic else args.protocol
    port = manifest["udp_ports"][0] if protocol == "udp" else manifest["target_port"]
    return [bin_dir / "ale-endpoints.exe", "--target", manifest["target_ip"], "--port", port,
            "--protocol", protocol, "--out", (out_dir / "ale-endpoints.jsonl").resolve(),
            "--stop-file", (out_dir / "ale-endpoints.stop").resolve(), "--seconds", args.seconds,
            "--interval-ms", 5]


def ale_probe_report(clients, packets, records, app_paths, frequency, returncode):
    summaries = [r for r in records if r.get("kind") == "summary" and r.get("source") == "ale_endpoint"]
    native = summaries[-1] if summaries else None
    report = dict(status="INCONCLUSIVE_ALE_ENDPOINT_PROBE", routing_authority=False,
                  qualification="Shadow native WFP endpoint observations only; no socket-generation or routing guarantee",
                  native_summary=native, rows=[])
    if (not native or returncode != 0 or not native.get("available") or not native.get("success")
            or native.get("errors") or native.get("truncated") or frequency <= 0):
        report["reason"] = "probe unavailable, incomplete, failed, or missing a clean native summary"
        return report
    snapshots = {r["snapshot_id"]: r for r in records
                 if r.get("kind") == "ale_snapshot" and r.get("complete") and "snapshot_id" in r}
    endpoint_index = {}
    for entry in records:
        if entry.get("kind") == "ale_endpoint" and entry.get("snapshot_complete"):
            endpoint_index.setdefault((entry.get("snapshot_id"), tuple_key(entry)), []).append(entry)
    for client in clients:
        attempts = client.get("attempts", [])
        if len(attempts) != 1 or not tuple_key(attempts[0]):
            report["reason"] = "client attempted tuple missing"
            return report
        key = tuple_key(attempts[0])
        decisions = [p for p in packets if p.get("kind") == "decision" and tuple_key(p) == key]
        if not decisions:
            report["reason"] = "packet decision/capture missing"
            return report
        decision = min(decisions, key=lambda p: p.get("qpc", 0))
        capture = decision.get("capture_qpc", 0)
        candidates = []
        ambiguous = False
        for snapshot_id, snapshot in snapshots.items():
            began, observed = snapshot.get("query_start_qpc", 0), snapshot.get("observed_qpc", 0)
            if capture <= 0 or began < capture or observed < began:
                continue
            matches = [e for e in endpoint_index.get((snapshot_id, key), [])
                       if e.get("query_start_qpc") == began and e.get("observed_qpc") == observed
                       and e.get("endpoint_id", 0) > 0 and e.get("app_path")]
            identities = {(e["endpoint_id"], normalized_path(e["app_path"])) for e in matches}
            if identities and (len(identities) != 1 or any(
                    path != normalized_path(app_paths[client["app"]]) for _, path in identities)):
                ambiguous = True
            elif matches:
                candidates.append(min(matches, key=lambda e: e["observed_qpc"]))
        row = dict(app=client["app"], tuple=list(key), capture_qpc=capture,
                   decision_qpc=decision.get("qpc"), ambiguous=ambiguous,
                   observed_before_decision=False)
        if candidates and not ambiguous:
            first = min(candidates, key=lambda e: e["observed_qpc"])
            row.update(endpoint_id=first["endpoint_id"], snapshot_id=first["snapshot_id"],
                       app_path=first["app_path"], observed_qpc=first["observed_qpc"],
                       observation_minus_capture_ms=(first["observed_qpc"] - capture) * 1000 / frequency,
                       observed_before_decision=first["observed_qpc"] < decision.get("qpc", 0))
        report["rows"].append(row)
    report["observed_while_held"] = sum(row["observed_before_decision"] for row in report["rows"])
    if report["rows"] and report["observed_while_held"] == len(report["rows"]):
        report["status"] = "OBSERVED_WHILE_HELD"
    else:
        report["reason"] = "not every client had a unique native endpoint snapshot observed while its packet was held"
    return report


def ale_control_report(clients, native_records, ale_records, app_paths, frequency,
                       native_exit, probe_exit, clock_uncertainty=0):
    report = dict(status="INCONCLUSIVE_ENDPOINT_CONTROL", routing_authority=False, packet_interception=False,
                  qualification="Live post-echo native-source comparison only; no packet-generation or admission guarantee",
                  native_reference_matches=0, endpoint_observed_clients=0, original_app_matches=0,
                  system_app_clients=0, shared_endpoint_groups=0, shared_endpoint_ids=[], rows=[])
    native_summaries = [r for r in native_records if r.get("kind") == "summary"]
    native = native_summaries[-1] if native_summaries else None
    report["native_summary"] = native
    if (native_exit != 0 or not clean_native_summary(native) or native.get("wfp_api") != "poll"
            or not native.get("wfp_polls") or native.get("wfp_poll_errors")
            or native.get("wfp_enum_errors") or native.get("wfp_enum_truncated") or frequency <= 0):
        report.update(status="INCONCLUSIVE_NO_NATIVE_REFERENCE", reason="native poll reference was not clean")
        return report
    probe_summaries = [r for r in ale_records if r.get("kind") == "summary" and r.get("source") == "ale_endpoint"]
    probe = probe_summaries[-1] if probe_summaries else None
    report["ale_summary"] = probe
    if (probe_exit != 0 or not probe or not probe.get("available") or not probe.get("success")
            or probe.get("errors") or probe.get("truncated") or probe.get("incomplete_snapshots")):
        report["reason"] = "ALE probe was unavailable or incomplete"
        return report
    snapshots = {}
    for entry in ale_records:
        if entry.get("kind") != "ale_snapshot":
            continue
        snapshot_id = entry.get("snapshot_id", 0)
        if snapshot_id <= 0 or snapshot_id in snapshots:
            report["reason"] = "ALE snapshot identifiers were missing or repeated"
            return report
        snapshots[snapshot_id] = entry
    endpoint_index = {}
    for entry in ale_records:
        if entry.get("kind") == "ale_endpoint" and entry.get("snapshot_complete"):
            endpoint_index.setdefault(tuple_key(entry), []).append(entry)
    endpoint_tuples = {}
    seen_tuples = set()
    for client in clients:
        attempts = [a for a in client.get("attempts", []) if a.get("kind") == "client_attempt"
                    and a.get("nonce") == client.get("nonce")]
        results = [r for r in client.get("results", []) if r.get("kind") == "client"
                   and r.get("nonce") == client.get("nonce") and r.get("status") == "echo_ok"]
        if client.get("returncode") != 0 or len(attempts) != 1 or len(results) != 1:
            report.update(status="FAIL_CONTROL_CLIENT", reason="control client lacked a successful echo and attempted tuple")
            return report
        key = tuple_key(attempts[0])
        attempt = attempts[0].get("attempt_qpc", 0)
        echo, end = results[0].get("echo_qpc", 0), results[0].get("hold_end_qpc", 0)
        expected_protocol = 6 if client.get("protocol") == "tcp" else 17
        if (not key or key in seen_tuples or key[-1] != expected_protocol or tuple_key(results[0]) != key
                or not 0 < attempt <= echo < end <= results[0].get("done_qpc", 0)
                or results[0].get("hold_open_ms", 0) <= 0):
            report.update(status="FAIL_CONTROL_CLIENT", reason="control tuple, protocol or live hold interval was invalid")
            return report
        seen_tuples.add(key)
        expected = normalized_path(app_paths[client["app"]])
        references = [r for r in native_records if r.get("kind") == "wfp" and tuple_key(r) == key
                      and r.get("complete") and r.get("direction") == "outbound" and r.get("layer_id") == 48
                      and normalized_path(r.get("app_path", "")) == expected
                      and attempt - clock_uncertainty <= r.get("occurrence_qpc", -1) <= echo + clock_uncertainty
                      and attempt <= r.get("recv_qpc", 0) <= end]
        if references:
            report["native_reference_matches"] += 1
        observations = []
        for entry in endpoint_index.get(key, []):
            snapshot = snapshots.get(entry.get("snapshot_id"))
            if not snapshot or not snapshot.get("complete") or not entry.get("app_path") or entry.get("endpoint_id", 0) <= 0:
                continue
            began, observed = snapshot.get("query_start_qpc", 0), snapshot.get("observed_qpc", 0)
            if (entry.get("query_start_qpc") == began and entry.get("observed_qpc") == observed
                    and echo <= began <= observed <= end):
                observations.append(entry)
                endpoint_tuples.setdefault((entry["snapshot_id"], entry["endpoint_id"]), set()).add(key)
        paths = sorted({entry["app_path"] for entry in observations})
        matched = bool(paths) and {normalized_path(path) for path in paths} == {expected}
        report["endpoint_observed_clients"] += bool(observations)
        report["original_app_matches"] += matched
        report["system_app_clients"] += bool(paths) and all(normalized_path(path) == "system" for path in paths)
        report["rows"].append(dict(app=client["app"], tuple=list(key), attempt_qpc=attempt,
                                   echo_qpc=echo, hold_end_qpc=end, hold_elapsed_ms=(end - echo) * 1000 / frequency,
                                   expected_app_path=app_paths[client["app"]],
                                   native_reference=bool(references), endpoint_app_paths=paths,
                                   endpoint_ids=sorted({e["endpoint_id"] for e in observations}),
                                   endpoint_original_app_match=matched, observations=len(observations)))
    report["shared_endpoint_ids"] = [dict(snapshot_id=key[0], endpoint_id=key[1], tuple_count=len(tuples))
                                     for key, tuples in endpoint_tuples.items() if len(tuples) > 1]
    report["shared_endpoint_groups"] = len(report["shared_endpoint_ids"])
    if not clients or report["native_reference_matches"] != len(clients):
        report.update(status="INCONCLUSIVE_NO_NATIVE_REFERENCE", reason="not every client had fresh original-app net-event evidence")
    elif report["endpoint_observed_clients"] != len(clients):
        report["reason"] = "not every echoed live socket had a complete ALE observation"
    elif report["original_app_matches"] == len(clients):
        report["status"] = "OBSERVED_ALE_ORIGINAL_APP"
    else:
        report["status"] = "CHARACTERIZED_ALE_APP_MISMATCH"
    return report


def positive_integer(value):
    return type(value) is int and value > 0


def socket_ownership_valid(record, client, attempt, capture, decided, deadline, leaking, clock):
    if not clock or len(clock) != 4:
        return False
    frequency, anchor_filetime, anchor_qpc, uncertainty = clock
    if (not all(positive_integer(value) for value in (frequency, anchor_filetime, anchor_qpc))
            or type(uncertainty) is not int or uncertainty < 0):
        return False
    pid, creation = client.get("pid"), client.get("process_creation_filetime")
    event, received, ready = (record.get(key) for key in ("socket_event_qpc", "socket_recv_qpc", "socket_app_ready_qpc"))
    applied = record.get("apply_qpc")
    if (record.get("ownership_source") != "socket" or "event_filetime" in record
            or record.get("creation_guard_valid") is not True
            or not all(positive_integer(value) for value in (pid, creation, event, received, ready, applied,
                                                            record.get("endpoint_id"), attempt.get("attempt_qpc")))
            or record.get("pid") != pid or attempt.get("pid") != pid
            or record.get("process_creation_filetime") != creation or record.get("capture_qpc") != capture
            or record.get("qpc") != applied
            or not attempt["attempt_qpc"] <= event <= capture
            or not event <= received <= ready <= applied
            or not leaking and not applied <= decided < deadline
            or leaking and not deadline <= decided <= applied):
        return False
    creation_ticks = anchor_qpc * 10_000_000 + (creation - anchor_filetime) * frequency
    return creation_ticks <= (event - uncertainty) * 10_000_000


def client_latency_summary(clients, frequency):
    if not positive_integer(frequency):
        raise RuntimeError("invalid client latency clock")
    result = {}
    for app, group in (("a", "selected"), ("b", "direct")):
        members = [client for client in clients if client.get("app") == app]
        echoes, done, resets = [], [], 0
        for client in members:
            attempts = [r for r in client.get("attempts", []) if r.get("kind") == "client_attempt"
                        and r.get("nonce") == client.get("nonce")]
            replies = [r for r in client.get("results", []) if r.get("kind") == "client"
                       and r.get("nonce") == client.get("nonce")]
            if not replies and client.get("returncode") != 0:
                continue
            if len(attempts) != 1 or len(replies) != 1:
                raise RuntimeError("client latency evidence missing")
            start, echo, end = (replies[0].get(key) for key in ("start_qpc", "echo_qpc", "done_qpc"))
            if (not all(positive_integer(value) for value in (start, echo, end)) or not start <= echo <= end
                    or attempts[0].get("attempt_qpc") != start or tuple_key(attempts[0]) != tuple_key(replies[0])):
                raise RuntimeError("invalid client latency evidence")
            echoes.append((echo - start) * 1000 / frequency)
            done.append((end - start) * 1000 / frequency)
            resets += replies[0].get("status") == "reset_observed"

        def distribution(values):
            values = sorted(values)
            if not values:
                return dict(count=0)
            return dict(count=len(values), min=values[0], p50=values[math.ceil(len(values) * .5) - 1],
                        p95=values[math.ceil(len(values) * .95) - 1], max=values[-1])

        result[group] = dict(clients=len(members), echo_matches=len(echoes), reset_observed=resets,
                             start_to_echo_ms=distribution(echoes), start_to_done_ms=distribution(done))
    return result


def reference_diagnostics(key, expected, began, captured, native_records, packet_records, clock, missing, conflict):
    frequency, anchor_filetime, anchor_qpc, uncertainty = clock
    polled = [r for r in native_records if r.get("kind") == "wfp" and tuple_key(r) == key]
    original = [r for r in polled if normalized_path(r.get("app_path", "")) == expected]
    complete = [r for r in original if r.get("complete") is True]
    outbound = [r for r in complete if r.get("direction") == "outbound"]
    layer = [r for r in outbound if r.get("layer_id") == 48]
    qualified = [r for r in layer if positive_integer(r.get("event_filetime"))]
    final = [r for r in native_records if r.get("kind") == "wfp_enum" and tuple_key(r) == key
             and normalized_path(r.get("app_path", "")) == expected and r.get("complete") is True
             and r.get("direction") == "outbound" and r.get("layer_id") == 48
             and positive_integer(r.get("event_filetime"))]

    def occurred(event):
        return anchor_qpc * 10_000_000 + (event["event_filetime"] - anchor_filetime) * frequency

    lower, upper = (began - uncertainty) * 10_000_000, (captured + uncertainty) * 10_000_000
    owners = {r["event_filetime"] for r in packet_records if r.get("kind") == "ownership" and tuple_key(r) == key
              and r.get("capture_qpc") == captured and r.get("ownership_source", "wfp") == "wfp"
              and normalized_path(r.get("app_path", "")) == expected and positive_integer(r.get("event_filetime"))}
    seen_poll = bool(owners.intersection(r["event_filetime"] for r in qualified))
    counts = dict(original_app_outbound_layer48_clients=bool(qualified), engine_event_clients=bool(owners),
        engine_event_seen_in_poll_clients=seen_poll,
        engine_event_missing_from_poll_clients=bool(owners) and not seen_poll,
        engine_event_seen_in_final_enum_clients=bool(owners.intersection(r["event_filetime"] for r in final)),
        fresh_final_enum_only_clients=missing and not any(lower <= occurred(r) <= upper for r in qualified)
            and any(lower <= occurred(r) <= upper for r in final))
    cause = None
    if missing:
        cause = ("no_polled_tuple" if not polled else "no_original_app" if not original
                 else "fresh_app_conflict" if conflict else "incomplete_original_app" if not complete
                 else "wrong_direction" if not outbound else "wrong_layer" if not layer
                 else "invalid_event_time" if not qualified
                 else "before_attempt" if all(occurred(r) < lower for r in qualified)
                 else "after_capture" if all(occurred(r) > upper for r in qualified) else "outside_window")
    timing = None
    if missing and qualified:
        nearest = min(qualified, key=lambda r: abs(occurred(r) - captured * 10_000_000))
        ticks = occurred(nearest)
        capture_delta = (ticks - captured * 10_000_000) / (frequency * 10_000)
        attempt_delta = (ticks - began * 10_000_000) / (frequency * 10_000)
        if abs(capture_delta) <= 600_000 and abs(attempt_delta) <= 600_000:
            timing = capture_delta, attempt_delta
    return cause, counts, timing


def native_reference_audit(clients, packet_records, native_records, app_paths, clock, returncode):
    report = dict(success=False, client_total=len(clients), matched_clients=0, missing_clients=0,
                  conflicting_clients=0, poll_interval_ms=REFERENCE_POLL_INTERVAL_MS, drain_ms=1100, rows=[],
                  missing_causes={key: 0 for key in REFERENCE_MISSING_CAUSES},
                  diagnostic_counts={key: 0 for key in REFERENCE_DIAGNOSTIC_COUNTS})
    summaries = [r for r in native_records if r.get("kind") == "summary"]
    summary = summaries[0] if len(summaries) == 1 else None
    report["native_summary"] = summary
    report["poll_interval_ms"] = summary.get("wfp_poll_interval_ms") if summary else None
    if (returncode != 0 or not summary or summary.get("wfp_api") != "poll" or not summary.get("wfp_polls")
            or type(summary.get("wfp_poll_interval_ms")) is not int
            or summary["wfp_poll_interval_ms"] != REFERENCE_POLL_INTERVAL_MS
            or any(summary.get(key) != 0 for key in ("errors", "queue_dropped", "wfp_poll_errors", "wfp_enum_errors"))
            or summary.get("wfp_enum_truncated") is not False
            or any(r.get("kind") in ("error", "wfp_poll_error", "wfp_enum_error") for r in native_records)):
        report["missing_clients"] = len(clients)
        report["missing_causes"]["collector_unclean"] = len(clients)
        return report
    frequency, anchor_filetime, anchor_qpc, uncertainty = clock
    if (not all(positive_integer(value) for value in (frequency, anchor_filetime, anchor_qpc))
            or type(uncertainty) is not int or uncertainty < 0):
        report["missing_clients"] = len(clients)
        report["missing_causes"]["invalid_clock"] = len(clients)
        return report
    seen = set()
    timing = []
    for client in clients:
        attempts = [r for r in client.get("attempts", []) if r.get("kind") == "client_attempt"
                    and r.get("nonce") == client.get("nonce")]
        key = tuple_key(attempts[0]) if len(attempts) == 1 else None
        captures = [r.get("capture_qpc") for r in packet_records if r.get("kind") == "decision"
                    and tuple_key(r) == key and positive_integer(r.get("capture_qpc"))]
        if (not key or key in seen or not captures or not positive_integer(client.get("pid"))
                or attempts[0].get("pid") != client["pid"] or not positive_integer(attempts[0].get("attempt_qpc"))):
            report["missing_clients"] += 1
            report["missing_causes"]["invalid_client"] += 1
            continue
        seen.add(key)
        began, captured = attempts[0]["attempt_qpc"], min(captures)
        expected = normalized_path(app_paths[client["app"]])
        matches, conflict = [], False
        for event in native_records:
            if (event.get("kind") != "wfp" or tuple_key(event) != key or event.get("complete") is not True
                    or event.get("direction") != "outbound" or event.get("layer_id") != 48
                    or not positive_integer(event.get("event_filetime")) or not event.get("app_path")):
                continue
            occurred = anchor_qpc * 10_000_000 + (event["event_filetime"] - anchor_filetime) * frequency
            if not (began - uncertainty) * 10_000_000 <= occurred <= (captured + uncertainty) * 10_000_000:
                continue
            if normalized_path(event["app_path"]) == expected:
                matches.append(event)
            else:
                conflict = True
        report["matched_clients"] += bool(matches) and not conflict
        report["missing_clients"] += not matches or conflict
        report["conflicting_clients"] += conflict
        cause, counts, delta = reference_diagnostics(key, expected, began, captured, native_records,
            packet_records, clock, not matches or conflict, conflict)
        if cause:
            report["missing_causes"][cause] += 1
        for count_name, value in counts.items():
            report["diagnostic_counts"][count_name] += int(value)
        if delta:
            timing.append(delta)
        report["rows"].append(dict(app=client["app"], tuple=list(key), matched=bool(matches) and not conflict,
                                   attempt_qpc=began, capture_qpc=captured, references=matches))
    def distribution(values):
        values = sorted(values)
        if not values:
            return dict(count=0)
        return dict(count=len(values), min=values[0], p50=values[math.ceil(len(values) * .5) - 1],
                    p95=values[math.ceil(len(values) * .95) - 1], max=values[-1])

    report["missing_reference_timing"] = dict(anchor_uncertainty_ms=uncertainty * 1000 / frequency,
        nearest_original_minus_capture_ms=distribution(value[0] for value in timing),
        nearest_original_minus_attempt_ms=distribution(value[1] for value in timing))
    report["success"] = bool(clients) and report["matched_clients"] == len(clients)
    return report


def inproc_ready_matches(record, ownership_source):
    return (ownership_source in ("wfp", "socket") and record.get("kind") == "ready"
            and record.get("ownership_source") == ownership_source)


def inproc_client_evidence(clients, records, app_paths, mode, quic=False, expect_leak=False,
                           ownership_source="wfp", clock=None):
    selected_tuples, all_tuples = set(), set()
    quic_dropped = 0
    attested, late = 0, 0
    for client in clients:
        app, nonce = client["app"], client["nonce"]
        attempts = [r for r in client["attempts"] if r.get("kind") == "client_attempt" and r.get("nonce") == nonce]
        if len(attempts) != 1 or not tuple_key(attempts[0]):
            raise RuntimeError(f"client {nonce} lacks one valid attempted tuple")
        key = tuple_key(attempts[0])
        if key in all_tuples or key[-1] != (6 if client["protocol"] == "tcp" else 17):
            raise RuntimeError(f"client {nonce} reused a tuple or ran the wrong protocol")
        all_tuples.add(key)
        if app == "a":
            selected_tuples.add(key)
        decisions = [r for r in records if r.get("kind") == "decision" and tuple_key(r) == key]
        selected = app == "a"
        leaking = selected and expect_leak
        dropping = selected and quic
        action = "proxy" if selected and mode == "redirect" and key[-1] == 6 else "direct"
        reason = "selected" if selected else "other_app"
        if selected and key[-1] == 17:
            action, reason = ("drop", "selected_quic") if dropping else ("direct", "selected_udp_direct")
        if leaking:
            action, reason = "direct", "timeout"
        matching = [d for d in decisions if d.get("action") == action and d.get("reason") == reason]
        reset_drops = [d for d in decisions if leaking and d.get("action") == "drop"
                       and d.get("reason") == "leak_reset"]
        if not matching or leaking and len(matching) != 1 or len(matching) + len(reset_drops) != len(decisions):
            raise RuntimeError(f"client {nonce} lacks the expected {reason}/{action} decision")
        decision = matching[0]
        generation = decision.get("generation")
        if not isinstance(generation, int) or generation <= 0 or any(d.get("generation") != generation for d in decisions):
            raise RuntimeError(f"client {nonce} lacks one valid packet generation")
        capture = decision.get("capture_qpc", 0)
        decided = decision.get("qpc", 0)
        deadline = decision.get("deadline_qpc", 0)
        if capture <= 0 or deadline <= capture or decided < capture or not leaking and decided >= deadline:
            raise RuntimeError(f"client {nonce} has invalid decision timing")
        candidates = [r for r in records if r.get("kind") == "ownership" and tuple_key(r) == key
                      and r.get("generation") == generation]
        if ownership_source == "socket" and any(
                not socket_ownership_valid(r, client, attempts[0], capture, decided, deadline, leaking, clock)
                for r in candidates):
            raise RuntimeError(f"client {nonce} has conflicting socket ownership metadata")
        ownership = [r for r in candidates
                     if r.get("generation") == generation and r.get("capture_qpc") == capture
                     and normalized_path(r.get("app_path", "")) == normalized_path(app_paths[app])
                     and r.get("ownership_source", "wfp") == ownership_source
                     and (socket_ownership_valid(r, client, attempts[0], capture, decided, deadline, leaking, clock)
                          if ownership_source == "socket" else r.get("event_filetime", 0) > 0)]
        if not ownership:
            raise RuntimeError(f"client {nonce} lacks generation-matched native ownership")
        if any(normalized_path(r.get("app_path", "")) != normalized_path(app_paths[app])
               for r in records if r.get("kind") == "ownership" and tuple_key(r) == key
               and r.get("generation") == generation):
            raise RuntimeError(f"client {nonce} has conflicting native ownership")
        results = [r for r in client["results"] if r.get("kind") == "client" and r.get("nonce") == nonce]
        if dropping:
            if client["returncode"] == 0 or results:
                raise RuntimeError(f"selected QUIC client {nonce} unexpectedly succeeded")
            quic_dropped += 1
        else:
            status = "reset_observed" if leaking else "echo_ok"
            if client["returncode"] != 0 or len(results) != 1 or results[0].get("status") != status \
                    or tuple_key(results[0]) != key:
                raise RuntimeError(f"client {nonce} lacks a matching {status} result")
            if ownership_source == "socket" and results[0].get("pid") != client.get("pid"):
                raise RuntimeError(f"client {nonce} result has the wrong process identity")
        if leaking:
            leaks = [r for r in records if r.get("kind") == "leaked" and tuple_key(r) == key
                     and r.get("generation") == generation]
            resets = [r for r in records if r.get("kind") == "rst" and tuple_key(r) == key
                      and r.get("generation") == generation]
            if not leaks or not resets or not any(
                    decided <= o.get("qpc", 0) <= l.get("qpc", 0) <= r.get("qpc", 0)
                    and results[0].get("done_qpc", 0) >= l.get("qpc", 0)
                    for o in ownership for l in leaks for r in resets):
                raise RuntimeError(f"client {nonce} lacks timeout, late ownership, leak and observed reset evidence")
            if decided < deadline:
                raise RuntimeError(f"client {nonce} was released before its timeout deadline")
            if any(d.get("qpc", 0) < min(r.get("qpc", 0) for r in resets) for d in reset_drops):
                raise RuntimeError(f"client {nonce} was dropped before its checked reset")
        elif not any(o.get("qpc", 0) <= decided for o in ownership):
            raise RuntimeError(f"client {nonce} was decided before native ownership was observed")
        if ownership_source == "socket":
            attested += 1
            late += leaking

    if not clients or not selected_tuples:
        raise RuntimeError("inproc case lacks selected client attempts")
    if quic and not all_tuples - selected_tuples:
        raise RuntimeError("QUIC case lacks a non-selected UDP echo control")
    if wrong_app_redirected(records, selected_tuples) or any(
            tuple_key(r) not in selected_tuples and (r.get("kind") == "rst" or
            r.get("kind") == "decision" and r.get("action") == "drop") for r in records):
        raise RuntimeError("a non-selected tuple was redirected, dropped or reset")
    result = dict(selected_tuples=selected_tuples, quic_dropped_clients=quic_dropped)
    if ownership_source == "socket":
        result["socket_attestation"] = dict(client_total=len(clients), matched_clients=attested,
            pid_creation_matches=attested, deadline_checked_clients=attested - late, late_leak_clients=late)
    return result


def inproc_client_results(path):
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def inproc_evaluate(summary, mode, protocol, quic, expected_proxy_clients, gateway_count,
                    expect_leak=False, expected_selected_clients=None,
                    expected_lookup_mode=None, expected_filter_cache=None,
                    expected_enum_scope=None, expected_window_before_ms=None, expected_ownership_source=None):
    if not summary or summary.get("engine") != "inproc" or not summary.get("success"):
        return "FAIL", "inproc engine summary missing or reported failure"
    if summary.get("lookup_errors") or summary.get("bfe_errors"):
        return "FAIL", "inproc native lookup or BFE restoration reported an error"
    if expected_ownership_source is not None and summary.get("ownership_source") != expected_ownership_source:
        return "FAIL", "native ownership source differs from the requested comparison"
    if expected_ownership_source == "socket" and (summary.get("socket_clean_shutdown") is not True or any(
            summary.get(key) for key in ("socket_source_errors", "socket_queue_overflow", "socket_history_overflow", "socket_output_errors"))):
        return "FAIL", "socket ownership source reported a receiver, history or shutdown failure"
    if expected_ownership_source == "socket":
        counters = [summary.get(key) for key in ("lookup_calls", "lookup_query_count", "lookup_returned_events")]
        counters += [summary.get(key, {}).get("calls") if isinstance(summary.get(key), dict) else None
                     for key in ("lookup_create", "lookup_enum", "lookup_destroy")]
        if any(type(value) is not int or value != 0 for value in counters):
            return "FAIL", "socket routing unexpectedly used or omitted native WFP query work"
    if expected_lookup_mode is not None and summary.get("lookup_mode") != expected_lookup_mode:
        return "FAIL", "native lookup mode differs from the requested comparison"
    if expected_filter_cache is not None and summary.get("filter_cache") is not expected_filter_cache:
        return "FAIL", "native filter cache differs from the requested comparison"
    if expected_enum_scope is not None and summary.get("enum_scope") != expected_enum_scope:
        return "FAIL", "native enumeration scope differs from the requested comparison"
    if expected_window_before_ms is not None and summary.get("window_before_ms") != expected_window_before_ms:
        return "FAIL", "native event window differs from the requested comparison"
    redirecting = mode == "redirect" and protocol == "tcp"
    expected = expected_proxy_clients if redirecting else 0
    if summary.get("decided_proxy") != expected:
        return "FAIL", f"decided_proxy {summary.get('decided_proxy')} != expected {expected}"
    if gateway_count != expected:
        return "FAIL", f"gateway CONNECT count {gateway_count} != expected {expected}"
    if summary.get("nonselected_client_disrupted"):
        return "FAIL", "inproc engine disrupted a non-selected client"
    if not expect_leak and (summary.get("unattributed") or summary.get("leaked") or summary.get("rst_count")):
        return "FAIL", "normal inproc case had unattributed, leaked or reset flows"
    if expect_leak and (not expected_selected_clients or any(
            summary.get(key) != expected_selected_clients for key in ["unattributed", "leaked", "rst_count"])):
        return "FAIL", "leak case did not time out, identify and reset every selected flow"
    if quic and not summary.get("quic_drops"):
        return "FAIL", "QUIC case dropped no selected UDP/443 flow"
    if quic and expected_selected_clients is not None and summary.get("quic_drops") != expected_selected_clients:
        return "FAIL", "QUIC drop count differs from selected client count"
    return "PASS_RESTRICTED_CASE", None


def wrong_app_redirected(decisions, selected_tuples):
    return any(d.get("kind") == "decision" and d.get("action") == "proxy" and
               tuple_key(d) not in selected_tuples for d in decisions)


def collector_errors(records):
    return any(r.get("kind") == "error" for r in records)


def clean_native_summary(native_summary):
    return bool(native_summary) and not native_summary.get("errors") and not native_summary.get("queue_dropped")


def native_evidence_status(status, source, native_summary, usable_events=None):
    if status not in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION"] or source != "wfp":
        return status, None
    if (native_summary or {}).get("wfp_count"):
        if usable_events == 0:
            return ("INCONCLUSIVE_NO_USABLE_NATIVE_EVENTS",
                    "WFP callbacks contained no usable target ownership; negative controls did not exercise attribution")
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


def process_creation_filetime(process):
    created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
    handle = ctypes.c_void_p(int(process._handle))
    if not ctypes.windll.kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                                ctypes.byref(kernel), ctypes.byref(user)):
        return None
    return created.value


def stop_inproc_collectors(engine, probe, bin_dir, out_dir):
    report = dict(cleanup_forced_pids=[])
    for process in [probe, engine]:
        if process is None or process.poll() is not None:
            continue
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            report["cleanup_forced_pids"].append(process.pid)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    state = out_dir / "bfe-state.json"
    if engine is not None and (report["cleanup_forced_pids"] or engine.poll() != 0) and state.exists():
        try:
            restore = subprocess.run([str(bin_dir / "native-events.exe"), "--restore-state", str(state.resolve()),
                                      "--out", str((out_dir / "restore.jsonl").resolve())],
                                     capture_output=True, text=True, timeout=10)
            (out_dir / "restore.stdout.txt").write_text(restore.stdout + restore.stderr, encoding="utf-8")
            report["fallback_restore_exit_code"] = restore.returncode
        except Exception as error:
            report["fallback_restore_error"] = str(error)
    return report


def stop_native_reference(reference, bin_dir, out_dir):
    directory = out_dir / "native-reference"
    if reference is None:
        return dict(cleanup_forced_pids=[])
    deadline = time.monotonic() + 1.1
    while reference.poll() is None and time.monotonic() < deadline:
        time.sleep(.02)
    (directory / "native.stop").touch()
    return stop_inproc_collectors(reference, None, bin_dir, directory)


def finish_routing_collectors(engine, probe, reference, bin_dir, out_dir,
                              engine_cleanup=None, reference_cleanup=None):
    if engine_cleanup is None:
        engine_cleanup = stop_inproc_collectors(engine, probe, bin_dir, out_dir)
    if reference is not None and reference_cleanup is None:
        reference_cleanup = stop_native_reference(reference, bin_dir, out_dir)
    return engine_cleanup, reference_cleanup


def release_client_start_barrier(clients, start_file, check_collectors):
    if not clients or start_file.exists():
        raise RuntimeError("invalid client start barrier")
    deadline = time.monotonic() + 8
    while True:
        check_collectors()
        if any(client["process"].poll() is not None for client in clients):
            raise RuntimeError("barrier client exited before release")
        if all(client["ready_file"].is_file() for client in clients):
            start_file.touch()
            return len(clients)
        if time.monotonic() > deadline:
            raise TimeoutError("client start barrier readiness missing")
        time.sleep(.01)


def inproc_source_supported(ownership_source, protocol, quic):
    return (ownership_source in ("wfp", "socket") and protocol in ("tcp", "udp")
            and (ownership_source == "wfp" or protocol == "tcp" and not quic))


def run_inproc(args, parser):
    if not inproc_source_supported(args.ownership_source, args.protocol, args.quic):
        parser.error("socket ownership routing currently supports TCP only")
    if args.seconds < 15 or args.hold_ms < 1 or args.iterations < 1 or not 0 <= args.delay_ms <= 10000 or not 0 <= args.concurrency <= 4096:
        parser.error("require --seconds >= 15, --hold-ms >= 1, --delay-ms 0..10000 and --concurrency 0..4096")
    if args.synchronized_start and (args.concurrency <= 0 or args.sequential):
        parser.error("--synchronized-start requires positive concurrency and no --sequential")
    if args.sequential and args.concurrency:
        parser.error("--sequential cannot be combined with --concurrency")
    if args.expect_leak and (args.mode != "redirect" or args.protocol != "tcp" or args.quic or not args.send_rst
                             or not args.hold_ms < args.delay_ms < args.hold_ms + args.leak_ms):
        parser.error("--expect-leak requires TCP redirect, --send-rst and a selected-app delay inside the post-timeout leak window")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("--out must be empty to avoid stale evidence")
    args.out.mkdir(parents=True, exist_ok=True)
    args.bin = args.bin.resolve()
    redirecting = args.mode == "redirect" and args.protocol == "tcp" and not args.quic
    processes, logs = [], []
    private = tempfile.TemporaryDirectory(prefix="gateinto-wfp-private-", dir=args.private_dir)
    bridge = None
    probe = None
    engine = None
    reference = None
    engine_cleanup = None
    reference_cleanup = None
    summary = dict(status="NOT_COMPLETED", validation_stage="startup", engine="inproc", mode=args.mode,
                   protocol="udp" if args.quic else args.protocol,
                   quic=args.quic, expect_leak=args.expect_leak, delay_ms=args.delay_ms,
                   lookup_mode=args.lookup_mode, filter_cache=args.filter_cache, enum_scope=args.enum_scope,
                   client_hold_ms=args.client_hold_ms, window_before_ms=args.window_before_ms,
                   benchmark_round=args.benchmark_round,
                   ownership_source=args.ownership_source, native_reference=args.native_reference,
                   sequential=args.sequential, synchronized_start=args.synchronized_start,
                   concurrency=args.concurrency, topology="single-host-local")

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
        app_paths = {app: native_path(args.bin / f"app-{app}.exe") for app in ["a", "b"]}
        selected_app = app_paths["a"]
        summary["selected_app"] = selected_app
        clock = windows_clock()
        summary.update(qpc_frequency=clock[0], anchor_filetime=clock[1], anchor_qpc=clock[2],
                       clock_uncertainty_ticks=clock[3])
        packet_file = args.out / "packets.jsonl"
        packet_tail = JsonTail(packet_file)
        if redirecting:
            from bridge import Bridge
            bridge = Bridge(manifest, packet_file, args.out / "bridge.jsonl")
            bridge.start()
        if args.native_reference:
            reference_dir = args.out / "native-reference"
            reference_dir.mkdir()
            reference = start(native_reference_command(args.bin, args.out, args.seconds + 30), "native-reference")
            reference_tail = JsonTail(reference_dir / "native.jsonl")
            deadline = time.monotonic() + 10
            while True:
                alive(reference, "native reference")
                ready = next((r for r in reference_tail.read() if r.get("kind") == "ready"), None)
                if ready:
                    summary["native_reference_ready"] = ready
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("native reference readiness missing")
                time.sleep(.01)
        engine_args = inproc_command(args.bin, args.out, manifest, selected_app, args)
        if redirecting:
            engine_args += ["--listener-port", bridge.port]
        engine = start(engine_args, "inproc")
        packet_ready = False
        packet_frequency = 0
        deadline = time.monotonic() + 10
        while not packet_ready:
            alive(engine, "inproc engine")
            for record in packet_tail.read():
                if record.get("kind") == "ready":
                    if not inproc_ready_matches(record, args.ownership_source):
                        raise RuntimeError("engine ready ownership source differs from request")
                    packet_ready = True
                    packet_frequency = record.get("qpc_frequency", 0)
                    summary["engine_ready"] = record
            if time.monotonic() > deadline:
                raise TimeoutError("inproc engine readiness missing")
            time.sleep(.01)
        if packet_frequency != clock[0]:
            raise RuntimeError("engine clock differs from the client reference clock")

        if args.ale_probe:
            probe = start(ale_probe_command(args.bin, args.out, manifest, args), "ale-endpoints")
            probe_tail = JsonTail(args.out / "ale-endpoints.jsonl")
            deadline = time.monotonic() + 10
            while probe.poll() is None:
                if any(r.get("kind") == "ready" for r in probe_tail.read()):
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("ALE endpoint probe readiness missing")
                time.sleep(.01)

        summary["validation_stage"] = "clients"
        clients = []
        client_deadline = time.monotonic() + min(args.seconds - 5, 40)

        def wait_clients(waiting):
            while any(c["process"].poll() is None for c in waiting):
                alive(engine, "inproc engine")
                if reference:
                    alive(reference, "native reference")
                if time.monotonic() > client_deadline:
                    raise TimeoutError("client timeout")
                time.sleep(.01)

        def launch(app, iteration, protocol, port):
            name = f"client-{app}-{protocol}-{iteration}"
            nonce = f"inproc-{args.mode}-{app}-{protocol}-{iteration}"
            attempt_file = args.out / f"{name}.attempt.jsonl"
            command = [args.bin / f"app-{app}.exe", "--target", manifest["target_ip"], "--port", port,
                       "--protocol", protocol, "--nonce", nonce, "--attempt-out", attempt_file.resolve()]
            if args.expect_leak and app == "a":
                command += ["--expect-reset", 1]
            if args.client_hold_ms:
                command += ["--hold-open-ms", args.client_hold_ms]
            ready_file = args.out / f"{name}.ready"
            if args.synchronized_start:
                command += ["--start-file", (args.out / "clients.start").resolve(), "--ready-file", ready_file.resolve()]
            launched = qpc()
            process = start(command, name)
            created = process_creation_filetime(process)
            if not positive_integer(created):
                raise RuntimeError("client process creation time unavailable")
            client = dict(app=app, protocol=protocol, nonce=nonce, process=process, pid=process.pid,
                          process_creation_filetime=created, launched_qpc=launched, ready_file=ready_file,
                          attempt_file=attempt_file, stdout_file=args.out / f"{name}.stdout.txt")
            clients.append(client)
            if args.sequential and not args.concurrency:
                wait_clients([client])

        for client in inproc_client_plan(args, manifest):
            launch(**client)

        if args.synchronized_start:
            def check_collectors():
                alive(engine, "inproc engine")
                if reference:
                    alive(reference, "native reference")
            summary["barrier_client_count"] = release_client_start_barrier(
                clients, args.out / "clients.start", check_collectors)
        wait_clients(clients)

        summary["validation_stage"] = "collectors"
        if probe:
            (args.out / "ale-endpoints.stop").touch()
            try:
                probe.wait(timeout=10)
            except subprocess.TimeoutExpired:
                probe.terminate()
                probe.wait(timeout=5)
        (args.out / "inproc.stop").touch()
        try:
            engine.wait(timeout=args.seconds + 15)
        except subprocess.TimeoutExpired:
            engine.terminate()
            raise RuntimeError("inproc engine did not exit")
        engine_cleanup, reference_cleanup = finish_routing_collectors(
            engine, probe, reference, args.bin, args.out)
        if reference:
            summary["native_reference_cleanup"] = reference_cleanup
        summary["validation_stage"] = "client_evidence"
        packet_records = JsonTail(packet_file).read()
        try:
            engine_summary = json.loads((args.out / "engine-summary.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            engine_summary = None
        summary["engine_summary"] = engine_summary
        client_evidence = []
        for client in clients:
            client_evidence.append(dict(app=client["app"], protocol=client["protocol"], nonce=client["nonce"],
                                        pid=client["pid"], process_creation_filetime=client["process_creation_filetime"],
                                        launched_qpc=client["launched_qpc"],
                                        attempts=JsonTail(client["attempt_file"]).read(),
                                        results=inproc_client_results(client["stdout_file"]),
                                        returncode=client["process"].returncode))
        summary["clients"] = client_evidence
        if probe:
            summary["ale_probe"] = ale_probe_report(client_evidence, packet_records,
                JsonTail(args.out / "ale-endpoints.jsonl").read(), app_paths, packet_frequency, probe.returncode)
        summary["validation_stage"] = "client_attestation"
        evidence = inproc_client_evidence(client_evidence, packet_records, app_paths, args.mode,
                                         quic=args.quic, expect_leak=args.expect_leak,
                                         ownership_source=args.ownership_source, clock=clock)
        selected_tuples = evidence["selected_tuples"]
        summary["validation_stage"] = "client_latency"
        summary["client_latency"] = client_latency_summary(client_evidence, packet_frequency)
        if "socket_attestation" in evidence:
            summary["socket_attestation"] = evidence["socket_attestation"]
        if reference:
            summary["validation_stage"] = "native_reference"
            audit = native_reference_audit(client_evidence, packet_records,
                JsonTail(args.out / "native-reference" / "native.jsonl").read(), app_paths, clock, reference.returncode)
            summary["native_reference_audit"] = audit
            if not audit["success"]:
                raise RuntimeError("independent native reference did not confirm every fresh original client")

        summary["validation_stage"] = "gateway"
        gateway_records = []
        gateway_path = args.out / "gateway.jsonl"
        expected_proxy = len(selected_tuples) if redirecting and not args.expect_leak else 0
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

        summary["validation_stage"] = "engine_complete"
        if any(r.get("kind") == "error" for r in packet_records):
            raise RuntimeError("inproc engine reported an error")
        complete = [r for r in packet_records if r.get("kind") == "complete"]
        if not complete or not complete[-1].get("success"):
            raise RuntimeError("inproc engine did not complete successfully")
        if engine.returncode != 0:
            raise RuntimeError("inproc engine exit code was nonzero")
        summary["validation_stage"] = "engine_evaluation"
        status, error = inproc_evaluate(engine_summary, args.mode, "udp" if args.quic else args.protocol,
                                        args.quic, expected_proxy, len(gateway_records), expect_leak=args.expect_leak,
                                        expected_selected_clients=len(selected_tuples), expected_lookup_mode=args.lookup_mode,
                                        expected_filter_cache=args.filter_cache == "on", expected_enum_scope=args.enum_scope,
                                        expected_window_before_ms=args.window_before_ms,
                                        expected_ownership_source=args.ownership_source)
        summary["status"] = status
        if error:
            summary["error"] = error
            summary["failure_stage"] = "engine_evaluation"
        summary["selected_tuple_count"] = len(selected_tuples)
        summary["gateway_connect_count"] = len(gateway_records)
        summary["quic_dropped_clients"] = evidence["quic_dropped_clients"]
        if args.ale_probe and status == "PASS_RESTRICTED_CASE" and summary["ale_probe"]["status"] != "OBSERVED_WHILE_HELD":
            summary.update(routing_case_status=status, status="INCONCLUSIVE_ALE_ENDPOINT_PROBE",
                           validation_stage="ale_shadow", failure_stage="ale_shadow",
                           error=summary["ale_probe"].get("reason"))
        elif status == "PASS_RESTRICTED_CASE":
            summary["validation_stage"] = "complete"
    except Exception as error:
        summary.update(status="FAIL", failure_stage=summary["validation_stage"], error=str(error))
    finally:
        for name in ["inproc.stop", "ale-endpoints.stop"]:
            (args.out / name).touch()
        cleanup, reference_cleanup = finish_routing_collectors(
            engine, probe, reference, args.bin, args.out, engine_cleanup, reference_cleanup)
        summary.update(cleanup)
        if cleanup["cleanup_forced_pids"] or cleanup.get("fallback_restore_exit_code", 0) or cleanup.get("fallback_restore_error"):
            summary.update(status="FAIL", cleanup_failed=True, validation_stage="cleanup")
            summary.setdefault("failure_stage", "cleanup")
        if reference:
            summary["native_reference_cleanup"] = reference_cleanup
            if (reference_cleanup["cleanup_forced_pids"] or reference_cleanup.get("fallback_restore_exit_code", 0)
                    or reference_cleanup.get("fallback_restore_error")):
                summary.update(status="FAIL", cleanup_failed=True, validation_stage="cleanup")
                summary.setdefault("failure_stage", "cleanup")
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
    print(json.dumps(public_summary(summary)))
    return 0 if summary["status"] == "PASS_RESTRICTED_CASE" else 1


def run_endpoint_control(args, parser):
    if (args.seconds < 15 or not 200 <= args.client_hold_ms <= 5000 or args.quic or args.expect_leak
            or args.send_rst or args.mode != "hold" or args.external_target):
        parser.error("endpoint-control requires local TCP/UDP hold mode, --client-hold-ms 200..5000 and --seconds >= 15")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("--out must be empty to avoid stale evidence")
    args.out.mkdir(parents=True, exist_ok=True)
    args.bin = args.bin.resolve()
    processes, streams = [], []
    fixture = native = probe = None
    cleanup_report = None
    private = tempfile.TemporaryDirectory(prefix="gateinto-wfp-private-", dir=args.private_dir)
    summary = dict(status="NOT_COMPLETED", engine="endpoint-control", protocol=args.protocol,
                   packet_interception=False, routing_authority=False, client_hold_ms=args.client_hold_ms,
                   topology="single-host-local", clients=[])

    def start(command, name):
        stream = (args.out / (name + ".stdout.txt")).open("w", encoding="utf-8")
        streams.append(stream)
        process = subprocess.Popen([str(value) for value in command], stdout=stream, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        processes.append(process)
        return process

    def alive(process, label):
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}; see its log")

    def ready(process, path, label):
        tail = JsonTail(path)
        deadline = time.monotonic() + 10
        while True:
            for record in tail.read():
                if record.get("kind") == "ready":
                    return record
            alive(process, label)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{label} readiness missing")
            time.sleep(.01)

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
                if time.monotonic() >= deadline:
                    raise TimeoutError("fixture manifest missing")
                time.sleep(.02)
        manifest_path.chmod(0o600)
        paths = {app: native_path(args.bin / f"app-{app}.exe") for app in ["a", "b"]}
        native = start(native_command(args.bin, args.out, args.seconds, "poll"), "native")
        native_ready = ready(native, args.out / "native.jsonl", "native reference")
        probe = start(ale_probe_command(args.bin, args.out, manifest, args), "ale-endpoints")
        probe_ready = ready(probe, args.out / "ale-endpoints.jsonl", "ALE probe")
        summary.update(native_ready=native_ready, ale_ready=probe_ready)
        frequency, anchor_filetime, anchor_qpc, uncertainty = windows_clock()
        summary.update(qpc_frequency=frequency, anchor_filetime=anchor_filetime,
                       anchor_qpc=anchor_qpc, clock_uncertainty_ticks=uncertainty)
        clients = []
        for plan in inproc_client_plan(args, manifest):
            app, iteration, protocol, port = plan["app"], plan["iteration"], plan["protocol"], plan["port"]
            label = f"client-{app}-{protocol}-{iteration}"
            nonce = f"endpoint-control-{app}-{protocol}-{iteration}"
            attempt_file = args.out / f"{label}.attempt.jsonl"
            process = start([args.bin / f"app-{app}.exe", "--target", manifest["target_ip"], "--port", port,
                             "--protocol", protocol, "--nonce", nonce, "--attempt-out", attempt_file.resolve(),
                             "--hold-open-ms", args.client_hold_ms], label)
            clients.append(dict(app=app, protocol=protocol, nonce=nonce, process=process,
                                attempt_file=attempt_file, stdout_file=args.out / f"{label}.stdout.txt"))
        deadline = time.monotonic() + min(args.seconds - 5, 40)
        while any(c["process"].poll() is None for c in clients):
            alive(native, "native reference")
            alive(probe, "ALE probe")
            if time.monotonic() >= deadline:
                raise TimeoutError("endpoint control client timeout")
            time.sleep(.01)
        for name in ["native.stop", "ale-endpoints.stop"]:
            (args.out / name).touch()
        cleanup_report = stop_inproc_collectors(native, probe, args.bin, args.out)
        summary.update(cleanup_report)
        evidence = [dict(app=c["app"], protocol=c["protocol"], nonce=c["nonce"],
                         attempts=JsonTail(c["attempt_file"]).read(), results=inproc_client_results(c["stdout_file"]),
                         returncode=c["process"].returncode) for c in clients]
        summary["clients"] = evidence
        if any(result.get("hold_open_ms") != args.client_hold_ms for client in evidence for result in client["results"]
               if result.get("kind") == "client"):
            raise RuntimeError("client hold duration differs from the requested control")
        native_records = JsonTail(args.out / "native.jsonl").read()
        for record in native_records:
            if "event_filetime" in record:
                record["occurrence_qpc"] = anchor_qpc + (record["event_filetime"] - anchor_filetime) * frequency / 10_000_000
        result = ale_control_report(evidence, native_records, JsonTail(args.out / "ale-endpoints.jsonl").read(),
                                    paths, frequency, native.returncode, probe.returncode, uncertainty)
        summary.update(status=result["status"], endpoint_control=result)
    except Exception as error:
        summary.update(status="FAIL_ENDPOINT_CONTROL", error=str(error))
    finally:
        for name in ["native.stop", "ale-endpoints.stop"]:
            (args.out / name).touch()
        cleanup = cleanup_report if cleanup_report is not None else stop_inproc_collectors(native, probe, args.bin, args.out)
        summary["cleanup_forced_pids"] = sorted(set(summary.get("cleanup_forced_pids", []) + cleanup["cleanup_forced_pids"]))
        for key, value in cleanup.items():
            if key != "cleanup_forced_pids":
                summary[key] = value
        if (summary["cleanup_forced_pids"] or summary.get("fallback_restore_exit_code", 0)
                or summary.get("fallback_restore_error")):
            summary.update(status="FAIL_ENDPOINT_CONTROL", cleanup_failed=True)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in streams:
            stream.close()
        private.cleanup()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(public_summary(summary)))
    return 0 if summary["status"] in ["OBSERVED_ALE_ORIGINAL_APP", "CHARACTERIZED_ALE_APP_MISMATCH"] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--private-dir", type=pathlib.Path)
    parser.add_argument("--source", choices=["wfp", "security5156"], default="wfp")
    parser.add_argument("--wfp-api", choices=["subscribe2", "subscribe3", "subscribe4", "poll"], default="subscribe2")
    parser.add_argument("--callback-drain-ms", type=int, default=0)
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
    parser.add_argument("--engine", choices=["external", "inproc", "endpoint-control"], default="external")
    parser.add_argument("--ownership-source", choices=["wfp", "socket"], default="wfp")
    parser.add_argument("--native-reference", action="store_true")
    parser.add_argument("--sequential", action="store_true")
    parser.add_argument("--synchronized-start", action="store_true")
    parser.add_argument("--concurrency", type=int, default=0)
    parser.add_argument("--quic", action="store_true")
    parser.add_argument("--window-before-ms", type=int, default=500)
    parser.add_argument("--window-after-ms", type=int, default=50)
    parser.add_argument("--leak-ms", type=int, default=2000)
    parser.add_argument("--send-rst", action="store_true")
    parser.add_argument("--expect-leak", action="store_true")
    parser.add_argument("--lookup-mode", choices=["inline", "async"], default="inline")
    parser.add_argument("--filter-cache", choices=["on", "off"], default="on")
    parser.add_argument("--ale-probe", action="store_true")
    parser.add_argument("--enum-scope", choices=["legacy", "destination"], default="legacy")
    parser.add_argument("--client-hold-ms", type=int, default=0)
    parser.add_argument("--benchmark-round", type=int, choices=[0, 1, 2], default=0)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows is required; pure attribution tests run on other hosts")
    if not 0 <= args.client_hold_ms <= 5000:
        parser.error("--client-hold-ms must be 0..5000")
    if args.engine != "inproc" and (args.ownership_source != "wfp" or args.native_reference or args.sequential or args.synchronized_start):
        parser.error("ownership-source, native-reference and client launch controls require --engine inproc")
    if args.engine == "endpoint-control":
        return run_endpoint_control(args, parser)
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
        native = start(native_command(args.bin, args.out, args.seconds, args.wfp_api, args.callback_drain_ms), "native")
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
                    process.wait(timeout=10 if "native" in locals() and process is native else 5)
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
        status, error = native_evidence_status(summary["status"], args.source, summary.get("native_summary"),
                                               summary.get("source_target_complete_outbound_events"))
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
    print(json.dumps(public_summary(summary)))
    return 0 if summary["status"] in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION"] else 1


if __name__ == "__main__":
    sys.exit(main())
