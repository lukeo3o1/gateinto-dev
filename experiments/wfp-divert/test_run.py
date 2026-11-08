import importlib.util
import pathlib
import json
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("lab_run", pathlib.Path(__file__).with_name("run.py"))
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from bridge import Bridge


class AttributionTests(unittest.TestCase):
    def engine(self, **kwargs):
        return lab.Attribution("wfp", "\\device\\lab\\app-a.exe", 1000, 100, **kwargs)

    def packet(self, generation=1000):
        return dict(kind="packet", local_ip="10.0.0.1", local_port=1234,
                    remote_ip="10.0.0.2", remote_port=443, protocol=6,
                    generation=generation, capture_qpc=generation, recv_qpc=generation,
                    action="pending")

    def event(self, **changes):
        value = dict(self.packet(), kind="wfp", direction="outbound", complete=True,
                     app_path="\\device\\lab\\app-a.exe", recv_qpc=1010,
                     occurrence_qpc=995)
        value.update(changes)
        return value

    def test_unknown_never_proxies(self):
        engine = self.engine()
        engine.packet(self.packet())
        self.assertEqual([], engine.decisions(1020))

    def test_confirmation_before_or_after_packet(self):
        for event_first in [False, True]:
            engine = self.engine()
            if event_first:
                engine.event(self.event())
            engine.packet(self.packet())
            if not event_first:
                engine.event(self.event())
            result = engine.decisions(1020)
            self.assertEqual("proxy", result[0]["action"])
            self.assertEqual(1000, result[0]["generation"])

    def test_wrong_tuple_and_wrong_source_cannot_authorize(self):
        for change in [dict(local_port=5678), dict(kind="security5156"), dict(direction="inbound")]:
            engine = self.engine()
            engine.packet(self.packet())
            engine.event(self.event(**change))
            self.assertEqual([], engine.decisions(1020))

    def test_other_app_is_direct_and_same_basename_other_directory_is_direct(self):
        for path in ["\\device\\lab\\app-b.exe", "\\device\\elsewhere\\app-a.exe"]:
            engine = self.engine()
            engine.packet(self.packet())
            engine.event(self.event(app_path=path))
            self.assertEqual("direct", engine.decisions(1020)[0]["action"])

    def test_missing_path_or_tuple_is_not_authority(self):
        for change in [dict(app_path=""), dict(complete=False), dict(remote_port=0)]:
            engine = self.engine()
            engine.packet(self.packet())
            engine.event(self.event(**change))
            self.assertEqual([], engine.decisions(1020))

    def test_skip_and_delay_past_deadline_never_proxy(self):
        for options in [dict(skip_all=True), dict(delay_ms=150)]:
            engine = self.engine(**options)
            engine.packet(self.packet())
            engine.event(self.event())
            self.assertEqual([], engine.decisions(1200))

    def test_old_timestamp_and_reused_tuple_rejected(self):
        engine = self.engine()
        engine.packet(self.packet())
        engine.event(self.event(occurrence_qpc=-5000))
        self.assertEqual([], engine.decisions(1020))
        engine.packet(self.packet(generation=1030))
        engine.event(self.event(occurrence_qpc=1025, recv_qpc=1040))
        self.assertEqual([], engine.decisions(1050))

    def test_conflicting_native_ownership_rejected(self):
        engine = self.engine()
        engine.packet(self.packet())
        engine.event(self.event())
        engine.event(self.event(app_path="\\device\\lab\\app-b.exe"))
        self.assertEqual([], engine.decisions(1020))

    def test_udp_and_hold_mode_do_not_proxy(self):
        for protocol, mode in [(17, "redirect"), (6, "hold")]:
            engine = self.engine(mode=mode)
            packet = self.packet()
            packet["protocol"] = protocol
            engine.packet(packet)
            engine.event(self.event(protocol=protocol))
            self.assertEqual("direct", engine.decisions(1020)[0]["action"])

    def test_security_xml_uses_eventdata_pid(self):
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Execution ProcessID="4"/><TimeCreated SystemTime="2026-11-06T00:00:00.0000000Z"/></System><EventData>'
        for name, value in dict(ProcessID="123", Application="\\device\\lab\\app-a.exe", Direction="%%14593", SourceAddress="10.0.0.1", SourcePort="1234", DestAddress="10.0.0.2", DestPort="443", Protocol="6").items():
            xml += f'<Data Name="{name}">{value}</Data>'
        event = lab.security_fields(dict(kind="security5156", raw_xml=xml + '</EventData></Event>'))
        self.assertEqual(123, event["pid"])
        self.assertTrue(event["complete"])
        self.assertEqual("outbound", event["direction"])

    def test_retransmission_requires_distinct_capture_with_same_sequence(self):
        packet = dict(self.packet(), syn=1, sequence=123, kind="packet")
        dropped = dict(packet, action="drop", reason="injected_first_syn_drop")
        self.assertFalse(lab.retransmissions_verified([dropped, dict(packet, action="proxy")]))
        repeated = dict(packet, capture_qpc=1100, action="proxy")
        self.assertTrue(lab.retransmissions_verified([dropped, repeated]))
        self.assertFalse(lab.retransmissions_verified([dropped, dict(repeated, sequence=999)]))

    def test_reuse_requires_post_launch_same_tuple_syn_rejection(self):
        packet = dict(self.packet(), action="drop", reason="ambiguous_reuse_of_proxy_tuple", syn=1,
                      capture_qpc=1090, recv_qpc=1100, sequence=456)
        key = lab.tuple_key(packet)
        self.assertTrue(lab.reuse_rejection_verified([packet], key, 1050, 123))
        self.assertFalse(lab.reuse_rejection_verified([packet], key, 1150, 123))
        self.assertFalse(lab.reuse_rejection_verified([dict(packet, syn=0)], key, 1050, 123))
        self.assertFalse(lab.reuse_rejection_verified([dict(packet, local_port=5555)], key, 1050, 123))
        self.assertFalse(lab.reuse_rejection_verified([dict(packet, capture_qpc=1040)], key, 1050, 123))
        self.assertFalse(lab.reuse_rejection_verified([dict(packet, sequence=123)], key, 1050, 123))

    def test_timing_separates_notification_from_delayed_decision(self):
        packet = self.packet()
        packet["recv_qpc"] = 1015
        event = self.event(recv_qpc=1010, occurrence_qpc=995)
        decision = dict(packet, decision_qpc=1060)
        client = dict(packet, nonce="timing")
        result = lab.timing_summary([("a", client)], [packet], [event], [decision], 1000)
        self.assertEqual(1, result["native_after_packet_capture"])
        self.assertEqual(0, result["native_after_packet_receive"])
        self.assertEqual(10, result["notification_minus_capture_ms"]["p95"])
        self.assertEqual(60, result["decision_minus_capture_ms"]["p95"])
        self.assertEqual(995, result["rows"][0]["occurrence_qpc"])

    def test_connect_only_result_does_not_count_as_echo(self):
        result = dict(self.packet(), kind="client", status="connected")
        self.assertTrue(lab.valid_client_result(result, connect_only=True))
        self.assertFalse(lab.valid_client_result(result, connect_only=False))
        result["status"] = "echo_ok"
        self.assertTrue(lab.valid_client_result(result, connect_only=False))
        self.assertFalse(lab.valid_client_result(result, connect_only=True))

    def test_wfp_pass_without_native_events_is_inconclusive(self):
        status, error = lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", dict(wfp_count=0, wfp_raw_count=3))
        self.assertEqual("INCONCLUSIVE_NO_NATIVE_EVENTS", status)
        self.assertIn("wfp_count", error)
        self.assertEqual(("PASS_RESTRICTED_CASE", None),
                         lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", dict(wfp_count=2)))
        self.assertEqual(("PASS_RESTRICTED_CASE", None),
                         lab.native_evidence_status("PASS_RESTRICTED_CASE", "security5156", dict(wfp_count=0)))
        self.assertEqual(("FAIL", None), lab.native_evidence_status("FAIL", "wfp", dict(wfp_count=0)))
        self.assertEqual("INCONCLUSIVE_NO_NATIVE_EVENTS",
                         lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", None)[0])

    def test_wfp_reuse_rejection_without_native_events_is_inconclusive(self):
        self.assertEqual("INCONCLUSIVE_NO_NATIVE_EVENTS",
                         lab.native_evidence_status("CHARACTERIZED_REUSE_REJECTION", "wfp", dict(wfp_count=0))[0])
        self.assertEqual(("CHARACTERIZED_REUSE_REJECTION", None),
                         lab.native_evidence_status("CHARACTERIZED_REUSE_REJECTION", "security5156", dict(wfp_count=0)))

    def test_raw_callbacks_without_usable_ownership_cannot_pass_negative_controls(self):
        status, error = lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", dict(wfp_count=6), usable_events=0)
        self.assertEqual("INCONCLUSIVE_NO_USABLE_NATIVE_EVENTS", status)
        self.assertIn("usable", error)
        self.assertEqual(("PASS_RESTRICTED_CASE", None),
                         lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", dict(wfp_count=6), usable_events=3))

    def test_native_command_passes_wfp_api(self):
        command = [str(x) for x in lab.native_command(pathlib.Path("bin"), pathlib.Path("out"), 35, "poll")]
        self.assertEqual(str(pathlib.Path("bin") / "native-events.exe"), command[0])
        self.assertEqual("poll", command[command.index("--wfp-api") + 1])
        self.assertEqual("35", command[command.index("--seconds") + 1])
        self.assertTrue(command[command.index("--out") + 1].endswith("native.jsonl"))
        self.assertTrue(command[command.index("--stop-file") + 1].endswith("native.stop"))
        self.assertTrue(command[command.index("--state-out") + 1].endswith("bfe-state.json"))

    def test_polled_event_timing_uses_poll_observation_time(self):
        client = dict(self.packet(), kind="client", nonce="n")
        packet = self.packet(generation=1000)
        polled = self.event(recv_qpc=1050, event_filetime=1, occurrence_qpc=999)
        decision = dict(self.packet(), kind="decision", decision_qpc=1060)
        result = lab.timing_summary([("a", client)], [packet], [polled], [decision], 1000)
        self.assertEqual(50, result["notification_minus_capture_ms"]["p50"])
        self.assertEqual(60, result["decision_minus_capture_ms"]["p50"])
        self.assertEqual(999, result["rows"][0]["occurrence_qpc"])

    def test_enumeration_errors_do_not_fail_wfp_case(self):
        summary = dict(kind="summary", wfp_count=0, wfp_enum_errors=2, errors=0, queue_dropped=0)
        records = [dict(kind="wfp_enum_error", operation="FwpmNetEventEnum3", code=5), summary]
        self.assertFalse(lab.collector_errors(records))
        self.assertTrue(lab.collector_errors([dict(kind="error", operation="x", code=1)]))
        self.assertTrue(lab.clean_native_summary(summary))
        self.assertFalse(lab.clean_native_summary(dict(summary, errors=1)))
        self.assertFalse(lab.clean_native_summary(dict(summary, queue_dropped=1)))
        self.assertFalse(lab.clean_native_summary(None))
        self.assertEqual("INCONCLUSIVE_NO_NATIVE_EVENTS",
                         lab.native_evidence_status("PASS_RESTRICTED_CASE", "wfp", summary)[0])

    def test_poll_case_without_polls_fails(self):
        for status in ["PASS_RESTRICTED_CASE", "CHARACTERIZED_REUSE_REJECTION", "INCONCLUSIVE_NO_NATIVE_EVENTS"]:
            result, error = lab.poll_evidence_status(status, None, "poll", dict(wfp_polls=0, wfp_count=0))
            self.assertEqual("FAIL", result)
            self.assertIn("wfp_polls", error)
        result, error = lab.poll_evidence_status("FAIL", "client timeout", "poll", dict(wfp_polls=0))
        self.assertEqual("FAIL", result)
        self.assertIn("client timeout", error)
        self.assertIn("wfp_polls", error)
        self.assertEqual("FAIL", lab.poll_evidence_status("PASS_RESTRICTED_CASE", None, "poll", dict(kind="summary"))[0])
        self.assertEqual(("PASS_RESTRICTED_CASE", None),
                         lab.poll_evidence_status("PASS_RESTRICTED_CASE", None, "poll", dict(wfp_polls=3)))
        self.assertEqual(("PASS_RESTRICTED_CASE", None),
                         lab.poll_evidence_status("PASS_RESTRICTED_CASE", None, "subscribe4", dict(wfp_polls=0)))
        self.assertEqual(("FAIL", "native collector missing"),
                         lab.poll_evidence_status("FAIL", "native collector missing", "poll", None))


class InprocEngineTests(unittest.TestCase):
    def args(self, **changes):
        base = dict(mode="redirect", protocol="tcp", hold_ms=1000, seconds=35, window_before_ms=500,
                    window_after_ms=50, leak_ms=2000, send_rst=True, quic=False, delay_ms=0,
                    expect_leak=False, concurrency=0)
        base.update(changes)
        return type("Args", (), base)()

    def manifest(self):
        return dict(target_ip="127.0.0.1", target_port=9000, udp_ports=[9100, 9101])

    def test_inproc_command_includes_engine_options(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe", self.args())]
        self.assertEqual(str(pathlib.Path("bin") / "inproc.exe"), command[0])
        self.assertEqual("redirect", command[command.index("--mode") + 1])
        self.assertEqual("\\device\\app-a.exe", command[command.index("--selected-app") + 1])
        self.assertEqual("500", command[command.index("--window-before-ms") + 1])
        self.assertEqual("1", command[command.index("--send-rst") + 1])
        self.assertTrue(command[command.index("--summary") + 1].endswith("engine-summary.json"))
        self.assertNotIn("--quic-port", command)

    def test_inproc_command_quic_adds_drop_port(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe",
            self.args(quic=True, protocol="udp"))]
        self.assertEqual("9100", command[command.index("--quic-port") + 1])

    def test_udp_command_does_not_require_a_tcp_listener(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe",
            self.args(quic=True, protocol="udp"))]
        self.assertEqual("hold", command[command.index("--mode") + 1])
        self.assertEqual(1, command.count("--udp-port"))

    def test_inproc_command_passes_selected_attribution_delay(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe",
            self.args(delay_ms=150, expect_leak=True))]
        self.assertEqual("150", command[command.index("--delay-ms") + 1])

    def test_inproc_command_selects_async_and_cache_baselines(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe",
            self.args(lookup_mode="async", filter_cache="off"))]
        self.assertEqual("async", command[command.index("--lookup-mode") + 1])
        self.assertEqual("off", command[command.index("--filter-cache") + 1])

    def test_inproc_command_passes_destination_scope_and_narrow_window(self):
        command = [str(x) for x in lab.inproc_command(
            pathlib.Path("bin"), pathlib.Path("out"), self.manifest(), "\\device\\app-a.exe",
            self.args(enum_scope="destination", window_before_ms=5))]
        self.assertEqual("destination", command[command.index("--enum-scope") + 1])
        self.assertEqual("5", command[command.index("--window-before-ms") + 1])

    def test_inproc_comparison_requires_the_requested_native_mode(self):
        summary = dict(engine="inproc", success=True, decided_proxy=0, quic_drops=0,
                       lookup_mode="inline", filter_cache=True, enum_scope="legacy", window_before_ms=500)
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "hold", "tcp", False, 0, 0,
                                                    expected_lookup_mode="async")[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "hold", "tcp", False, 0, 0,
                                                    expected_filter_cache=False)[0])
        self.assertEqual("PASS_RESTRICTED_CASE", lab.inproc_evaluate(summary, "hold", "tcp", False, 0, 0,
                            expected_lookup_mode="inline", expected_filter_cache=True)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "hold", "tcp", False, 0, 0,
                                                    expected_enum_scope="destination")[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "hold", "tcp", False, 0, 0,
                                                    expected_window_before_ms=5)[0])

    def test_udp_and_quic_plans_exercise_both_apps_with_udp(self):
        for quic in [False, True]:
            plan = lab.inproc_client_plan(self.args(protocol="udp", quic=quic), self.manifest())
            self.assertEqual(6, len(plan))
            self.assertEqual({"a", "b"}, {c["app"] for c in plan})
            self.assertEqual({"udp"}, {c["protocol"] for c in plan})
            self.assertEqual({9100}, {c["port"] for c in plan})

    def client_evidence(self, app="a", protocol=6, action="proxy", reason="selected", status="echo_ok"):
        attempt = dict(kind="client_attempt", local_ip="127.0.0.1", local_port=40000 if app == "a" else 40001,
                       remote_ip="127.0.0.1", remote_port=9000, protocol=protocol, nonce=f"test-{app}")
        result = dict(attempt, kind="client", status=status, done_qpc=150)
        client = dict(app=app, protocol="tcp" if protocol == 6 else "udp", nonce=f"test-{app}",
                      attempts=[attempt], results=[result], returncode=0)
        ownership = dict(attempt, kind="ownership", generation=100, capture_qpc=100, qpc=110,
                         event_filetime=1000, app_path=f"\\device\\lab\\app-{app}.exe")
        decision = dict(attempt, kind="decision", generation=100, capture_qpc=100, deadline_qpc=120,
                        qpc=115, action=action, reason=reason)
        return client, [ownership, decision]

    def validate_clients(self, clients, records, **changes):
        args = dict(mode="redirect", quic=False, expect_leak=False)
        args.update(changes)
        return lab.inproc_client_evidence(clients, records,
            {a: f"\\device\\lab\\app-{a}.exe" for a in ["a", "b"]}, **args)

    def test_hold_udp_requires_real_udp_native_ownership_for_each_client(self):
        a, a_records = self.client_evidence(protocol=17, action="direct", reason="selected_udp_direct")
        b, b_records = self.client_evidence(app="b", protocol=17, action="direct", reason="other_app")
        self.validate_clients([a, b], a_records + b_records, mode="hold")
        for broken in [a_records[1:] + b_records,
                       [dict(a_records[0], app_path="\\device\\elsewhere\\app-a.exe"), a_records[1]] + b_records,
                       [dict(a_records[0], generation=99), a_records[1]] + b_records,
                       [a_records[0], dict(a_records[1], qpc=125)] + b_records,
                       [a_records[0], dict(a_records[1], reason="timeout")] + b_records]:
            with self.assertRaises(RuntimeError):
                self.validate_clients([a, b], broken, mode="hold")

    def test_client_echo_and_decision_cannot_authorize_without_native_evidence(self):
        client, records = self.client_evidence()
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            self.validate_clients([client], records[1:])
        with self.assertRaises(RuntimeError):
            self.validate_clients([dict(client, results=[])], records)
        with self.assertRaises(RuntimeError):
            self.validate_clients([dict(client, attempts=[])], records)

    def test_quic_proves_selected_drop_and_other_app_echo(self):
        a, a_records = self.client_evidence(protocol=17, action="drop", reason="selected_quic")
        a.update(returncode=1, results=[])
        b, b_records = self.client_evidence(app="b", protocol=17, action="direct", reason="other_app")
        self.validate_clients([a, b], a_records + b_records, quic=True)
        with self.assertRaises(RuntimeError):
            self.validate_clients([a], a_records, quic=True)
        with self.assertRaises(RuntimeError):
            self.validate_clients([a, dict(b, returncode=1, results=[])], a_records + b_records, quic=True)
        with self.assertRaises(RuntimeError):
            self.validate_clients([a, b], [a_records[0]] + b_records, quic=True)
        with self.assertRaises(RuntimeError):
            self.validate_clients([a, b], a_records + [b_records[0], dict(b_records[1], action="drop")], quic=True)

    def test_leakcheck_requires_timeout_late_ownership_reset_and_client_reset(self):
        client, records = self.client_evidence(action="direct", reason="timeout", status="reset_observed")
        records[1]["qpc"] = 125
        records[0]["qpc"] = 130
        records += [dict(records[1], kind="leaked", qpc=135), dict(records[1], kind="rst", qpc=140)]
        self.validate_clients([client], records, expect_leak=True)
        post_reset_drop = dict(records[1], action="drop", reason="leak_reset", qpc=145)
        self.validate_clients([client], records + [post_reset_drop], expect_leak=True)
        for broken in [records[:-1], records[:2] + records[3:],
                       [dict(records[0], qpc=105)] + records[1:],
                       records[:3] + [dict(records[3], generation=99)],
                       records + [dict(post_reset_drop, qpc=130)],
                       records + [dict(post_reset_drop, generation=99)],
                       records + [dict(post_reset_drop, reason="other_app")],
                       records + [dict(records[1], qpc=126)]]:
            with self.assertRaises(RuntimeError):
                self.validate_clients([client], broken, expect_leak=True)
        with self.assertRaises(RuntimeError):
            self.validate_clients([dict(client, results=[dict(client["results"][0], status="echo_ok")])], records,
                                  expect_leak=True)

    def test_failed_quic_stdout_keeps_diagnostic_without_json_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "client.stdout.txt"
            path.write_text('reply missing; WSA=10060\n', encoding="utf-8")
            self.assertEqual([], lab.inproc_client_results(path))
            path.write_text(json.dumps(dict(kind="client", status="echo_ok")) + '\n', encoding="utf-8")
            self.assertEqual("echo_ok", lab.inproc_client_results(path)[0]["status"])

    def test_inproc_summary_rejects_unexpected_leak_or_nonselected_disruption(self):
        summary = dict(engine="inproc", success=True, decided_proxy=0, quic_drops=0)
        for changes in [dict(unattributed=1), dict(leaked=1), dict(rst_count=1), dict(nonselected_client_disrupted=True),
                        dict(lookup_errors=1), dict(bfe_errors=1)]:
            self.assertEqual("FAIL", lab.inproc_evaluate(dict(summary, **changes), "hold", "tcp", False, 0, 0)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "redirect", "tcp", False, 0, 0,
                                                    expect_leak=True, expected_selected_clients=3)[0])

    def test_inproc_evaluate_redirect_requires_matching_proxy_and_gateway(self):
        summary = dict(engine="inproc", success=True, decided_proxy=3, quic_drops=0)
        self.assertEqual("PASS_RESTRICTED_CASE",
                         lab.inproc_evaluate(summary, "redirect", "tcp", False, 3, 3)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "redirect", "tcp", False, 3, 2)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(dict(summary, decided_proxy=2), "redirect", "tcp", False, 3, 3)[0])

    def test_inproc_evaluate_hold_and_udp_expect_no_proxy(self):
        summary = dict(engine="inproc", success=True, decided_proxy=0, quic_drops=0)
        self.assertEqual("PASS_RESTRICTED_CASE", lab.inproc_evaluate(summary, "hold", "tcp", False, 3, 0)[0])
        self.assertEqual("PASS_RESTRICTED_CASE", lab.inproc_evaluate(summary, "redirect", "udp", False, 0, 0)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(dict(summary, decided_proxy=1), "hold", "tcp", False, 3, 0)[0])

    def test_inproc_evaluate_requires_success_and_engine(self):
        self.assertEqual("FAIL", lab.inproc_evaluate(None, "hold", "tcp", False, 0, 0)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(dict(engine="inproc", success=False), "hold", "tcp", False, 0, 0)[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(dict(engine="poll", success=True), "hold", "tcp", False, 0, 0)[0])

    def test_inproc_evaluate_quic_requires_a_drop(self):
        summary = dict(engine="inproc", success=True, decided_proxy=0, quic_drops=0)
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "redirect", "udp", True, 0, 0)[0])
        self.assertEqual("PASS_RESTRICTED_CASE",
                         lab.inproc_evaluate(dict(summary, quic_drops=2), "redirect", "udp", True, 0, 0)[0])

    def test_wrong_app_redirected_detects_unselected_proxy(self):
        selected = {("10.0.0.1", 1111, "10.0.0.2", 443, 6)}
        good = dict(kind="decision", action="proxy", local_ip="10.0.0.1", local_port=1111,
                    remote_ip="10.0.0.2", remote_port=443, protocol=6)
        bad = dict(good, local_port=2222)
        self.assertFalse(lab.wrong_app_redirected([good], selected))
        self.assertTrue(lab.wrong_app_redirected([good, bad], selected))
        self.assertFalse(lab.wrong_app_redirected([dict(bad, action="direct")], selected))


class AleEndpointProbeTests(unittest.TestCase):
    def fixture(self):
        key = dict(local_ip="127.0.0.1", local_port=40000, remote_ip="127.0.0.1", remote_port=9000, protocol=6)
        clients = [dict(app="a", attempts=[dict(key, kind="client_attempt", nonce="n")])]
        packets = [dict(key, kind="decision", generation=100, capture_qpc=100, qpc=200)]
        records = [dict(kind="summary", source="ale_endpoint", available=True, success=True, errors=0, truncated=False),
                   dict(kind="ale_snapshot", snapshot_id=1, complete=True, query_start_qpc=110, observed_qpc=130),
                   dict(key, kind="ale_endpoint", snapshot_id=1, endpoint_id=77, app_path="\\device\\app-a.exe",
                        snapshot_complete=True, query_start_qpc=110, observed_qpc=130, recv_qpc=130)]
        return clients, packets, records

    def report(self, clients, packets, records):
        return lab.ale_probe_report(clients, packets, records, {"a": "\\device\\app-a.exe"}, 1000, 0)

    def test_endpoint_probe_is_a_distinct_source_with_observation_timing(self):
        clients, packets, records = self.fixture()
        result = self.report(clients, packets, records)
        self.assertEqual("OBSERVED_WHILE_HELD", result["status"])
        self.assertFalse(result["routing_authority"])
        self.assertEqual(30, result["rows"][0]["observation_minus_capture_ms"])
        self.assertEqual(77, result["rows"][0]["endpoint_id"])
        self.assertNotIn("event_filetime", result["rows"][0])

    def test_partial_failed_or_unavailable_snapshots_are_inconclusive(self):
        for change in ["partial", "failed", "unavailable", "missing_summary"]:
            clients, packets, records = self.fixture()
            if change == "partial":
                records[1]["complete"] = False
            elif change == "failed":
                records[0]["success"] = False
            elif change == "unavailable":
                records[0]["available"] = False
            else:
                records = records[1:]
            self.assertEqual("INCONCLUSIVE_ALE_ENDPOINT_PROBE", self.report(clients, packets, records)["status"])

    def test_endpoint_identity_path_and_tuple_ambiguity_are_rejected(self):
        for field, value in [("app_path", "\\device\\other.exe"), ("local_port", 40001), ("endpoint_id", 0)]:
            clients, packets, records = self.fixture()
            records[2][field] = value
            self.assertEqual("INCONCLUSIVE_ALE_ENDPOINT_PROBE", self.report(clients, packets, records)["status"])
        clients, packets, records = self.fixture()
        records.append(dict(records[2], endpoint_id=78))
        self.assertEqual("INCONCLUSIVE_ALE_ENDPOINT_PROBE", self.report(clients, packets, records)["status"])

    def test_endpoint_observed_after_decision_is_not_before_release_evidence(self):
        clients, packets, records = self.fixture()
        for record in records[1:]:
            record["observed_qpc"] = 250
        result = self.report(clients, packets, records)
        self.assertEqual("INCONCLUSIVE_ALE_ENDPOINT_PROBE", result["status"])
        self.assertFalse(result["rows"][0]["observed_before_decision"])


class AleNoDiversionControlTests(unittest.TestCase):
    def fixture(self):
        clients, native, ale = [], [], []
        paths = {"a": "\\device\\app-a.exe", "b": "\\device\\app-b.exe"}
        native.append(dict(kind="summary", wfp_api="poll", errors=0, queue_dropped=0, wfp_polls=3, wfp_poll_errors=0))
        ale += [dict(kind="summary", source="ale_endpoint", available=True, success=True, errors=0, truncated=False),
                dict(kind="ale_snapshot", snapshot_id=1, complete=True, query_start_qpc=150, observed_qpc=170)]
        for app, port in [("a", 40000), ("b", 40001)]:
            key = dict(local_ip="127.0.0.1", local_port=port, remote_ip="127.0.0.1", remote_port=9000, protocol=6)
            attempt = dict(key, kind="client_attempt", nonce=app, attempt_qpc=100)
            result = dict(key, kind="client", nonce=app, status="echo_ok", echo_qpc=120,
                          hold_end_qpc=620, done_qpc=621, hold_open_ms=500)
            clients.append(dict(app=app, protocol="tcp", nonce=app, attempts=[attempt], results=[result], returncode=0))
            native.append(dict(key, kind="wfp", app_path=paths[app], layer_id=48, direction="outbound",
                               complete=True, occurrence_qpc=110, recv_qpc=130))
            ale.append(dict(key, kind="ale_endpoint", snapshot_id=1, endpoint_id=77, app_path="System",
                            snapshot_complete=True, query_start_qpc=150, observed_qpc=170))
        return clients, native, ale, paths

    def report(self, clients, native, ale, paths):
        return lab.ale_control_report(clients, native, ale, paths, 1000, native_exit=0, probe_exit=0)

    def test_system_mismatch_with_original_native_reference_is_characterized(self):
        result = self.report(*self.fixture())
        self.assertEqual("CHARACTERIZED_ALE_APP_MISMATCH", result["status"])
        self.assertFalse(result["routing_authority"])
        self.assertFalse(result["packet_interception"])
        self.assertEqual(2, result["native_reference_matches"])
        self.assertEqual(2, result["endpoint_observed_clients"])
        self.assertEqual(0, result["original_app_matches"])
        self.assertTrue(result["shared_endpoint_ids"])
        self.assertNotIn("generation", result["rows"][0])
        self.assertNotIn("capture_qpc", result["rows"][0])

    def test_correct_original_app_snapshot_is_only_live_endpoint_evidence(self):
        clients, native, ale, paths = self.fixture()
        for i, entry in enumerate(ale[2:]):
            entry["app_path"] = paths[clients[i]["app"]]
            entry["endpoint_id"] += i
        result = self.report(clients, native, ale, paths)
        self.assertEqual("OBSERVED_ALE_ORIGINAL_APP", result["status"])
        self.assertFalse(result["routing_authority"])
        self.assertEqual(2, result["original_app_matches"])

    def test_missing_or_failed_native_reference_cannot_characterize_ale(self):
        for change in ["missing", "wrong_app", "poll_error", "old_event"]:
            clients, native, ale, paths = self.fixture()
            if change == "missing":
                native = native[:1]
            elif change == "wrong_app":
                native[1]["app_path"] = "System"
            elif change == "poll_error":
                native[0]["wfp_poll_errors"] = 1
            else:
                native[1]["occurrence_qpc"] = 10
            self.assertEqual("INCONCLUSIVE_NO_NATIVE_REFERENCE", self.report(clients, native, ale, paths)["status"])

    def test_query_must_complete_while_echoed_socket_is_alive(self):
        for change in ["early", "late", "partial", "missing_summary"]:
            clients, native, ale, paths = self.fixture()
            if change == "early":
                for entry in ale[1:]:
                    entry["query_start_qpc"] = 110
            elif change == "late":
                for entry in ale[1:]:
                    entry["observed_qpc"] = 700
            elif change == "partial":
                ale[1]["complete"] = False
            else:
                ale = ale[1:]
            self.assertEqual("INCONCLUSIVE_ENDPOINT_CONTROL", self.report(clients, native, ale, paths)["status"])

    def test_failed_echo_is_control_failure(self):
        clients, native, ale, paths = self.fixture()
        clients[0]["returncode"] = 1
        self.assertEqual("FAIL_CONTROL_CLIENT", self.report(clients, native, ale, paths)["status"])

    def test_id_repetition_across_queries_is_not_same_snapshot_sharing(self):
        clients, native, ale, paths = self.fixture()
        ale.append(dict(ale[1], snapshot_id=2))
        ale[3]["snapshot_id"] = 2
        self.assertEqual([], self.report(clients, native, ale, paths)["shared_endpoint_ids"])


class InprocCleanupTests(unittest.TestCase):
    def test_cooperative_engine_exit_precedes_forced_termination(self):
        engine = mock.Mock(pid=1)
        engine.poll.return_value = None
        engine.wait.return_value = 0
        with tempfile.TemporaryDirectory() as root:
            report = lab.stop_inproc_collectors(engine, None, pathlib.Path("bin"), pathlib.Path(root))
        engine.wait.assert_called_once_with(timeout=10)
        engine.terminate.assert_not_called()
        self.assertEqual([], report["cleanup_forced_pids"])

    def test_forced_engine_exit_waits_before_bfe_fallback_restore(self):
        engine = mock.Mock(pid=1)
        engine.poll.side_effect = [None, 1]
        engine.wait.side_effect = [lab.subprocess.TimeoutExpired("engine", 10), 1]
        with tempfile.TemporaryDirectory() as root:
            out = pathlib.Path(root)
            (out / "bfe-state.json").write_text('{}')
            with mock.patch.object(lab.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as restore:
                report = lab.stop_inproc_collectors(engine, None, pathlib.Path("bin"), out)
        engine.terminate.assert_called_once()
        self.assertEqual(2, engine.wait.call_count)
        self.assertIn("--restore-state", restore.call_args.args[0])
        self.assertEqual([1], report["cleanup_forced_pids"])
        self.assertEqual(0, report["fallback_restore_exit_code"])


class PublicSummaryTests(unittest.TestCase):
    def test_scoped_benchmarks_and_live_controls_publish_only_aggregates(self):
        token = "PRIVATE-PATH-192.0.2.8"
        value = dict(status="CHARACTERIZED_ALE_APP_MISMATCH", engine="endpoint-control", benchmark_round=2,
                     enum_scope="destination", window_before_ms=5, client_hold_ms=500,
                     clients=[dict(returncode=0, nonce=token)],
                     engine_summary=dict(lookup_mode="async", enum_scope="destination", selected_app=token,
                         lookup_query_busy_ms=4.5, lookup_calls=2, success=True,
                         enum_filter="type+protocol+remote_address+remote_port",
                         enum_condition_shapes=[dict(mask=27, count=4, app_path=token)],
                         lookup_create=dict(calls=2, total_ms=4.0, max_ms=3.0, path=token),
                         added_latency_direct_ms=dict(count=3, p50=1.2, p95=2.5, max=3.0, recv_qpc=999)),
                     endpoint_control=dict(status="CHARACTERIZED_ALE_APP_MISMATCH", routing_authority=False,
                         native_reference_matches=1, endpoint_observed_clients=1, original_app_matches=0,
                         system_app_clients=1, shared_endpoint_groups=1,
                         shared_endpoint_ids=[dict(snapshot_id=77, endpoint_id=777)],
                         rows=[dict(endpoint_app_paths=[token], endpoint_ids=[777], echo_qpc=999)],
                         ale_summary=dict(queries=8, errors=0, success=True, query=dict(calls=8, total_ms=2.0))),
                     ale_ready=dict(qpc=999, abi=dict(pointer_bits=64, architecture="x64",
                         endpoint_properties_size=104, endpoint_properties_offsets=dict(appId=88, secret=token)),
                         runtime_os=dict(available=True, major=10, minor=0, build=26100, private=token)))
        result = lab.public_summary(value)
        self.assertEqual("CHARACTERIZED_ALE_APP_MISMATCH", result["status"])
        self.assertEqual("destination", result["enum_scope"])
        self.assertEqual(2, result["benchmark_round"])
        self.assertEqual(dict(total=1, success=1, failure=0), result["clients"])
        self.assertEqual(4.0, result["engine_summary"]["lookup_create"]["total_ms"])
        self.assertEqual(1, result["endpoint_control"]["system_app_clients"])
        self.assertEqual(88, result["ale_ready"]["abi"]["endpoint_properties_offsets"]["appId"])
        encoded = json.dumps(result)
        for private in (token, '"rows"', '"endpoint_ids"', '"endpoint_id"', '"snapshot_id"', '"qpc"', '"recv_qpc"'):
            self.assertNotIn(private, encoded)
        self.assertEqual(result, lab.public_summary(result))
        shadow = lab.public_summary(dict(status="INCONCLUSIVE_ALE_ENDPOINT_PROBE",
            ale_probe=dict(status="INCONCLUSIVE_ALE_ENDPOINT_PROBE", routing_authority=False,
                observed_while_held=0, native_summary=dict(source="ale_endpoint", queries=5,
                    complete_snapshots=5, errors=0, success=True))))
        self.assertEqual(shadow, lab.public_summary(shadow))

    def test_new_metric_fields_reject_strings_nonfinite_values_and_unknown_enums(self):
        result = lab.public_summary(dict(status="FAIL_ENDPOINT_CONTROL", engine="PRIVATE",
            enum_scope="PRIVATE", benchmark_round="PRIVATE", engine_summary=dict(enum_filter="PRIVATE",
                lookup_calls="PRIVATE", lookup_query_busy_ms=float("inf"),
                lookup_create=dict(total_ms=float("nan"))),
            endpoint_control=dict(native_reference_matches="PRIVATE", rows=[dict(app_path="PRIVATE")]),
            ale_ready=dict(abi=dict(architecture="PRIVATE", pointer_bits="PRIVATE"))))
        encoded = json.dumps(result)
        self.assertNotIn("PRIVATE", encoded)
        self.assertNotIn("NaN", encoded)
        self.assertNotIn("Infinity", encoded)
        self.assertEqual("FAIL_ENDPOINT_CONTROL", result["status"])

    def test_recursive_projection_excludes_raw_telemetry(self):
        token = "PRIVATE-TOKEN-192.0.2.44-C:\\private\\owner.exe"
        value = dict(status="FAIL", source="security5156", mode="redirect", protocol="tcp",
                     scenario="baseline", topology="single-host-local", selected_path=token,
                     external_target=token, error=token, anchor_filetime=1234567890123,
                     cleanup_forced_pids=[1234], clients=[dict(app=token, pid=1234, exit_code=0),
                                                        dict(app=token, exit_code=1)],
                     timing=dict(matched_client_tuples=2, rows=[dict(app_path=token, recv_qpc=123)],
                                 anchor_uncertainty_ms=.01,
                                 notification_minus_capture_ms=dict(count=2, min=-1, max=2, p50=0, p95=2, raw_xml=token)),
                     native_summary=dict(recv_qpc=123, wfp_count=2, errors=0, raw_xml=token),
                     diagnostic_events=[dict(event_type=3, flags=32, app_path_matches=True,
                                             bound_port_matches=False, raw_xml=token, path=token)])
        result = lab.public_summary(value)
        encoded = json.dumps(result)
        self.assertNotIn(token, encoded)
        for field in ["rows", "recv_qpc", "anchor_filetime", "cleanup_forced_pids", "raw_xml", "selected_path"]:
            self.assertNotIn('"' + field + '"', encoded)
        self.assertEqual(dict(total=2, success=1, failure=1), result["clients"])
        self.assertEqual("inspect_local_records", result["reason"])
        self.assertEqual(2, result["native_summary"]["wfp_count"])

    def test_string_and_numeric_type_checks_prevent_side_channels(self):
        token = "PRIVATE-PATH"
        result = lab.public_summary(dict(status=token, source=token, purpose=token,
                                         decisions=token, native_summary=dict(wfp_count=token),
                                         timing=dict(anchor_uncertainty_ms=token,
                                                     notification_minus_capture_ms=dict(min=token)),
                                         diagnostic_events=[dict(flags=token, event_type=token,
                                                                 app_path_matches=token)]))
        self.assertNotIn(token, json.dumps(result))
        self.assertEqual("UNKNOWN", result["status"])

    def test_native_unconfirmed_and_positive_control_are_preserved_safely(self):
        result = lab.public_summary(dict(status="NO_OWNERSHIP_CONFIRMATION", error="C:\\sensitive"))
        self.assertEqual("native_source_unconfirmed", result["reason"])
        positive = lab.public_summary(dict(status="PASS_BLOCKED_EVENT_CONTROL", client_exit=1,
                                           purpose="blocked-flow positive control, never an allow ownership source",
                                           matching_native_drops=2, native_summary=dict(wfp_drop_count=2)))
        self.assertEqual(2, positive["matching_native_drops"])
        self.assertEqual(1, positive["client_exit"])
        self.assertEqual("PASS_BLOCKED_EVENT_CONTROL", positive["status"])

    def test_native_inconclusive_statuses_remain_distinguishable(self):
        for status in ("INCONCLUSIVE_NO_NATIVE_EVENTS", "INCONCLUSIVE_NO_USABLE_NATIVE_EVENTS"):
            result = lab.public_summary(dict(status=status, error="PRIVATE"))
            self.assertEqual(status, result["status"])
            self.assertEqual(result, lab.public_summary(result))

    def test_already_public_counts_and_numeric_event_types_survive_aggregation(self):
        value = dict(status="PASS_RESTRICTED_CASE", clients=[dict(exit_code=0), dict(exit_code=1)],
                     native_summary=dict(wfp_callback_count=3, wfp_type_counts={"3": 2, "6": 1, "PRIVATE": 99}))
        public = lab.public_summary(value)
        self.assertEqual(public, lab.public_summary(public))
        self.assertEqual({"3": 2, "6": 1}, public["native_summary"]["wfp_type_counts"])
        self.assertEqual(3, public["native_summary"]["wfp_callback_count"])

    def test_directory_aggregation_does_not_publish_case_paths(self):
        spec = importlib.util.spec_from_file_location("lab_summarize", pathlib.Path(__file__).with_name("summarize.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case = root / "PRIVATE-PATH-192.0.2.7"
            case.mkdir()
            (case / "summary.json").write_text(json.dumps(dict(status="FAIL", error="PRIVATE-ERROR")))
            result = module.aggregate(root)
            self.assertEqual(1, result["case_count"])
            self.assertNotIn("PRIVATE", json.dumps(result))


class BridgeProtocolTests(unittest.TestCase):
    def test_consumes_http_response_preserves_early_data_and_half_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            try:
                proxy = socket.socket()
            except PermissionError:
                self.skipTest("execution sandbox prohibits sockets; run bridge protocol test on Windows runner")
            proxy.bind(("127.0.0.1", 0))
            proxy.listen()
            requests = []
            errors = []

            def serve():
                try:
                    connection, _ = proxy.accept()
                    with connection:
                        connection.settimeout(5)
                        request = b""
                        while not request.endswith(b"\r\n\r\n"):
                            request += connection.recv(1)
                        requests.append(request)
                        connection.sendall(b"HTTP/1.1 200 Connection Established\r\nX-Lab: only-proxy\r\n\r\nearly")
                        payload = b""
                        while True:
                            chunk = connection.recv(1024)
                            if not chunk:
                                break
                            payload += chunk
                        connection.sendall(payload)
                        connection.shutdown(socket.SHUT_WR)
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            manifest = dict(target_ip="127.0.0.1", proxy_host="127.0.0.1", proxy_port=proxy.getsockname()[1],
                            proxy_authorization="Basic dGVzdDp0ZXN0")
            bridge = Bridge(manifest, root / "map.jsonl", root / "bridge.jsonl")
            client = socket.socket()
            client.bind(("127.0.0.1", 0))
            mapping = dict(kind="translation", peer_ip="127.0.0.1", peer_port=client.getsockname()[1],
                           listener_ip="127.0.0.1", listener_port=bridge.port,
                           original_ip="192.0.2.4", original_port=8443, generation=123)
            (root / "map.jsonl").write_text(json.dumps(mapping) + "\n")
            bridge.start()
            try:
                client.settimeout(5)
                client.connect(("127.0.0.1", bridge.port))
                client.sendall(b"client-data")
                client.shutdown(socket.SHUT_WR)
                result = b""
                while True:
                    data = client.recv(1024)
                    if not data:
                        break
                    result += data
                self.assertEqual(b"earlyclient-data", result)
                worker.join(timeout=5)
                self.assertFalse(errors)
                self.assertTrue(requests[0].startswith(b"CONNECT 192.0.2.4:8443 HTTP/1.1\r\n"))
                self.assertIn(b"Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n", requests[0])
                self.assertEqual(1, bridge.successful_tunnels)
            finally:
                client.close()
                bridge.close()
                proxy.close()
            self.assertNotIn("dGVzdDp0ZXN0", (root / "bridge.jsonl").read_text())


if __name__ == "__main__":
    unittest.main()
