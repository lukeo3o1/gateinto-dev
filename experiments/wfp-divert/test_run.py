import importlib.util
import pathlib
import json
import socket
import sys
import tempfile
import threading
import unittest


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
                    window_after_ms=50, leak_ms=2000, send_rst=True, quic=False)
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
