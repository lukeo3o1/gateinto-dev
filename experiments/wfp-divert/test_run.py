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


class PublicSummaryTests(unittest.TestCase):
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
