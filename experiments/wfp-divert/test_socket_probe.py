import copy
import importlib.util
import json
import pathlib
import unittest


SPEC = importlib.util.spec_from_file_location("socket_probe", pathlib.Path(__file__).with_name("socket_probe.py"))
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class SocketObservationTests(unittest.TestCase):
    def setUp(self):
        self.key = dict(local_ip="127.0.0.1", local_port=40001, remote_ip="127.0.0.1",
                        remote_port=443, protocol=6)
        self.paths = {"a": dict(dos="C:\\lab\\app-a.exe", native="\\device\\lab\\app-a.exe")}
        self.client = dict(app="a", nonce="socket-a-0", pid=41, process_creation_filetime=10_500_000,
                           returncode=0, expected_hold_ms=0,
                           attempts=[dict(self.key, kind="client_attempt", pid=41, attempt_qpc=1100,
                                          nonce="socket-a-0")],
                           results=[dict(self.key, kind="client", pid=41, nonce="socket-a-0", status="echo_ok",
                                         start_qpc=1100, echo_qpc=1120, hold_end_qpc=1120,
                                         hold_open_ms=0, done_qpc=1130)])
        self.socket = dict(self.key, kind="socket_event", event_name="connect", pid=41,
                           outbound=False, ipv6=False, event_qpc=1105, recv_qpc=1115, app_ready_qpc=1125,
                           app_path=self.paths["a"]["dos"], process_creation_filetime=10_500_000,
                           app_path_status="ok", identity_valid=True, lookup_error=0)
        self.packet = dict(self.key, kind="packet", outbound=True, ipv6=False, capture_qpc=1110,
                           event_qpc=1110, recv_qpc=1140, tcp_syn=True, tcp_ack=False)
        self.ready = dict(kind="ready", source="socket_probe", qpc_frequency=1000,
                          socket_ready=True, network_ready=True, capture_only=True, routing_authority=False)
        self.socket_summary = dict(kind="summary", source="socket_probe", success=True, errors=0,
                                   queue_dropped=0, output_errors=0, truncated=False,
                                   capture_only=True, routing_authority=False, driver_queue_loss_known=False)
        self.native = dict(self.key, kind="wfp", complete=True, direction="outbound", layer_id=48,
                           app_path=self.paths["a"]["native"], event_filetime=11_070_000, recv_qpc=1200)
        self.native_summary = dict(kind="summary", wfp_api="poll", wfp_count=1, wfp_polls=4,
                                   errors=0, queue_dropped=0, wfp_poll_errors=0,
                                   wfp_enum_errors=0, wfp_enum_truncated=False)

    def evaluate(self, clients=None, events=None, native=None, expected_socket_filter=None):
        return probe.evaluate_probe(clients or [self.client],
            [self.ready, *(events if events is not None else [self.socket, self.packet]), self.socket_summary],
            (native if native is not None else [self.native]) + [self.native_summary],
            self.paths, 1000, 10_000_000, 1000, 2, expected_socket_filter=expected_socket_filter)

    def test_exact_pid_tuple_and_independent_native_reference_pass(self):
        result = self.evaluate()
        self.assertEqual("PASS_SOCKET_OBSERVATION", result["status"])
        self.assertEqual(1, result["counts"]["socket_connect_pid_matches"])
        self.assertEqual(1, result["counts"]["app_path_usable_clients"])
        self.assertFalse(result["driver_queue_loss_known"])

    def test_capture_receipt_and_identity_readiness_are_separate(self):
        result = self.evaluate()
        timing = result["timing"]
        self.assertEqual(-5, timing["socket_event_minus_network_capture_ms"]["p95"])
        self.assertEqual(5, timing["socket_recv_minus_network_capture_ms"]["p95"])
        self.assertEqual(15, timing["socket_app_ready_minus_network_capture_ms"]["p95"])
        self.assertEqual(1, timing["socket_event_before_network_capture"]["count"])
        self.assertEqual(0, timing["socket_app_ready_before_network_capture"]["count"])
        self.assertEqual(1, timing["socket_app_ready_before_network_recv"]["count"])

    def test_first_network_receipt_is_measured_separately_from_first_capture(self):
        self.socket["app_ready_qpc"] = 1135
        second_packet = dict(self.packet, capture_qpc=1111, event_qpc=1111, recv_qpc=1130)
        result = self.evaluate(events=[self.socket, self.packet, second_packet])
        self.assertEqual(5, result["timing"]["socket_app_ready_minus_network_recv_ms"]["p95"])
        self.assertEqual(0, result["timing"]["socket_app_ready_before_network_recv"]["count"])

    def test_wrong_event_pid_never_matches(self):
        self.socket["pid"] = 42
        result = self.evaluate()
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", result["status"])
        self.assertEqual(0, result["counts"]["socket_connect_pid_matches"])
        self.assertEqual(1, result["counts"]["socket_pid_mismatch_clients"])

    def test_client_report_pid_must_match_retained_popen_pid(self):
        self.client["results"][0]["pid"] = 42
        self.assertEqual("FAIL_SOCKET_PROBE", self.evaluate()["status"])

    def test_full_tuple_and_event_time_cannot_be_replaced_by_pid(self):
        for changes in [dict(local_port=40002), dict(remote_ip="127.0.0.2"),
                        dict(event_qpc=1099), dict(event_qpc=1131), dict(protocol=17)]:
            with self.subTest(changes=changes):
                event = dict(self.socket, **changes)
                self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate(events=[event, self.packet])["status"])

    def test_bind_close_accept_and_arbitrary_frames_cannot_substitute_for_connect(self):
        for changes in [dict(event_name="bind"), dict(event_name="close"), dict(event_name="accept"),
                        dict(kind="packet"), dict(kind="untrusted")]:
            with self.subTest(changes=changes):
                self.assertEqual("INCONCLUSIVE_SOCKET_PROBE",
                    self.evaluate(events=[dict(self.socket, **changes), self.packet])["status"])

    def test_udp_requires_the_remote_tuple_not_just_a_bind(self):
        self.key["protocol"] = 17
        for value in [self.socket, self.packet, self.native, *self.client["attempts"], *self.client["results"]]:
            value["protocol"] = 17
        self.assertEqual("PASS_SOCKET_OBSERVATION", self.evaluate()["status"])
        self.socket["remote_port"] = 0
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])

    def test_missing_packet_or_noninitial_tcp_packet_is_inconclusive(self):
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate(events=[self.socket])["status"])
        self.packet["tcp_ack"] = True
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])

    def test_native_path_and_layer_are_required_even_if_socket_pid_matches(self):
        for changes in [dict(app_path=""), dict(app_path="\\device\\elsewhere\\app-a.exe"),
                        dict(layer_id=49), dict(complete=False), dict(direction="inbound"),
                        dict(event_filetime=1)]:
            with self.subTest(changes=changes):
                self.assertEqual("INCONCLUSIVE_SOCKET_PROBE",
                    self.evaluate(native=[dict(self.native, **changes)])["status"])

    def test_native_and_output_queue_errors_prevent_pass(self):
        for key in ["wfp_poll_errors", "wfp_enum_errors", "queue_dropped", "errors"]:
            with self.subTest(key=key):
                self.native_summary[key] = 1
                self.assertEqual("FAIL_SOCKET_PROBE", self.evaluate()["status"])
                self.native_summary[key] = 0
        self.socket_summary["output_errors"] = 1
        self.assertEqual("FAIL_SOCKET_PROBE", self.evaluate()["status"])

    def test_fast_exit_lookup_failure_preserves_pid_coverage_but_no_path_ready_metric(self):
        self.socket.update(app_path="", identity_valid=False, app_path_status="open_process_failed",
                           lookup_error=87, process_creation_filetime=None)
        result = self.evaluate()
        self.assertEqual("PASS_SOCKET_OBSERVATION", result["status"])
        self.assertEqual(1, result["counts"]["app_path_missing_clients"])
        self.assertEqual(0, result["counts"]["app_path_mismatch_clients"])
        self.assertEqual(0, result["timing"]["socket_app_ready_minus_network_capture_ms"]["count"])

    def test_failed_generation_guard_cannot_supply_path_readiness(self):
        self.socket.update(identity_valid=False, app_path_status="creation_time_uncertain")
        result = self.evaluate()
        self.assertEqual(0, result["counts"]["app_path_usable_clients"])
        self.assertEqual(0, result["timing"]["socket_app_ready_minus_network_capture_ms"]["count"])

    def test_successful_identity_lookup_requires_consistent_ready_time(self):
        for ready in [None, 0, 1114]:
            with self.subTest(ready=ready):
                self.socket["app_ready_qpc"] = ready
                result = self.evaluate()
                self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", result["status"])
                self.assertEqual(1, result["counts"]["invalid_timing_clients"])

    def test_reused_process_lookup_is_ambiguous_even_when_pid_matches(self):
        self.socket["process_creation_filetime"] = 12_000_000
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])
        self.socket["process_creation_filetime"] = 10_600_000
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])

    def test_conflicting_native_or_socket_identity_is_not_hidden_by_one_good_match(self):
        conflict = dict(self.socket, app_path="C:\\elsewhere\\app-a.exe")
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate(events=[self.socket, conflict, self.packet])["status"])
        native = dict(self.native, app_path="\\device\\elsewhere\\app-a.exe")
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate(native=[self.native, native])["status"])

    def test_reused_full_client_tuple_is_ambiguous(self):
        second = copy.deepcopy(self.client)
        second["nonce"] = "socket-a-1"
        second["attempts"][0]["nonce"] = second["results"][0]["nonce"] = second["nonce"]
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate(clients=[self.client, second])["status"])

    def test_inverted_capture_receipt_is_not_a_pre_packet_identity(self):
        self.socket["recv_qpc"] = 1104
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])
        self.socket["recv_qpc"] = 1115
        self.packet["recv_qpc"] = 1109
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", self.evaluate()["status"])

    def test_projection_never_exposes_identities_or_arbitrary_nested_strings(self):
        result = self.evaluate()
        result.update(error="PRIVATE-PATH-SECRET", stdout="PRIVATE-STDOUT", pid=987654321,
                      endpoint_id=987654321, app_path="PRIVATE-PATH-SECRET", qpc=987654321)
        result["counts"]["pid"] = 987654321
        result["timing"]["raw"] = dict(path="PRIVATE-PATH-SECRET")
        result["socket_summary"]["error"] = "PRIVATE-PATH-SECRET"
        projected = probe.socket_public_summary(result)
        text = json.dumps(projected)
        for secret in ["PRIVATE-PATH-SECRET", "PRIVATE-STDOUT", "987654321", "40001", "127.0.0.1", "socket-a-0"]:
            self.assertNotIn(secret, text)
        self.assertNotIn("rows", projected)
        self.assertEqual("PASS_SOCKET_OBSERVATION", projected["status"])

    def test_projection_rejects_nonfinite_or_string_metrics_and_unapproved_status(self):
        projected = probe.socket_public_summary(dict(status="PRIVATE-ERROR", protocol="PRIVATE-PATH",
            counts=dict(client_total="PRIVATE-PATH"),
            timing=dict(socket_recv_minus_network_capture_ms=dict(count=1, p95=float("nan"), max="PRIVATE-PATH"))))
        self.assertEqual("NOT_COMPLETED", projected["status"])
        self.assertNotIn("PRIVATE", json.dumps(projected))
        self.assertNotIn("NaN", json.dumps(projected))

    def test_plan_distinguishes_pairs_from_burst_total(self):
        self.assertEqual(40, len(probe.client_plan(20, 0)))
        burst = probe.client_plan(20, 50)
        self.assertEqual(50, len(burst))
        self.assertEqual(25, sum(app == "a" for app, _ in burst))

    def test_fixture_uses_first_udp_port_and_distinct_tcp_target(self):
        manifest = dict(target_port=41000, udp_ports=[42000, 42001])
        self.assertEqual(41000, probe.fixture_port(manifest, "tcp"))
        self.assertEqual(42000, probe.fixture_port(manifest, "udp"))

    def test_socket_filter_profile_is_forwarded_to_native_collector(self):
        manifest = dict(target_ip="127.0.0.1", target_port=41000, udp_ports=[42000, 42001])
        for profile in ["scoped", "connect"]:
            command = [str(value) for value in probe.socket_command(
                pathlib.Path("bin"), pathlib.Path("out"), manifest, "udp", 35, profile)]
            self.assertEqual(profile, command[command.index("--socket-filter") + 1])
            self.assertEqual("42000", command[command.index("--port") + 1])
            self.assertEqual("udp", command[command.index("--protocol") + 1])
        default = [str(value) for value in probe.socket_command(
            pathlib.Path("bin"), pathlib.Path("out"), manifest, "tcp", 35)]
        self.assertEqual("scoped", default[default.index("--socket-filter") + 1])

    def test_public_projection_preserves_only_fixed_socket_filter_profiles(self):
        for profile in ["scoped", "connect"]:
            summary = probe.socket_public_summary(dict(status="NOT_COMPLETED", socket_filter=profile))
            self.assertEqual(profile, summary["socket_filter"])
            self.assertEqual(summary, probe.socket_public_summary(summary))
        self.assertNotIn("socket_filter", probe.socket_public_summary(dict(socket_filter="PRIVATE-PATH")))

    def test_zero_received_socket_events_has_a_fixed_public_reason(self):
        self.socket_summary["socket_received"] = 0
        result = self.evaluate(events=[self.packet])
        self.assertEqual("INCONCLUSIVE_SOCKET_PROBE", result["status"])
        self.assertEqual("no_socket_events", result["reason"])
        self.assertEqual("no_socket_events", probe.socket_public_summary(result)["reason"])

    def test_broad_control_projection_keeps_only_fixed_numeric_predicate_counts(self):
        keys = ("socket_protocol_matches", "socket_ipv4_matches", "socket_ipv4_mapped_matches",
                "socket_remote_address_matches", "socket_remote_port_matches", "socket_scope_matches",
                "socket_unrelated_discarded")
        summary = dict(socket_summary={key: 3 for key in keys})
        summary["socket_summary"].update(remote_port=42000, app_path="PRIVATE-PATH", unknown_predicate=123)
        result = probe.socket_public_summary(summary)
        self.assertEqual({key: 3 for key in keys}, result["socket_summary"])

    def test_requested_filter_requires_matching_ready_and_final_profile(self):
        self.ready["socket_filter"] = self.socket_summary["socket_filter"] = "scoped"
        self.assertEqual("PASS_SOCKET_OBSERVATION", self.evaluate(expected_socket_filter="scoped")["status"])
        for record in [self.ready, self.socket_summary]:
            for reported in [None, "connect", "PRIVATE-PATH"]:
                with self.subTest(record=record["kind"], reported=reported):
                    if reported is None:
                        record.pop("socket_filter", None)
                    else:
                        record["socket_filter"] = reported
                    result = self.evaluate(expected_socket_filter="scoped")
                    self.assertEqual("FAIL_SOCKET_PROBE", result["status"])
                    self.assertEqual("filter_profile_mismatch", result["reason"])
                    self.assertEqual("filter_profile_mismatch", probe.socket_public_summary(result)["reason"])
                    record["socket_filter"] = "scoped"
        self.ready["socket_filter"] = self.socket_summary["socket_filter"] = "connect"
        self.assertEqual("PASS_SOCKET_OBSERVATION", self.evaluate(expected_socket_filter="connect")["status"])


if __name__ == "__main__":
    unittest.main()
