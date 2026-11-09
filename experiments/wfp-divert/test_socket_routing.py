import copy
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("socket_routing_run", pathlib.Path(__file__).with_name("run.py"))
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class SocketRoutingTests(unittest.TestCase):
    def setUp(self):
        self.paths = {app: f"\\device\\lab\\app-{app}.exe" for app in ("a", "b")}
        self.clock = (1000, 10_000_000, 1000, 2)
        self.clients, self.records = [], []
        for app, pid, port in [("a", 41, 40001), ("b", 42, 40002)]:
            attempt = dict(kind="client_attempt", local_ip="127.0.0.1", local_port=port,
                           remote_ip="127.0.0.1", remote_port=9000, protocol=6,
                           nonce=f"socket-routing-{app}", pid=pid, attempt_qpc=1100)
            reply = dict(attempt, kind="client", status="echo_ok", start_qpc=1100,
                         echo_qpc=1140 if app == "a" else 1130, done_qpc=1150)
            self.clients.append(dict(app=app, protocol="tcp", nonce=attempt["nonce"], pid=pid,
                                     process_creation_filetime=10_500_000, attempts=[attempt],
                                     results=[reply], returncode=0))
            self.records += [dict(attempt, kind="ownership", ownership_source="socket", generation=1110,
                capture_qpc=1110, app_path=self.paths[app], process_creation_filetime=10_500_000,
                socket_event_qpc=1105, socket_recv_qpc=1112, socket_app_ready_qpc=1115,
                creation_guard_valid=True, endpoint_id=pid * 10, qpc=1116, apply_qpc=1116),
                dict(attempt, kind="decision", generation=1110, capture_qpc=1110, deadline_qpc=1200,
                     qpc=1120, action="proxy" if app == "a" else "direct",
                     reason="selected" if app == "a" else "other_app")]

    def validate(self, source="socket"):
        return lab.inproc_client_evidence(self.clients, self.records, self.paths, "redirect",
                                         ownership_source=source, clock=self.clock)

    def test_command_forwards_source_and_legacy_default(self):
        args = types.SimpleNamespace(protocol="tcp", quic=False, mode="redirect", hold_ms=1000,
            seconds=35, window_before_ms=500, window_after_ms=50, leak_ms=2000, send_rst=False,
            delay_ms=0, ownership_source="socket")
        manifest = dict(target_ip="127.0.0.1", target_port=9000)
        command = [str(x) for x in lab.inproc_command(pathlib.Path("bin"), pathlib.Path("out"),
                                                     manifest, self.paths["a"], args)]
        self.assertEqual("socket", command[command.index("--ownership-source") + 1])
        del args.ownership_source
        command = [str(x) for x in lab.inproc_command(pathlib.Path("bin"), pathlib.Path("out"),
                                                     manifest, self.paths["a"], args)]
        self.assertEqual("wfp", command[command.index("--ownership-source") + 1])

    def test_socket_routing_rejects_udp_and_quic_before_startup(self):
        self.assertTrue(lab.inproc_source_supported("socket", "tcp", False))
        self.assertFalse(lab.inproc_source_supported("socket", "udp", False))
        self.assertFalse(lab.inproc_source_supported("socket", "tcp", True))
        self.assertTrue(lab.inproc_source_supported("wfp", "udp", True))

    def test_valid_socket_evidence_uses_retained_process_identity(self):
        result = self.validate()
        self.assertEqual(2, result["socket_attestation"]["matched_clients"])
        self.assertEqual(1, len(result["selected_tuples"]))

    def test_socket_cannot_accept_fabricated_wfp_time_or_source_alias(self):
        for changes in [dict(ownership_source="wfp", event_filetime=11_050_000),
                        dict(event_filetime=11_050_000), dict(creation_guard_valid=False),
                        dict(app_path="\\device\\elsewhere\\app-a.exe")]:
            with self.subTest(changes=changes):
                saved = self.records[0]
                self.records[0] = dict(saved, **changes)
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.records[0] = saved
        self.records[0].pop("ownership_source")
        self.records[0]["source"] = "socket"
        with self.assertRaises(RuntimeError):
            self.validate()

    def test_wrong_pid_creation_or_capture_cannot_authorize(self):
        for changes in [dict(pid=42), dict(process_creation_filetime=10_600_000),
                        dict(capture_qpc=1111), dict(generation=1111), dict(endpoint_id=0)]:
            with self.subTest(changes=changes):
                saved = self.records[0]
                self.records[0] = dict(saved, **changes)
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.records[0] = saved

    def test_socket_ready_apply_and_decision_must_meet_real_deadline(self):
        for changes in [dict(socket_event_qpc=1099), dict(socket_event_qpc=1111),
                        dict(socket_recv_qpc=1104), dict(socket_app_ready_qpc=1111),
                        dict(socket_app_ready_qpc=1121), dict(apply_qpc=1121), dict(qpc=1200, apply_qpc=1200)]:
            with self.subTest(changes=changes):
                saved = self.records[0]
                self.records[0] = dict(saved, **changes)
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.records[0] = saved

    def test_creation_inside_clock_uncertainty_interval_is_not_attested(self):
        for creation_qpc in [1104, 1105, 1106]:
            with self.subTest(creation_qpc=creation_qpc):
                creation = 10_000_000 + (creation_qpc - 1000) * 10_000
                self.clients[0]["process_creation_filetime"] = creation
                self.records[0]["process_creation_filetime"] = creation
                with self.assertRaises(RuntimeError):
                    self.validate()

    def test_late_socket_ownership_requires_expired_timeout_then_application(self):
        record = dict(self.records[0], qpc=1250, apply_qpc=1250)
        valid = lambda decided, deadline, owner=record: lab.socket_ownership_valid(
            owner, self.clients[0], self.clients[0]["attempts"][0], 1110,
            decided, deadline, True, self.clock)
        self.assertTrue(valid(1200, 1200))
        self.assertFalse(valid(1199, 1200))
        self.assertFalse(valid(1200, 1200, dict(record, qpc=1199, apply_qpc=1199)))

    def test_socket_cannot_weaken_wfp_ownership_guard(self):
        for record in self.records:
            if record["kind"] == "ownership":
                record["ownership_source"] = "socket"
                record["event_filetime"] = 11_050_000
        with self.assertRaises(RuntimeError):
            self.validate("wfp")

    def test_actual_client_echo_metrics_are_separate_from_packet_population(self):
        result = lab.client_latency_summary(self.clients, 1000)
        self.assertEqual(40, result["selected"]["start_to_echo_ms"]["p50"])
        self.assertEqual(30, result["direct"]["start_to_echo_ms"]["p50"])
        self.assertEqual(1, result["selected"]["clients"])
        self.assertEqual(1, result["direct"]["clients"])

    def test_inproc_iterations_are_honored_and_concurrency_is_total(self):
        args = types.SimpleNamespace(quic=False, protocol="tcp", iterations=20, concurrency=0)
        manifest = dict(target_port=9000)
        self.assertEqual(40, len(lab.inproc_client_plan(args, manifest)))
        args.concurrency = 50
        self.assertEqual(50, len(lab.inproc_client_plan(args, manifest)))

    def native_records(self):
        events = [dict(client["attempts"][0], kind="wfp", complete=True, direction="outbound", layer_id=48,
                       app_path=self.paths[client["app"]], event_filetime=11_070_000, recv_qpc=3000)
                  for client in self.clients]
        return events + [dict(kind="summary", wfp_api="poll", wfp_polls=2, errors=0, queue_dropped=0,
                              wfp_poll_errors=0, wfp_enum_errors=0, wfp_enum_truncated=False,
                              wfp_poll_interval_ms=100)]

    def test_independent_native_reference_is_fresh_before_first_capture_and_can_arrive_later(self):
        report = lab.native_reference_audit(self.clients, self.records, self.native_records(),
                                            self.paths, self.clock, 0)
        self.assertTrue(report["success"])
        self.assertEqual(2, report["matched_clients"])

    def test_reference_missing_wrong_path_or_post_capture_reinjection_cannot_confirm(self):
        for changes in [dict(app_path="System"), dict(event_filetime=11_500_000),
                        dict(layer_id=49), dict(complete=False)]:
            with self.subTest(changes=changes):
                records = self.native_records()
                records[0].update(changes)
                report = lab.native_reference_audit(self.clients, self.records, records, self.paths, self.clock, 0)
                self.assertFalse(report["success"])
                self.assertEqual(1, report["missing_clients"])
        records = self.native_records()
        records[-1]["wfp_poll_errors"] = 1
        self.assertFalse(lab.native_reference_audit(self.clients, self.records, records, self.paths, self.clock, 0)["success"])

    def test_native_reference_command_has_independent_state_and_equal_poll_cost(self):
        command = [str(value) for value in lab.native_reference_command(pathlib.Path("bin"), pathlib.Path("out"), 35)]
        self.assertEqual("100", command[command.index("--poll-interval-ms") + 1])
        for key in ["--out", "--state-out", "--stop-file"]:
            self.assertIn("native-reference", command[command.index(key) + 1])

    def test_reference_requires_the_collector_to_report_the_requested_poll_interval(self):
        for reported in [None, 5, 99, 1000, "100"]:
            with self.subTest(reported=reported):
                records = self.native_records()
                if reported is None:
                    records[-1].pop("wfp_poll_interval_ms")
                else:
                    records[-1]["wfp_poll_interval_ms"] = reported
                report = lab.native_reference_audit(self.clients, self.records, records, self.paths, self.clock, 0)
                self.assertFalse(report["success"])
                self.assertEqual(2, report["missing_clients"])

    def test_missing_reference_cause_bins_preserve_the_strict_window(self):
        for changes, cause in [(dict(layer_id=49), "wrong_layer"), (dict(app_path="System"), "no_original_app"),
                               (dict(event_filetime=11_500_000), "after_capture"),
                               (dict(event_filetime=10_900_000), "before_attempt")]:
            with self.subTest(cause=cause):
                records = self.native_records()
                records[0].update(changes)
                report = lab.native_reference_audit(self.clients, self.records, records, self.paths, self.clock, 0)
                self.assertFalse(report["success"])
                self.assertEqual(1, report["missing_causes"][cause])
                self.assertEqual(report["missing_clients"], sum(report["missing_causes"].values()))

    def test_final_enumeration_can_diagnose_poll_loss_but_cannot_replace_the_reference(self):
        packet_records = copy.deepcopy(self.records)
        packet_records[0].update(ownership_source="wfp", event_filetime=11_070_000)
        records = self.native_records()
        final = dict(records[0], kind="wfp_enum")
        records[0]["layer_id"] = 49
        report = lab.native_reference_audit(self.clients, packet_records, [final, *records], self.paths, self.clock, 0)
        self.assertFalse(report["success"])
        self.assertEqual(1, report["matched_clients"])
        self.assertEqual(1, report["diagnostic_counts"]["engine_event_missing_from_poll_clients"])
        self.assertEqual(1, report["diagnostic_counts"]["engine_event_seen_in_final_enum_clients"])
        self.assertEqual(1, report["diagnostic_counts"]["fresh_final_enum_only_clients"])

    def test_reference_diagnostics_publish_relative_boundaries_and_fixed_counts_only(self):
        records = self.native_records()
        records[0]["event_filetime"] = 11_500_000
        report = lab.native_reference_audit(self.clients, self.records, records, self.paths, self.clock, 0)
        report["missing_causes"]["PRIVATE-PATH"] = 987654321
        report["diagnostic_counts"]["pid"] = 987654321
        public = lab.public_summary(dict(status="FAIL", native_reference_audit=report))
        self.assertEqual(40, public["native_reference_audit"]["missing_reference_timing"]["nearest_original_minus_capture_ms"]["p50"])
        self.assertEqual(50, public["native_reference_audit"]["missing_reference_timing"]["nearest_original_minus_attempt_ms"]["p50"])
        self.assertEqual(public, lab.public_summary(public))
        for private in ["PRIVATE-PATH", "987654321", '"rows"', '"event_filetime"', '"capture_qpc"']:
            self.assertNotIn(private, json.dumps(public))

    def test_socket_diagnostic_count_maps_have_closed_labels_and_no_raw_values(self):
        public = lab.public_summary(dict(status="FAIL", engine_summary=dict(
            socket_diagnostics=dict(connect_changes=dict(pid_changed=2, pid=987654321),
                identity_failures=dict(creation_guard=1, image_name="PRIVATE-PATH"),
                close_context=dict(original_endpoint=1, endpoint_id=987654321),
                post_capture_connect=dict(total=3, parent_matches=1, app_path="PRIVATE-PATH")),
            socket_forward_guard_verdicts=dict(matched=4, closed=-1, remote_port=40001),
            socket_reverse_guard_verdicts=dict(stale=2, unknown="PRIVATE-PATH"))))
        engine = public["engine_summary"]
        self.assertEqual(dict(pid_changed=2), engine["socket_diagnostics"]["connect_changes"])
        self.assertEqual(dict(creation_guard=1), engine["socket_diagnostics"]["identity_failures"])
        self.assertEqual(dict(original_endpoint=1), engine["socket_diagnostics"]["close_context"])
        self.assertEqual(dict(total=3, parent_matches=1), engine["socket_diagnostics"]["post_capture_connect"])
        self.assertEqual(dict(matched=4), engine["socket_forward_guard_verdicts"])
        self.assertEqual(dict(stale=2), engine["socket_reverse_guard_verdicts"])
        self.assertEqual(public, lab.public_summary(public))
        for private in ["PRIVATE-PATH", "987654321", "40001", '"pid"', '"app_path"']:
            self.assertNotIn(private, json.dumps(public))

    def test_quarantine_projection_reports_counts_without_endpoint_records(self):
        counters = {key: index for index, key in enumerate(("socket_quarantined_connects",
            "socket_quarantined_pairs", "socket_quarantined_endpoints", "socket_quarantined_syn_rejections",
            "socket_identity_skipped_quarantine"), 1)}
        engine = dict(counters, quarantined_endpoint_ids=[987654321], quarantined_tuples=["PRIVATE-TUPLE"],
                      socket_diagnostics=dict(close_context=dict(quarantined_endpoint=2, endpoint_id=987654321),
                          post_capture_connect=dict(identity_not_requested=3, app_path="PRIVATE-PATH")))
        public = lab.public_summary(dict(status="PASS_RESTRICTED_CASE", engine_summary=engine))
        for key, count in counters.items():
            self.assertEqual(count, public["engine_summary"][key])
        self.assertEqual(2, public["engine_summary"]["socket_diagnostics"]["close_context"]["quarantined_endpoint"])
        self.assertEqual(3, public["engine_summary"]["socket_diagnostics"]["post_capture_connect"]["identity_not_requested"])
        self.assertEqual(public, lab.public_summary(public))
        for private in ["PRIVATE", "987654321", '"endpoint_id"', '"quarantined_endpoint_ids"', '"quarantined_tuples"']:
            self.assertNotIn(private, json.dumps(public))

    def test_requested_source_is_checked_in_ready_and_final_summary(self):
        self.assertTrue(lab.inproc_ready_matches(dict(kind="ready", ownership_source="socket"), "socket"))
        self.assertFalse(lab.inproc_ready_matches(dict(kind="ready", ownership_source="wfp"), "socket"))
        summary = dict(engine="inproc", success=True, decided_proxy=1, quic_drops=0,
                       ownership_source="socket", socket_clean_shutdown=True,
                       lookup_calls=0, lookup_query_count=0, lookup_returned_events=0,
                       lookup_create=dict(calls=0), lookup_enum=dict(calls=0), lookup_destroy=dict(calls=0))
        self.assertEqual("PASS_RESTRICTED_CASE", lab.inproc_evaluate(summary, "redirect", "tcp", False, 1, 1,
                                                                   expected_ownership_source="socket")[0])
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "redirect", "tcp", False, 1, 1,
                                                  expected_ownership_source="wfp")[0])
        summary["socket_history_overflow"] = 1
        self.assertEqual("FAIL", lab.inproc_evaluate(summary, "redirect", "tcp", False, 1, 1,
                                                  expected_ownership_source="socket")[0])

    def test_socket_routing_summary_rejects_any_routing_wfp_query_work(self):
        summary = dict(engine="inproc", success=True, decided_proxy=1, quic_drops=0,
                       ownership_source="socket", socket_clean_shutdown=True,
                       lookup_calls=0, lookup_query_count=0, lookup_returned_events=0,
                       lookup_create=dict(calls=0), lookup_enum=dict(calls=0), lookup_destroy=dict(calls=0))
        for key in ["lookup_calls", "lookup_query_count", "lookup_returned_events", "lookup_create", "lookup_enum", "lookup_destroy"]:
            with self.subTest(key=key):
                bad = copy.deepcopy(summary)
                bad[key] = dict(calls=1) if isinstance(bad[key], dict) else 1
                self.assertEqual("FAIL", lab.inproc_evaluate(bad, "redirect", "tcp", False, 1, 1,
                                                            expected_ownership_source="socket")[0])
        summary["ownership_source"] = "wfp"
        summary["lookup_calls"] = 2
        self.assertEqual("PASS_RESTRICTED_CASE", lab.inproc_evaluate(summary, "redirect", "tcp", False, 1, 1,
                                                                    expected_ownership_source="wfp")[0])

    def test_new_public_metrics_exclude_actual_identity_and_are_idempotent(self):
        value = dict(status="PASS_RESTRICTED_CASE", ownership_source="socket", native_reference=True,
                     sequential=True, client_latency=lab.client_latency_summary(self.clients, 1000),
                     socket_attestation=dict(matched_clients=2, pid=987654321, rows=self.records),
                     native_reference_audit=dict(success=True, matched_clients=2, missing_clients=0,
                                                 error="PRIVATE-PATH", rows=self.records),
                     engine_summary=dict(ownership_source="socket", socket_history_overflow=0,
                                         pid=987654321, app_path="PRIVATE-PATH"))
        public = lab.public_summary(value)
        self.assertEqual("socket", public["ownership_source"])
        self.assertEqual(2, public["socket_attestation"]["matched_clients"])
        self.assertEqual(40, public["client_latency"]["selected"]["start_to_echo_ms"]["p50"])
        for raw in ["PRIVATE-PATH", "987654321", '"rows"', '"pid"', '"app_path"']:
            self.assertNotIn(raw, json.dumps(public))
        self.assertEqual(public, lab.public_summary(public))

    def test_engine_restoration_finishes_before_reference_and_is_not_repeated(self):
        order = []
        engine_cleanup = dict(cleanup_forced_pids=[])
        reference_cleanup = dict(cleanup_forced_pids=[])
        with mock.patch.object(lab, "stop_inproc_collectors", side_effect=lambda *args: order.append("engine") or engine_cleanup), \
                mock.patch.object(lab, "stop_native_reference", side_effect=lambda *args: order.append("reference") or reference_cleanup):
            reports = lab.finish_routing_collectors(object(), None, object(), pathlib.Path("bin"), pathlib.Path("out"))
            lab.finish_routing_collectors(object(), None, object(), pathlib.Path("bin"), pathlib.Path("out"), *reports)
        self.assertEqual(["engine", "reference"], order)

    def test_reference_cleanup_failure_is_public_without_process_ids_or_error_text(self):
        summary = lab.public_summary(dict(status="FAIL", native_reference_cleanup=dict(
            cleanup_forced_pids=[987654321, 987654322], fallback_restore_error="PRIVATE-PATH")))
        self.assertEqual(2, summary["native_reference_cleanup"]["forced_processes"])
        self.assertTrue(summary["native_reference_cleanup"]["fallback_restore_failed"])
        self.assertFalse(summary["native_reference_cleanup"]["success"])
        self.assertEqual(summary, lab.public_summary(summary))
        self.assertNotIn("PRIVATE", json.dumps(summary))
        self.assertNotIn("987654321", json.dumps(summary))

    def test_public_failure_stage_is_closed_and_preserved_without_exception_text(self):
        for stage in ["client_attestation", "native_reference", "gateway", "engine_complete", "engine_evaluation", "cleanup"]:
            with self.subTest(stage=stage):
                summary = lab.public_summary(dict(status="FAIL", validation_stage=stage, failure_stage=stage,
                                                  error="PRIVATE-PATH-DETAILS", pid=987654321))
                self.assertEqual(stage, summary["failure_stage"])
                self.assertEqual(stage, summary["validation_stage"])
                self.assertEqual(summary, lab.public_summary(summary))
                self.assertNotIn("PRIVATE", json.dumps(summary))
                self.assertNotIn("987654321", json.dumps(summary))
        summary = lab.public_summary(dict(status="FAIL", validation_stage="PRIVATE-PATH", failure_stage="PRIVATE-PATH"))
        self.assertNotIn("failure_stage", summary)
        self.assertNotIn("validation_stage", summary)

    def test_start_barrier_releases_only_a_ready_live_cohort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            start = root / "clients.start"
            clients = []
            for index in range(2):
                ready = root / f"client-{index}.ready"
                ready.touch()
                clients.append(dict(ready_file=ready, process=mock.Mock(poll=mock.Mock(return_value=None))))
            checked = []
            self.assertEqual(2, lab.release_client_start_barrier(clients, start, lambda: checked.append(start.exists())))
            self.assertEqual([False], checked)
            self.assertTrue(start.exists())
            start.unlink()
            clients[0]["process"].poll.return_value = 1
            with self.assertRaises(RuntimeError):
                lab.release_client_start_barrier(clients, start, lambda: None)
            self.assertFalse(start.exists())


if __name__ == "__main__":
    unittest.main()
