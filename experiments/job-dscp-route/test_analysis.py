import copy
import json
import unittest

import analysis

R = "192.0.2.10"
OTHER = "192.0.2.11"
PORTS = {"untagged": (50001, 50002, 50003), "tagged-a": (50011, 50012, 50013), "tagged-b": (50021, 50022, 50023),
         "tagged-no-engine": (50031, 50032, 50033)}
BRIDGE_PORT = 8443
DSCP = {"tagged-a": 10, "tagged-b": 20, "tagged-no-engine": 10}


def curl(code=200, port=50000, remote=R, connect=0.02, appconnect=0.05, total=0.1):
    return dict(http_code=code, local_port=port, remote_ip=remote, num_connects=1, time_connect=connect,
                time_appconnect=appconnect, time_total=total)


def launch(dscp, exit_code=0, **overrides):
    record = dict(kind="launch", dscp=dscp, job_created=True, job_error=0, kill_on_close_set=True,
                  kill_on_close_error=0, dscp_set=True, dscp_error=0, readback_ok=True, readback_error=0,
                  readback_flags=5, readback_dscp=dscp, redirected=True, redirect_ok=True, redirect_error=0,
                  process_created=True, process_error=0, assigned=True, assign_error=0, resumed=True,
                  resume_error=0, child_ran=True, child_exit_code=exit_code)
    record.update(overrides)
    return record


def attempts(role, exit_code=0, code=200, **launch_overrides):
    result = []
    for index, port in enumerate(PORTS[role]):
        item = dict(role=role, index=index, exit_code=exit_code, timed_out=False, skipped=None,
                    curl=curl(code=code, port=port))
        if role in DSCP:
            item["launch"] = launch(DSCP[role], exit_code, **launch_overrides)
        result.append(item)
    return result


def engine(**counters):
    summary = dict(kind="summary", captured=40, new_flows=6, reflected=20, replies_restored=20, syn_retransmits=0,
                   send_errors=0, recv_errors=0, checksum_errors=0, orphan_dropped=0, key_collisions=0,
                   unknown_reply_dropped=0, fragment_dropped=0, malformed_dropped=0, table_full=0,
                   map_write_errors=0, open_error=0, param_errors=0, shutdown_error=0, last_error=0,
                   timed_out=False, stop_timeout=False)
    summary.update(counters)
    return dict(ready=True, exit_code=0, summary=summary)


def wire(src_port, dst=R, dport=443, syn=False):
    return dict(v=4, proto=6, src="10.1.0.4", dst=dst, sport=src_port, dport=dport, tos=0, syn=syn, ack=not syn)


def nic_ok(extra=()):
    packets = [wire(port, syn=index == 0) for port in PORTS["untagged"] for index in range(3)]
    packets += [wire(40000), dict(wire(443, dst="10.1.0.4"), src=R)]
    return dict(status="ok", packets=packets + list(extra))


def routed_input():
    runs = attempts("untagged") + attempts("tagged-a") + attempts("tagged-b")
    return dict(precondition=None, target_ip=R, attempts=runs, baseline=attempts("tagged-no-engine"),
                gateway=dict(read=True, lines=[f"CONNECT {R}:443 HTTP/1.1"] * 6),
                bridge=dict(started=True, close_ok=True, accepted=6, tunnels=6, errors=0, error_kinds={}),
                engine=engine(), firewall="added", nic=nic_ok(), bridge_port=BRIDGE_PORT)


def with_role(value, role, replacement):
    value["attempts"] = [a for a in value["attempts"] if a["role"] != role] + replacement
    return value


class CurlOutputTests(unittest.TestCase):
    def test_parses_the_write_out_object(self):
        text = ('{"http_code":"301","local_port":"50011","remote_ip":"192.0.2.10","num_connects":"1",'
                '"time_connect":"0.012000","time_appconnect":"0.040500","time_total":"0.100000"}')
        self.assertEqual(dict(http_code=301, local_port=50011, remote_ip=R, num_connects=1, time_connect=0.012,
                              time_appconnect=0.0405, time_total=0.1), analysis.parse_curl_output(text))

    def test_failed_transfer_fields(self):
        text = ('{"http_code":"000","local_port":"0","remote_ip":"","num_connects":"0","time_connect":"0.000000",'
                '"time_appconnect":"0.000000","time_total":"10.0"}')
        parsed = analysis.parse_curl_output(text)
        self.assertEqual(0, parsed["http_code"])
        self.assertIsNone(parsed["local_port"])
        self.assertIsNone(parsed["remote_ip"])

    def test_invalid_output(self):
        for text in ("", "garbage", "[1]", None, '{"http_code":"x"}'):
            parsed = analysis.parse_curl_output(text)
            self.assertTrue(parsed is None or parsed["http_code"] is None, text)
        self.assertIsNone(analysis.parse_curl_output("garbage"))
        parsed = analysis.parse_curl_output('{"time_total":"inf","http_code":"200"}\n')
        self.assertIsNone(parsed["time_total"])
        self.assertEqual(200, parsed["http_code"])

    def test_last_object_wins(self):
        text = '{"http_code":"500"}\nnoise\n{"http_code":"200"}\n'
        self.assertEqual(200, analysis.parse_curl_output(text)["http_code"])

    def test_status_classes(self):
        self.assertEqual(["2xx", "3xx", "4xx", "5xx", "1xx", "none", "none", "other"],
                         [analysis.status_class(code) for code in (200, 301, 404, 503, 101, 0, None, 999)])


class GatewayTests(unittest.TestCase):
    def test_exact_target_matching(self):
        lines = [f"CONNECT {R}:443 HTTP/1.1", f"CONNECT {R}:4430 HTTP/1.1", f"CONNECT {OTHER}:443 HTTP/1.1",
                 f"CONNECT {R}:443 HTTP/1.0", f"GET http://{R}/ HTTP/1.1", f"CONNECT {R}:443 HTTP/1.1"]
        self.assertEqual(dict(read=True, total=6, target=2, other=4),
                         analysis.gateway_counts(dict(read=True, lines=lines), R))

    def test_unreadable_log(self):
        self.assertEqual(dict(read=False, total=0, target=0, other=0),
                         analysis.gateway_counts(dict(read=False, lines=[]), R))
        self.assertEqual(dict(read=False, total=0, target=0, other=0), analysis.gateway_counts(None, R))


class NicTests(unittest.TestCase):
    def test_attribution_by_role_local_port(self):
        value = routed_input()
        nic = analysis.nic_projection(nic_ok(extra=[wire(PORTS["tagged-a"][0]), wire(PORTS["tagged-b"][1], syn=True)]),
                                      value["attempts"], R, BRIDGE_PORT)
        self.assertEqual("ok", nic["status"])
        self.assertEqual(dict(untagged=9, **{"tagged-a": 1, "tagged-b": 1}), nic["roles"])
        self.assertEqual(dict(untagged=3, **{"tagged-a": 0, "tagged-b": 1}), nic["syns"])
        self.assertEqual(3, nic["untagged_attempts_on_wire"])
        self.assertEqual(1, nic["other_packets"])
        self.assertEqual(0, nic["bridge_segments_on_wire"])
        self.assertEqual(0, nic["port_collisions"])

    def test_bridge_segments_are_counted_separately(self):
        value = routed_input()
        nic = analysis.nic_projection(nic_ok(extra=[wire(BRIDGE_PORT, dport=PORTS["tagged-a"][0])] * 2),
                                      value["attempts"], R, BRIDGE_PORT)
        self.assertEqual(2, nic["bridge_segments_on_wire"])
        self.assertEqual(1, nic["other_packets"])

    def test_only_packets_toward_the_target_count(self):
        value = routed_input()
        packets = [wire(PORTS["tagged-a"][0], dst=OTHER), wire(PORTS["tagged-a"][0], dport=80)]
        nic = analysis.nic_projection(dict(status="ok", packets=packets), value["attempts"], R, BRIDGE_PORT)
        self.assertEqual(0, nic["roles"]["tagged-a"])
        self.assertEqual(1, nic["other_packets"])

    def test_unavailable_capture(self):
        self.assertEqual(dict(status="unavailable", step="start", exit_code=5),
                         analysis.nic_projection(dict(status="unavailable", step="start", exit_code=5), [], R))
        self.assertEqual(dict(status="unavailable", step="other"),
                         analysis.nic_projection(dict(status="unavailable", step="C:\\x"), [], R))
        self.assertEqual(dict(status="not_run"), analysis.nic_projection(None, [], R))


class JobTests(unittest.TestCase):
    def test_job_setup(self):
        self.assertTrue(analysis.job_setup_ok(launch(10), 10))
        self.assertFalse(analysis.job_setup_ok(launch(10, resumed=False), 10))
        self.assertTrue(analysis.job_setup_ok(dict(launch(10, resumed=False), kind="launch_setup"), 10))
        self.assertFalse(analysis.job_setup_ok(dict(launch(10, assigned=False), kind="launch_setup"), 10))
        self.assertFalse(analysis.job_setup_ok(launch(10), 20))
        self.assertFalse(analysis.job_setup_ok(launch(10, dscp_set=False, dscp_error=87), 10))
        self.assertFalse(analysis.job_setup_ok(launch(10, readback_flags=1), 10))
        self.assertFalse(analysis.job_setup_ok(launch(10, redirect_ok=False), 10))
        self.assertFalse(analysis.job_setup_ok(None, 10))

    def test_job_projection_counts_steps_and_error_codes(self):
        runs = attempts("tagged-a")
        runs[0]["launch"] = launch(10, dscp_set=False, dscp_error=87)
        stats = analysis.role_stats(runs, R, 10)
        self.assertEqual(2, stats["job"]["setup_ok"])
        self.assertEqual(2, stats["job"]["steps"]["dscp_set"])
        self.assertEqual({"dscp_error": {"87": 1}}, stats["job"]["errors"])


class RoleStatsTests(unittest.TestCase):
    def test_histograms_and_medians(self):
        runs = attempts("untagged")
        runs[1]["curl"] = curl(code=301, port=50002, connect=0.03, appconnect=0.07, total=0.3)
        runs[2].update(exit_code=28, curl=curl(code=0, port=50003, remote=None, connect=0, appconnect=0, total=25))
        stats = analysis.role_stats(runs, R)
        self.assertEqual(3, stats["attempts"])
        self.assertEqual(2, stats["succeeded"])
        self.assertEqual({"0": 2, "28": 1}, stats["curl_exit_codes"])
        self.assertEqual({"2xx": 1, "3xx": 1, "none": 1}, stats["http_status_classes"])
        self.assertEqual(2, stats["remote_matches"])
        self.assertEqual(25.0, stats["median_time_connect_ms"])
        self.assertEqual(60.0, stats["median_time_appconnect_ms"])
        self.assertEqual(200.0, stats["median_time_total_ms"])
        self.assertNotIn("job", stats)

    def test_timeouts_and_skips(self):
        runs = attempts("untagged")
        runs[0].update(exit_code=None, timed_out=True, curl=None)
        runs[1].update(exit_code=None, skipped="deadline", curl=None)
        stats = analysis.role_stats(runs, R)
        self.assertEqual(1, stats["timed_out"])
        self.assertEqual(1, stats["skipped"])
        self.assertEqual({"0": 1, "none": 1}, stats["curl_exit_codes"])
        self.assertEqual(1, stats["output_parsed"])


class VerdictTests(unittest.TestCase):
    def verdict(self, value):
        result = analysis.analyze(value)
        analysis.validate_public(result)
        return result

    def test_routed_via_gateway(self):
        result = self.verdict(routed_input())
        self.assertEqual("ROUTED_VIA_GATEWAY", result["verdict"])
        self.assertTrue(result["nic_confirmed"])
        self.assertEqual(6, result["tagged_attempts"])
        self.assertEqual(dict(read=True, total=6, target=6, other=0), result["gateway"])

    def test_routed_without_nic_capture(self):
        value = routed_input()
        value["nic"] = dict(status="unavailable", step="start", exit_code=1)
        result = self.verdict(value)
        self.assertEqual("ROUTED_VIA_GATEWAY", result["verdict"])
        self.assertIsNone(result["nic_confirmed"])

    def test_tagged_syn_on_the_wire_downgrades_to_partial(self):
        value = routed_input()
        value["nic"] = nic_ok(extra=[wire(PORTS["tagged-b"][2], syn=True)])
        result = self.verdict(value)
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertFalse(result["nic_confirmed"])

    def test_late_tagged_non_syn_packet_is_published_but_not_a_leak(self):
        value = routed_input()
        value["nic"] = nic_ok(extra=[wire(PORTS["tagged-b"][2])])
        result = self.verdict(value)
        self.assertEqual("ROUTED_VIA_GATEWAY", result["verdict"])
        self.assertTrue(result["nic_confirmed"])
        self.assertEqual((1, 0), (result["nic"]["roles"]["tagged-b"], result["nic"]["syns"]["tagged-b"]))

    def test_bridge_segment_on_the_wire_downgrades_to_partial(self):
        value = routed_input()
        value["nic"] = nic_ok(extra=[wire(BRIDGE_PORT, dport=PORTS["tagged-a"][0])])
        result = self.verdict(value)
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertFalse(result["nic_confirmed"])

    def test_untagged_attempt_missing_from_the_wire_downgrades_to_partial(self):
        value = routed_input()
        value["nic"] = dict(status="ok", packets=[wire(PORTS["untagged"][0])])
        result = self.verdict(value)
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertFalse(result["nic_confirmed"])

    def test_not_routed(self):
        value = routed_input()
        value["gateway"] = dict(read=True, lines=[])
        value["engine"] = engine(new_flows=0, captured=0, reflected=0, replies_restored=0)
        self.assertEqual("NOT_ROUTED", self.verdict(value)["verdict"])

    def test_routing_broke_tagged(self):
        value = routed_input()
        with_role(value, "tagged-a", attempts("tagged-a", exit_code=28, code=0))
        with_role(value, "tagged-b", attempts("tagged-b", exit_code=35, code=0))
        self.assertEqual("ROUTING_BROKE_TAGGED", self.verdict(value)["verdict"])

    def test_partial_cases(self):
        one_failed = routed_input()
        failed = attempts("tagged-b")
        failed[1].update(exit_code=28, launch=launch(20, 28), curl=curl(code=0, port=50022))
        with_role(one_failed, "tagged-b", failed)
        extra_connect = routed_input()
        extra_connect["gateway"]["lines"].append(f"CONNECT {OTHER}:80 HTTP/1.1")
        collision = routed_input()
        collision["engine"] = engine(key_collisions=1)
        send_error = routed_input()
        send_error["engine"] = engine(send_errors=2)
        extra_flow = routed_input()
        extra_flow["engine"] = engine(new_flows=7)
        untagged_failed = routed_input()
        failed = attempts("untagged")
        failed[0].update(exit_code=7, curl=curl(code=0, port=50001))
        with_role(untagged_failed, "untagged", failed)
        missing_connect = routed_input()
        missing_connect["gateway"]["lines"].pop()
        for name, value in [("one tagged failed", one_failed), ("extra connect", extra_connect),
                            ("collision", collision), ("send error", send_error),
                            ("extra flow", extra_flow), ("untagged failed", untagged_failed),
                            ("missing connect", missing_connect)]:
            self.assertEqual("PARTIAL", self.verdict(value)["verdict"], name)

    def test_orphans_and_retransmits_are_anomalies_only(self):
        value = routed_input()
        value["engine"] = engine(orphan_dropped=3, syn_retransmits=2)
        result = self.verdict(value)
        self.assertEqual("ROUTED_VIA_GATEWAY", result["verdict"])
        self.assertEqual((3, 2), (result["engine"]["orphan_dropped"], result["engine"]["syn_retransmits"]))

    def test_failed_firewall_rule(self):
        value = routed_input()
        value["firewall"] = "failed"
        result = self.verdict(value)
        self.assertEqual(("ROUTED_VIA_GATEWAY", "failed"), (result["verdict"], result["firewall"]))
        with_role(value, "tagged-a", attempts("tagged-a", exit_code=28, code=0))
        with_role(value, "tagged-b", attempts("tagged-b", exit_code=28, code=0))
        self.assertEqual("INCONCLUSIVE_FIREWALL_RULE_FAILED", self.verdict(value)["verdict"])
        value["firewall"] = "added"
        self.assertEqual("ROUTING_BROKE_TAGGED", self.verdict(value)["verdict"])

    def test_timed_out_attempt_with_a_good_setup_record_is_a_failed_attempt(self):
        value = routed_input()
        runs = attempts("tagged-a")
        setup = {k: v for k, v in launch(10).items() if k not in ("child_ran", "child_exit_code")}
        setup.update(kind="launch_setup", resumed=False)
        runs[1].update(exit_code=None, timed_out=True, curl=None, launch=setup)
        with_role(value, "tagged-a", runs)
        value["gateway"]["lines"].pop()
        value["engine"] = engine(new_flows=5)
        result = self.verdict(value)
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertEqual(3, result["roles"]["tagged-a"]["job"]["setup_ok"])

    def test_target_unreachable(self):
        value = routed_input()
        value["precondition"] = "INCONCLUSIVE_TARGET_UNREACHABLE"
        self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", self.verdict(value)["verdict"])
        value = routed_input()
        with_role(value, "untagged", attempts("untagged", exit_code=7, code=0))
        self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", self.verdict(value)["verdict"])

    def test_job_setup_failed(self):
        value = routed_input()
        with_role(value, "tagged-b", attempts("tagged-b", dscp_set=False, dscp_error=87))
        result = self.verdict(value)
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", result["verdict"])
        self.assertEqual({"dscp_error": {"87": 3}}, result["roles"]["tagged-b"]["job"]["errors"])

    def test_engine_and_bridge_faults_are_harness_errors(self):
        cases = []
        for change in (dict(ready=False), dict(exit_code=2), dict(summary=None)):
            value = routed_input()
            value["engine"].update(change)
            cases.append(value)
        for counters in (dict(recv_errors=1), dict(timed_out=True), dict(stop_timeout=True), dict(open_error=5),
                         dict(shutdown_error=6)):
            value = routed_input()
            value["engine"] = engine(**counters)
            cases.append(value)
        for change in (dict(started=False), dict(close_ok=False)):
            value = routed_input()
            value["bridge"].update(change)
            cases.append(value)
        for value in cases:
            result = self.verdict(value)
            self.assertEqual("HARNESS_ERROR", result["verdict"], value["engine"])
            self.assertTrue(result["faults"])

    def test_deadline(self):
        value = routed_input()
        value["attempts"][-1].update(skipped="deadline", exit_code=None, curl=None, launch=None)
        self.assertEqual("SKIPPED_DEADLINE", self.verdict(value)["verdict"])

    def test_baseline_never_changes_the_verdict(self):
        value = routed_input()
        value["baseline"] = attempts("tagged-no-engine", exit_code=28, code=0)
        result = self.verdict(value)
        self.assertEqual("ROUTED_VIA_GATEWAY", result["verdict"])
        self.assertEqual(0, result["baseline"]["succeeded"])

    def test_error_cases(self):
        self.assertEqual(dict(case="https-external", verdict="SKIPPED_DEADLINE"), analysis.skipped_case())
        self.assertEqual(dict(case="load", verdict="SKIPPED_DEADLINE"), analysis.skipped_case("load"))
        self.assertEqual("load", analysis.harness_error_case("OSError", "load")["case"])
        self.assertEqual(dict(case="https-external", verdict="HARNESS_ERROR", error_type="OSError"),
                         analysis.harness_error_case("OSError"))
        self.assertEqual("Exception", analysis.harness_error_case("C:\\x y")["error_type"])


class PrivacyTests(unittest.TestCase):
    def test_validate_public_rejects_identifiers(self):
        for value in ({"note": R}, {"note": "fe80::1"}, {"local_port": 1}, {"pid": 4}, {"path": "x"},
                      {"note": "C:\\Users"}, {"note": "/tmp/x"}, {"x": float("nan")}, {"x": object()}):
            with self.assertRaises(ValueError, msg=value):
                analysis.validate_public(value)
        analysis.validate_public({"note": "ROUTED_VIA_GATEWAY", "count": 1, "flag": True, "ms": 1.5,
                                  "nothing": None, "list": ["2xx"]})

    def test_report_is_aggregate_only_and_short(self):
        report = analysis.build_report(dict(os_build=20348, os_ubr=1, elevated=True, in_job=True,
                                            image="win22", image_version="20260101.1", secret="C:\\x"),
                                       [analysis.analyze(routed_input())])
        text = analysis.compact_dumps(report)
        self.assertEqual(report, json.loads(text))
        self.assertLess(len(text.splitlines()), 150)
        for token in (R, "10.1.0.4", "50011", "443", "C:\\"):
            self.assertNotIn(token, text)
        self.assertEqual({"https-external": "ROUTED_VIA_GATEWAY"}, report["verdicts"])
        self.assertEqual("job-dscp-route-v2", report["schema"])
        self.assertEqual(dict(status="invalid"), report["qos_policy"])
        self.assertNotIn("secret", report["env"])

    def test_report_of_error_case(self):
        report = analysis.build_report({}, [analysis.harness_error_case("OSError")])
        self.assertEqual(["https-external"], report["harness_errors"])
        analysis.validate_public(report)

    def test_markdown_summary(self):
        text = analysis.markdown_summary(analysis.build_report(dict(os_build=26100),
                                                               [analysis.analyze(routed_input())]))
        self.assertIn("| https-external | ROUTED_VIA_GATEWAY |", text)
        self.assertIn("| tagged-a |", text)
        self.assertIn("| tagged-no-engine |", text)
        self.assertNotIn(R, text)
        self.assertIn("HARNESS_ERROR", analysis.markdown_summary(
            analysis.build_report({}, [analysis.harness_error_case("OSError")])))

    def test_analysis_does_not_mutate_input(self):
        value = routed_input()
        before = copy.deepcopy(value)
        analysis.analyze(value)
        self.assertEqual(before, value)


if __name__ == "__main__":
    unittest.main()
