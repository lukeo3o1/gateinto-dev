import copy
import json
import unittest

import analysis
import analysis_extra as extra
from test_analysis import BRIDGE_PORT, R, curl, engine, launch, wire

SESSIONS = ("session-a", "session-b")


def attempt(role, index, port, exit_code=0, code=200, dscp=None, phase=None, total=0.1, **launch_overrides):
    item = dict(role=role, index=index, exit_code=exit_code, timed_out=False, skipped=None,
                curl=curl(code=code, port=port, total=total))
    if phase:
        item["phase"] = phase
    if dscp is not None:
        item["launch"] = launch(dscp, exit_code, **launch_overrides)
    return item


def common(attempts, connects, nic=None, **engine_counters):
    counters = dict(new_flows=connects)
    counters.update(engine_counters)
    return dict(precondition=None, target_ip=R, bridge_port=BRIDGE_PORT, attempts=attempts,
                gateway=dict(read=True, lines=[f"CONNECT {R}:443 HTTP/1.1"] * connects),
                bridge=dict(started=True, close_ok=True, accepted=connects, tunnels=connects, errors=0,
                            error_kinds={}),
                engine=engine(**counters), firewall="added", nic=nic or dict(status="unavailable", step="start"))


def load_input():
    attempts, port = [], 40000
    for role, dscp in (("untagged", None), ("tagged-a", 10), ("tagged-b", 20)):
        for index in range(10):
            port += 1
            attempts.append(attempt(role, index, port, dscp=dscp, phase="sequential", total=0.1 + index / 100))
        for index in range(10):
            port += 1
            attempts.append(attempt(role, 10 + index, port, dscp=dscp, phase="burst", total=1.0 + index / 10))
    return common(attempts, 40)


class PercentileTests(unittest.TestCase):
    def test_nearest_rank(self):
        values = [0.001 * v for v in range(1, 21)]
        self.assertEqual((10.0, 19.0), (extra.percentile_ms(values, 0.5), extra.percentile_ms(values, 0.95)))
        self.assertEqual(5.0, extra.percentile_ms([0.005], 0.95))
        self.assertIsNone(extra.percentile_ms([], 0.5))


class LoadTests(unittest.TestCase):
    def test_routed_with_latency_per_phase(self):
        result = extra.analyze_load(load_input())
        analysis.validate_public(result)
        self.assertEqual(("load", "ROUTED_VIA_GATEWAY"), (result["case"], result["verdict"]))
        self.assertNotIn("baseline", result)
        self.assertEqual(dict(n=10, p50_time_total_ms=140.0, p95_time_total_ms=190.0),
                         result["latency"]["tagged-a"]["sequential"])
        self.assertEqual(dict(n=10, p50_time_total_ms=1400.0, p95_time_total_ms=1900.0),
                         result["latency"]["untagged"]["burst"])
        self.assertEqual(dict(sequential=30, burst=30), result["phases"])

    def test_core_rules_apply(self):
        value = load_input()
        value["gateway"]["lines"].pop()
        self.assertEqual("PARTIAL", extra.analyze_load(value)["verdict"])
        value = load_input()
        value["engine"] = engine(new_flows=40, send_errors=1)
        self.assertEqual("PARTIAL", extra.analyze_load(value)["verdict"])

    def test_stopped_roles_and_skipped_burst_are_published(self):
        attempts = [attempt("untagged", i, 44000 + i, phase="sequential") for i in range(10)]
        for role, dscp, base in (("tagged-a", 10, 44100), ("tagged-b", 20, 44200)):
            for index in range(3):
                item = attempt(role, index, base + index, exit_code=28, code=0, dscp=dscp, phase="sequential")
                attempts.append(item)
        value = common(attempts, 0)
        value.update(stopped_early={"untagged": False, "tagged-a": True, "tagged-b": True, "C:\\x": True},
                     burst_skipped=True)
        result = extra.analyze_load(value)
        analysis.validate_public(result)
        self.assertEqual("ROUTING_BROKE_TAGGED", result["verdict"])
        self.assertEqual(6, result["tagged_attempts"])
        self.assertEqual({"untagged": False, "tagged-a": True, "tagged-b": True}, result["stopped_early"])
        self.assertTrue(result["burst_skipped"])
        self.assertEqual(dict(sequential=16, burst=0), result["phases"])
        self.assertFalse(extra.analyze_load(load_input())["burst_skipped"])

    def test_stopped_early_is_published_by_every_extension_case(self):
        for function, value, role in ((extra.analyze_shared, shared_input(), "session-a"),
                                      (extra.analyze_qos, qos_input(), "policy-inside"),
                                      (extra.analyze_udp, udp_input(), "udp-tagged")):
            value["stopped_early"] = {role: True}
            self.assertEqual({role: True}, function(value)["stopped_early"])

    def test_failures_have_no_latency(self):
        value = load_input()
        for item in value["attempts"]:
            if item["role"] == "tagged-b" and item["phase"] == "burst":
                item.update(exit_code=28, curl=curl(code=0, port=item["curl"]["local_port"]))
                item["launch"]["child_exit_code"] = 28
        result = extra.analyze_load(value)
        self.assertEqual(dict(n=0, p50_time_total_ms=None, p95_time_total_ms=None),
                         result["latency"]["tagged-b"]["burst"])


def owner(*memberships, found=True, rows=1, table_error=0, process_error=0, open_error=0, query_error=0):
    return dict(kind="owner", table_error=table_error, rows=rows, found=found, process_error=process_error,
                jobs=[dict(in_job=m, open_error=open_error if m is None else 0,
                           query_error=query_error if m is None else 0) for m in memberships])


def shared_launch():
    return dict(launch(43), shared_job=True, kill_on_close_set=False, dscp_set=False)


def shared_input():
    attempts, attributions, port = [], [], 41000
    for index in range(3):
        port += 1
        attempts.append(attempt("untagged", index, port))
    for session, membership in (("session-a", (True, False)), ("session-b", (False, True))):
        for index in range(6):
            port += 1
            item = attempt(session, index, port, phase="sequential" if index < 3 else "burst")
            item["launch"] = shared_launch()
            attempts.append(item)
            attributions.append(dict(local_port=port, owner=owner(*membership), error=None))
    value = common(attempts, 12)
    holder = dict(kind="session", dscp=43, job_created=True, job_error=0, kill_on_close_set=True,
                  kill_on_close_error=0, dscp_set=True, dscp_error=0, readback_ok=True, readback_error=0,
                  readback_flags=5, readback_dscp=43, ready=True)
    value.update(holders={s: dict(holder) for s in SESSIONS}, attributions=attributions)
    return value


class SharedTests(unittest.TestCase):
    def analyze(self, value):
        result = extra.analyze_shared(value)
        analysis.validate_public(result)
        return result

    def test_routed_and_attributed(self):
        result = self.analyze(shared_input())
        self.assertEqual(("shared-dscp", "ROUTED_AND_ATTRIBUTED"), (result["case"], result["verdict"]))
        self.assertEqual(dict(attempts=6, owner_found=6, attributed_correct=6, attributed_wrong=0, unattributed=0,
                              errors={}), result["attribution"]["session-a"])
        self.assertEqual(0, result["unexpected_attributions"])
        self.assertEqual(6, result["roles"]["session-b"]["job"]["setup_ok"])
        self.assertTrue(result["holders"]["session-a"]["ready"])

    def test_shared_launch_setup(self):
        self.assertTrue(extra.shared_launch_ok(shared_launch(), 43))
        self.assertFalse(extra.shared_launch_ok(launch(43), 43))
        self.assertFalse(extra.shared_launch_ok(dict(shared_launch(), readback_dscp=10), 43))
        self.assertTrue(extra.shared_launch_ok(dict(shared_launch(), kind="launch_setup", resumed=False), 43))

    def test_attribution_outcomes(self):
        value = shared_input()
        records = value["attributions"]
        records[0]["owner"] = owner(False, True)
        records[1]["owner"] = owner(True, True)
        records[2]["owner"] = owner(None, None, query_error=5)
        records[3]["owner"] = owner(None, None, found=False, rows=0)
        records[4].update(owner=None, error="owner_timeout")
        records[5]["local_port"] = 1
        records[6]["owner"] = owner(None, None, process_error=87)
        records[7]["owner"] = owner(None, None, found=False, rows=0, table_error=122)
        records[8]["owner"] = owner(False, False)
        records[9].update(owner=None, error="C:\\bad label")
        result = self.analyze(value)
        self.assertEqual("ROUTED_ATTRIBUTION_INCOMPLETE", result["verdict"])
        self.assertEqual(dict(attempts=6, owner_found=3, attributed_correct=0, attributed_wrong=2, unattributed=4,
                              errors={"job_query_5": 1, "no_record": 1, "owner_not_found": 1, "owner_timeout": 1}),
                         result["attribution"]["session-a"])
        self.assertEqual(dict(attempts=6, owner_found=4, attributed_correct=2, attributed_wrong=0, unattributed=4,
                              errors={"not_in_job": 1, "other": 1, "process_87": 1, "table_122": 1}),
                         result["attribution"]["session-b"])
        self.assertEqual(1, result["unexpected_attributions"])

    def test_error_labels_with_identifier_tokens_become_other(self):
        for label in ("pid_lookup", "src_port", "owner_ip"):
            self.assertEqual(("unattributed", "other", False),
                             extra.classify_attribution(dict(error=label), 0, 2))
        self.assertEqual(("unattributed", "owner_timeout", False),
                         extra.classify_attribution(dict(error="owner_timeout"), 0, 2))

    def test_failed_curls_without_a_local_port_stay_publishable(self):
        value = shared_input()
        for item in value["attempts"]:
            if item["role"] in SESSIONS:
                item.update(exit_code=28, curl=curl(code=0, port=None))
                item["launch"]["child_exit_code"] = 28
        value["attributions"] = []
        result = self.analyze(value)
        self.assertEqual("ROUTING_BROKE_TAGGED", result["verdict"])
        self.assertEqual({"curl_not_connected": 6}, result["attribution"]["session-a"]["errors"])

    def test_routing_failure_keeps_the_core_verdict(self):
        value = shared_input()
        value["gateway"]["lines"].append(f"CONNECT {R}:80 HTTP/1.1")
        self.assertEqual("PARTIAL", self.analyze(value)["verdict"])

    def test_holder_failure(self):
        value = shared_input()
        value["holders"]["session-b"].update(ready=False, dscp_set=False, dscp_error=87)
        result = self.analyze(value)
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", result["verdict"])
        self.assertEqual(dict(ready=False, job_error=0, dscp_error=87, readback_error=0),
                         result["holders"]["session-b"])
        value["holders"].pop("session-a")
        self.assertFalse(self.analyze(value)["holders"]["session-a"]["ready"])

    def test_holder_failure_wins_over_a_segment_that_never_ran(self):
        value = dict(precondition=None, target_ip=R, holders={"session-a": dict(ready=False, job_error=183)})
        result = self.analyze(value)
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", result["verdict"])
        self.assertEqual(dict(ready=False, job_error=183, dscp_error=None, readback_error=None),
                         result["holders"]["session-a"])
        value["attempts"] = [dict(role="session-a", index=0, skipped="deadline")]
        self.assertEqual("SKIPPED_DEADLINE", self.analyze(value)["verdict"])

    def test_faults_win_when_holders_are_ready(self):
        value = shared_input()
        value["engine"]["ready"] = False
        self.assertEqual("HARNESS_ERROR", self.analyze(value)["verdict"])


def qos_input(inside="routed"):
    attempts, packets = [], []
    for index, port in enumerate((42001, 42002, 42003)):
        attempts.append(attempt("policy-outside", index, port))
        packets += [dict(wire(port, syn=True), tos=46 << 2), dict(wire(port), tos=(46 << 2) | 1)]
    for index, port in enumerate((42011, 42012, 42013)):
        attempts.append(attempt("policy-inside", index, port, dscp=43))
        if inside == "policy":
            packets.append(dict(wire(port, syn=True), tos=46 << 2))
        elif inside == "tag":
            packets.append(dict(wire(port, syn=True), tos=43 << 2))
    connects = 3 if inside == "routed" else 0
    value = common(attempts, connects, nic=dict(status="ok", packets=packets))
    value.update(policy=dict(status="created"),
                 gateway_by_role={"policy-outside": 0, "policy-inside": connects})
    return value


class QosTests(unittest.TestCase):
    def analyze(self, value):
        result = extra.analyze_qos(value)
        analysis.validate_public(result)
        return result

    def test_job_tag_wins(self):
        result = self.analyze(qos_input("routed"))
        self.assertEqual(("qos-policy", "JOB_TAG_WINS"), (result["case"], result["verdict"]))
        self.assertEqual(dict(status="created", applied=True), result["policy"])
        self.assertEqual(dict(packets=6, syns=3, attempts_on_wire=3, dscp={"46": 6}), result["nic"]["policy-outside"])
        self.assertEqual({"routed": 3}, result["inside_outcomes"])
        self.assertEqual({"policy-outside": 0, "policy-inside": 3}, result["connects"])

    def test_policy_wins(self):
        result = self.analyze(qos_input("policy"))
        self.assertEqual("POLICY_WINS", result["verdict"])
        self.assertEqual({"policy": 3}, result["inside_outcomes"])

    def test_mixed(self):
        value = qos_input("routed")
        value["nic"]["packets"].append(dict(wire(42013, syn=True), tos=46 << 2))
        value["gateway_by_role"]["policy-inside"] = 2
        self.assertEqual("MIXED", self.analyze(value)["verdict"])
        self.assertEqual({"policy": 1, "routed": 2}, self.analyze(value)["inside_outcomes"])
        self.assertEqual({"tag_on_wire": 3}, self.analyze(qos_input("tag"))["inside_outcomes"])

    def test_policy_not_applied(self):
        value = qos_input()
        value["policy"] = dict(status="failed", reason="create_failed")
        result = self.analyze(value)
        self.assertEqual("INCONCLUSIVE_POLICY_NOT_APPLIED", result["verdict"])
        self.assertEqual(dict(status="failed", reason="create_failed", applied=False), result["policy"])
        for packets, reason in (([], "control_not_on_wire"),
                                ([dict(wire(42001, syn=True), tos=0)], "control_unmarked"),
                                ([dict(wire(42001, syn=True), tos=184), dict(wire(42001), tos=0)],
                                 "control_partially_marked")):
            value = qos_input()
            value["nic"]["packets"] = packets
            result = self.analyze(value)
            self.assertEqual("INCONCLUSIVE_POLICY_NOT_APPLIED", result["verdict"], reason)
            self.assertEqual(reason, result["policy"]["applied_reason"])
        value = qos_input()
        value["nic"] = dict(status="unavailable", step="start", exit_code=1)
        result = self.analyze(value)
        self.assertEqual(("INCONCLUSIVE_POLICY_NOT_APPLIED", None, "nic_unavailable"),
                         (result["verdict"], result["policy"]["applied"], result["policy"]["applied_reason"]))

    def test_unreached_control_and_faults(self):
        value = qos_input()
        for item in value["attempts"]:
            if item["role"] == "policy-outside":
                item.update(exit_code=7, curl=curl(code=0, port=item["curl"]["local_port"]))
        self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", self.analyze(value)["verdict"])
        value = qos_input()
        value["engine"]["exit_code"] = 2
        self.assertEqual("HARNESS_ERROR", self.analyze(value)["verdict"])
        value = qos_input()
        value["attempts"][-1]["launch"]["dscp_set"] = False
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", self.analyze(value)["verdict"])


def udp_attempt(role, index, port, sent=3, dscp=None):
    item = dict(role=role, index=index, exit_code=0, timed_out=False, skipped=None,
                udp=dict(local_port=port, sent=sent, error=0))
    if dscp is not None:
        item["launch"] = launch(dscp)
    return item


def udp_packet(port, dscp):
    return dict(v=4, proto=17, src="10.1.0.4", dst=R, sport=port, dport=443, tos=dscp << 2)


def udp_input(tagged_on_wire=0, contained=3):
    attempts = [udp_attempt("udp-tagged-no-engine", 0, 43001, dscp=43), udp_attempt("udp-untagged", 0, 43002),
                udp_attempt("udp-tagged", 0, 43003, dscp=43), attempt("tcp-tagged", 0, 43004, dscp=43)]
    packets = [udp_packet(43001, 43)] * 3 + [udp_packet(43002, 0)] * 3 + [udp_packet(43003, 43)] * tagged_on_wire
    value = common(attempts, 1, nic=dict(status="ok", packets=packets), contained_udp=contained, contained_other=0)
    return value


class UdpTests(unittest.TestCase):
    def analyze(self, value):
        result = extra.analyze_udp(value)
        analysis.validate_public(result)
        return result

    def test_contained(self):
        result = self.analyze(udp_input())
        self.assertEqual(("udp-containment", "CONTAINED"), (result["case"], result["verdict"]))
        self.assertEqual(dict(sends=1, sent=3, on_wire=3, dscp={"43": 3}), result["udp"]["udp-tagged-no-engine"])
        self.assertEqual(dict(sends=1, sent=3, on_wire=0, dscp={}), result["udp"]["udp-tagged"])
        self.assertEqual((3, 0), (result["engine"]["contained_udp"], result["engine"]["contained_other"]))
        self.assertTrue(result["tcp_coexists"])
        self.assertIsNone(result["baseline_reason"])

    def test_leaked_and_partial(self):
        self.assertEqual("LEAKED", self.analyze(udp_input(tagged_on_wire=3, contained=0))["verdict"])
        self.assertEqual("PARTIAL", self.analyze(udp_input(tagged_on_wire=1, contained=2))["verdict"])
        self.assertEqual("PARTIAL", self.analyze(udp_input(contained=6))["verdict"])
        value = udp_input()
        value["nic"]["packets"] = [p for p in value["nic"]["packets"] if p["sport"] != 43002]
        self.assertEqual("PARTIAL", self.analyze(value)["verdict"])

    def test_no_baseline(self):
        value = udp_input()
        value["nic"] = dict(status="unavailable", step="start", exit_code=1)
        result = self.analyze(value)
        self.assertEqual(("INCONCLUSIVE_NO_BASELINE", "nic_unavailable"), (result["verdict"], result["baseline_reason"]))
        self.assertEqual(3, result["engine"]["contained_udp"])
        value = udp_input()
        value["nic"]["packets"] = [p for p in value["nic"]["packets"] if p["sport"] != 43001]
        self.assertEqual("baseline_not_on_wire", self.analyze(value)["baseline_reason"])
        value = udp_input()
        value["nic"]["packets"] = [dict(p, tos=0) if p["sport"] == 43001 else p for p in value["nic"]["packets"]]
        self.assertEqual("baseline_unmarked", self.analyze(value)["baseline_reason"])

    def test_tcp_coexistence_is_reported_not_judged(self):
        value = udp_input()
        value["gateway"]["lines"] = []
        result = self.analyze(value)
        self.assertEqual(("CONTAINED", False), (result["verdict"], result["tcp_coexists"]))

    def test_faults_and_setup(self):
        value = udp_input()
        value["engine"]["summary"] = None
        self.assertEqual("HARNESS_ERROR", self.analyze(value)["verdict"])
        value = udp_input()
        value["attempts"][2]["launch"]["dscp_set"] = False
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", self.analyze(value)["verdict"])
        value = udp_input()
        value["attempts"][1]["skipped"] = "deadline"
        self.assertEqual("SKIPPED_DEADLINE", self.analyze(value)["verdict"])
        value = udp_input()
        value["precondition"] = "INCONCLUSIVE_TARGET_UNREACHABLE"
        self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", self.analyze(value)["verdict"])


class ReportTests(unittest.TestCase):
    def test_report_lists_every_case_and_stays_aggregate_only(self):
        from test_analysis import routed_input
        cases = [analysis.analyze(routed_input()), extra.analyze_load(load_input()), extra.analyze_shared(shared_input()),
                 extra.analyze_qos(qos_input()), extra.analyze_udp(udp_input()),
                 analysis.harness_error_case("OSError", "spare")]
        report = analysis.build_report(dict(os_build=20348, secret="C:\\x"), cases,
                                       dict(status="created", reason="C:\\x"))
        text = analysis.compact_dumps(report)
        self.assertEqual(report, json.loads(text))
        self.assertLess(len(text.splitlines()), 150)
        self.assertEqual("job-dscp-route-v2", report["schema"])
        self.assertEqual(["https-external", "load", "shared-dscp", "qos-policy", "udp-containment", "spare"],
                         list(report["verdicts"]))
        self.assertEqual(["spare"], report["harness_errors"])
        self.assertEqual(dict(status="created"), report["qos_policy"])
        for token in (R, "10.1.0.4", "41001", "8443", "C:\\", "Local"):
            self.assertNotIn(token, text)
        markdown = analysis.markdown_summary(report)
        for name in report["verdicts"]:
            self.assertIn(f"| {name} |", markdown)
        self.assertIn("| tagged-a |", markdown)
        self.assertNotIn(R, markdown)

    def test_analysis_does_not_mutate_inputs(self):
        for function, value in ((extra.analyze_load, load_input()), (extra.analyze_shared, shared_input()),
                                (extra.analyze_qos, qos_input()), (extra.analyze_udp, udp_input())):
            before = copy.deepcopy(value)
            function(value)
            self.assertEqual(before, value)


if __name__ == "__main__":
    unittest.main()
