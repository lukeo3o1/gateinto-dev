import json
import unittest

import analysis

TARGET = "192.0.2.1"
LOCAL = "10.1.0.4"
JOB_OK = dict(kind="launch", job_created=True, job_error=0, kill_on_close_set=True, kill_on_close_error=0,
              dscp_set=True, dscp_error=0, readback_ok=True, readback_error=0, readback_flags=5,
              process_created=True, process_error=0, assigned=True, assign_error=0, resumed=True,
              resume_error=0, child_ran=True, child_exit_code=0)


def packet(sport, tos, syn=False, ack=False, fin=False, seq=0, dst=TARGET, dport=443, proto=6, length=52):
    return dict(kind="packet", v=4, proto=proto, src=LOCAL, dst=dst, sport=sport, dport=dport, tos=tos,
                syn=syn, ack=ack, fin=fin, rst=False, len=length, seq=seq, loopback=False, outbound=True)


def syn(sport, dscp, seq=0):
    return packet(sport, dscp << 2, syn=True, seq=seq)


def role(name, ports, dscp, kind="tagged", outcome="timeout"):
    launch = None
    if kind == "tagged":
        launch = dict(JOB_OK, dscp=dscp, readback_dscp=dscp)
    return dict(name=name, kind=kind, expected_dscp=dscp, exit_ok=True, launch=launch, skipped=None,
                attempts=[dict(kind="attempt", role=name, proto="tcp", local_port=p, outcome=outcome, error=0)
                          for p in ports])


def sniffer(packets, **summary):
    base = dict(kind="summary", received=len(packets), parse_errors=0, recv_errors=0, last_error=0,
                open_error=0, truncated=False, records=len(packets))
    base.update(summary)
    return dict(ready=True, exit_code=0, summary=base, packets=packets)


def case(roles, observe, marked=None, **extra):
    if marked is None:
        marked = [p for p in observe if p["tos"] >= 4]
    value = dict(case="tcp-external-syn", proto="tcp", target=dict(addr=TARGET, port=443), precondition=None,
                 require_connect=False, roles=roles,
                 sniffers=dict(observe=sniffer(observe), marked=sniffer(marked)),
                 nic=dict(status="not_applicable"))
    value.update(extra)
    return value


def standard_roles():
    return [role("tagged-a", [1001, 1002], 10), role("tagged-b", [2001, 2002], 20),
            role("tagged-child", [3001], 10), role("untagged", [4001], 0, kind="untagged")]


def all_marked_packets():
    return [syn(1001, 10), syn(1002, 10), syn(2001, 20), syn(2002, 20), syn(3001, 10), syn(4001, 0)]


class DscpTests(unittest.TestCase):
    def test_dscp_ignores_ecn_bits(self):
        self.assertEqual(10, analysis.dscp(40))
        self.assertEqual(10, analysis.dscp(43))
        self.assertEqual(0, analysis.dscp(3))
        self.assertEqual(63, analysis.dscp(255))


class AttributionTests(unittest.TestCase):
    def test_packets_are_attributed_by_protocol_local_port_and_destination(self):
        roles = [role("tagged-a", [1001], 10), role("untagged", [4001], 0, kind="untagged")]
        packets = [syn(1001, 10, seq=1), syn(4001, 0, seq=2), syn(5555, 0, seq=3),
                   packet(1001, 40, dst="192.0.2.2", seq=4), packet(1001, 40, dport=80, seq=5),
                   packet(1001, 40, proto=17, seq=6)]
        flows, unattributed = analysis.attribute(packets, roles, "tcp", TARGET, 443)
        self.assertEqual([1], [p["seq"] for p in flows["tagged-a"][1001]])
        self.assertEqual([2], [p["seq"] for p in flows["untagged"][4001]])
        self.assertEqual(4, unattributed)

    def test_attribution_normalizes_address_spelling(self):
        roles = [role("tagged-a", [1001], 10)]
        v6 = dict(packet(1001, 40, dst="0:0:0:0:0:0:0:1"), v=6)
        flows, unattributed = analysis.attribute([v6], roles, "tcp", "::1", 443)
        self.assertEqual(1, len(flows["tagged-a"][1001]))
        self.assertEqual(0, unattributed)

    def test_attempts_without_local_port_are_never_keys(self):
        roles = [role("tagged-a", [0], 10)]
        flows, unattributed = analysis.attribute([syn(0, 10)], roles, "tcp", TARGET, 443)
        self.assertEqual({}, flows["tagged-a"])
        self.assertEqual(1, unattributed)


class CompletenessTests(unittest.TestCase):
    def test_missing_from_marked_is_a_multiset_difference_of_marked_packets(self):
        observe = [syn(1001, 10), syn(1001, 10), syn(1002, 0)]
        marked = [syn(1001, 10)]
        self.assertEqual(1, analysis.missing_from_marked(observe, marked))
        self.assertEqual(0, analysis.missing_from_marked(observe, marked + [syn(1001, 10)]))

    def test_marked_capture_shows_selectivity_and_foreign_packets(self):
        observe = all_marked_packets()
        foreign = packet(7777, 46 << 2, dst="198.51.100.7", dport=53, proto=17)
        marked = [p for p in observe if p["tos"] >= 4] + [syn(4001, 8), foreign]
        result = analysis.analyze_case(case(standard_roles(), observe, marked))
        self.assertFalse(result["marked_filter_selective"])
        self.assertEqual(1, result["roles"]["untagged"]["marked_packets"])
        self.assertEqual(1, result["foreign_marked_packets"])
        self.assertEqual({"46": 1}, result["foreign_marked_dscp"])

    def test_complete_and_selective_marked_capture(self):
        result = analysis.analyze_case(case(standard_roles(), all_marked_packets()))
        self.assertTrue(result["marked_filter_complete"])
        self.assertTrue(result["marked_filter_selective"])
        self.assertEqual(0, result["foreign_marked_packets"])

    def test_incomplete_marked_capture_is_reported_per_role(self):
        observe = all_marked_packets()
        marked = [p for p in observe if p["tos"] >= 4 and p["sport"] != 2002]
        result = analysis.analyze_case(case(standard_roles(), observe, marked))
        self.assertFalse(result["marked_filter_complete"])
        self.assertEqual(1, result["roles"]["tagged-b"]["observe_missing_from_marked"])
        self.assertEqual(0, result["roles"]["tagged-a"]["observe_missing_from_marked"])


class RoleStatsTests(unittest.TestCase):
    def test_flow_classification_and_histograms(self):
        roles = [role("tagged-a", [1001, 1002, 1003, 1004], 10)]
        observe = [syn(1001, 10, seq=1), packet(1001, 40, ack=True, seq=2), packet(1001, 40, fin=True, ack=True, seq=3),
                   syn(1002, 0, seq=4), packet(1002, 0, ack=True, seq=5),
                   syn(1003, 10, seq=6), packet(1003, 0, ack=True, seq=7)]
        stats = analysis.analyze_case(case(roles, observe))["roles"]["tagged-a"]
        self.assertEqual(4, stats["attempts"])
        self.assertEqual(3, stats["flows_observed"])
        self.assertEqual(3, stats["first_packets_observed"])
        self.assertEqual({"0": 1, "10": 2}, stats["first_packet_dscp"])
        self.assertEqual(3, stats["syn_packets"])
        self.assertEqual({"0": 1, "10": 2}, stats["syn_dscp"])
        self.assertEqual({"0": 3, "10": 4}, stats["all_dscp"])
        self.assertEqual(7, stats["packets"])
        self.assertEqual(1, stats["flows_fully_marked"])
        self.assertEqual(1, stats["flows_unmarked"])
        self.assertEqual(1, stats["flows_mixed"])
        self.assertEqual(3, stats["packets_unexpected_dscp"])
        self.assertEqual({"timeout": 4}, stats["outcomes"])

    def test_first_packet_must_be_initial_syn_for_tcp(self):
        roles = [role("tagged-a", [1001], 10)]
        stats = analysis.analyze_case(case(roles, [packet(1001, 40, ack=True)]))["roles"]["tagged-a"]
        self.assertEqual(1, stats["flows_observed"])
        self.assertEqual(0, stats["first_packets_observed"])

    def test_udp_first_datagram_counts_as_first_packet(self):
        roles = [role("tagged-a", [1001], 10)]
        for attempt in roles[0]["attempts"]:
            attempt["proto"] = "udp"
            attempt["outcome"] = "sent"
        observe = [packet(1001, 40, proto=17, seq=1), packet(1001, 40, proto=17, seq=2)]
        result = analysis.analyze_case(case(roles, observe, proto="udp", case="udp-external"))
        stats = result["roles"]["tagged-a"]
        self.assertEqual(1, stats["first_packets_observed"])
        self.assertEqual(1, stats["syn_packets"])
        self.assertEqual({"10": 2}, stats["all_dscp"])
        self.assertEqual("MARK_AT_FIRST_PACKET", result["verdict"])

    def test_job_setup_is_projected_with_codes_and_readback(self):
        roles = [role("tagged-a", [1001], 10)]
        roles[0]["launch"].update(dscp_set=False, dscp_error=87, readback_flags=0, readback_dscp=0)
        job = analysis.analyze_case(case(roles, [syn(1001, 0)]))["roles"]["tagged-a"]["job"]
        self.assertFalse(job["ok"])
        self.assertFalse(job["dscp_set"])
        self.assertEqual(87, job["dscp_error"])
        self.assertEqual(0, job["readback_dscp"])


class JobSetupTests(unittest.TestCase):
    def test_requires_every_step_and_matching_readback(self):
        good = dict(JOB_OK, readback_dscp=10)
        self.assertTrue(analysis.job_setup_ok(good, 10))
        self.assertFalse(analysis.job_setup_ok(good, 20))
        self.assertFalse(analysis.job_setup_ok(dict(good, readback_flags=1), 10))
        self.assertTrue(analysis.job_setup_ok(dict(good, readback_flags=7), 10))
        for step in ("job_created", "kill_on_close_set", "dscp_set", "readback_ok", "process_created",
                     "assigned", "resumed"):
            self.assertFalse(analysis.job_setup_ok(dict(good, **{step: False}), 10), step)
        self.assertFalse(analysis.job_setup_ok(None, 10))
        self.assertFalse(analysis.job_setup_ok("garbage", 10))


class VerdictTests(unittest.TestCase):
    def verdict(self, value):
        return analysis.analyze_case(value)["verdict"]

    def test_mark_at_first_packet(self):
        self.assertEqual("MARK_AT_FIRST_PACKET", self.verdict(case(standard_roles(), all_marked_packets())))

    def test_mark_at_first_packet_requires_every_attempt(self):
        roles = standard_roles()
        roles[0]["attempts"].append(dict(roles[0]["attempts"][0], local_port=1003))
        self.assertEqual("PARTIAL_MARK", self.verdict(case(roles, all_marked_packets())))

    def test_attempt_without_local_port_prevents_full_mark(self):
        roles = standard_roles()
        roles[0]["attempts"].append(dict(roles[0]["attempts"][0], local_port=0, outcome="error"))
        self.assertEqual("PARTIAL_MARK", self.verdict(case(roles, all_marked_packets())))

    def test_wrong_role_dscp_is_partial(self):
        observe = all_marked_packets()
        observe[2] = syn(2001, 10)
        self.assertEqual("PARTIAL_MARK", self.verdict(case(standard_roles(), observe)))

    def test_marked_untagged_packet_is_partial(self):
        observe = all_marked_packets()
        observe[5] = syn(4001, 10)
        self.assertEqual("PARTIAL_MARK", self.verdict(case(standard_roles(), observe)))

    def test_mark_only_after_first_packet_is_partial(self):
        observe = [syn(1001, 0, seq=1), packet(1001, 40, ack=True, seq=2)]
        roles = [role("tagged-a", [1001], 10)]
        self.assertEqual("PARTIAL_MARK", self.verdict(case(roles, observe)))

    def test_no_mark(self):
        observe = [syn(p, 0) for p in (1001, 1002, 2001, 2002, 3001, 4001)]
        self.assertEqual("NO_MARK", self.verdict(case(standard_roles(), observe)))

    def test_no_packets(self):
        self.assertEqual("INCONCLUSIVE_NO_PACKETS", self.verdict(case(standard_roles(), [syn(4001, 0)])))

    def test_job_setup_failed(self):
        roles = standard_roles()
        roles[1]["launch"]["dscp_set"] = False
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", self.verdict(case(roles, all_marked_packets())))

    def test_missing_launch_record_is_job_setup_failure(self):
        roles = standard_roles()
        roles[2]["launch"] = None
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", self.verdict(case(roles, all_marked_packets())))

    def test_preconditions_win(self):
        for precondition in ("INCONCLUSIVE_TARGET_UNREACHABLE", "INCONCLUSIVE_NO_IPV6"):
            value = case(standard_roles(), all_marked_packets(), precondition=precondition)
            self.assertEqual(precondition, self.verdict(value))

    def test_target_unreachable_when_no_attempt_connected(self):
        value = case(standard_roles(), all_marked_packets(), require_connect=True, case="tcp-external-complete")
        self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", self.verdict(value))
        for item in value["roles"]:
            for attempt in item["attempts"]:
                attempt["outcome"] = "connected"
        self.assertEqual("MARK_AT_FIRST_PACKET", self.verdict(value))

    def test_sniffer_errors(self):
        for change in (dict(ready=False), dict(exit_code=2), dict(summary=None)):
            value = case(standard_roles(), all_marked_packets())
            value["sniffers"]["marked"].update(change)
            self.assertEqual("INCONCLUSIVE_SNIFFER_ERROR", self.verdict(value), change)
        for change in (dict(recv_errors=1), dict(parse_errors=1), dict(open_error=5), dict(truncated=True)):
            value = case(standard_roles(), all_marked_packets())
            value["sniffers"]["observe"]["summary"].update(change)
            self.assertEqual("INCONCLUSIVE_SNIFFER_ERROR", self.verdict(value), change)

    def test_sniffer_counts_are_reported(self):
        value = case(standard_roles(), all_marked_packets())
        value["sniffers"]["observe"]["summary"].update(recv_errors=3, last_error=995)
        result = analysis.analyze_case(value)
        self.assertEqual(3, result["sniffers"]["observe"]["recv_errors"])
        self.assertEqual(995, result["sniffers"]["observe"]["last_error"])
        self.assertTrue(result["sniffers"]["marked"]["ready"])

    def test_harness_error_verdict(self):
        result = analysis.harness_error_case("tcp-loopback", "TimeoutExpired")
        self.assertEqual("HARNESS_ERROR", result["verdict"])
        self.assertEqual("TimeoutExpired", result["error_type"])


class QosControlTests(unittest.TestCase):
    def qos_case(self, qos_packets, status="created"):
        roles = standard_roles() + [role("qos-policy", [6001, 6002], 30, kind="qos")]
        return case(roles, all_marked_packets() + qos_packets, qos_policy=status)

    def test_qos_role_does_not_influence_job_verdict(self):
        result = analysis.analyze_case(self.qos_case([syn(6001, 0), syn(6002, 0)]))
        self.assertEqual("MARK_AT_FIRST_PACKET", result["verdict"])
        self.assertNotIn("qos-policy", result["roles"])
        self.assertEqual("QOS_NO_MARK", result["qos_control"]["verdict"])

    def test_qos_verdicts(self):
        cases = [([syn(6001, 30), syn(6002, 30)], "created", "QOS_MARK_VISIBLE"),
                 ([syn(6001, 30), syn(6002, 0)], "created", "QOS_PARTIAL_MARK"),
                 ([], "created", "QOS_NO_PACKETS"),
                 ([syn(6001, 30)], "unavailable", "QOS_POLICY_UNAVAILABLE")]
        for packets, status, expected in cases:
            result = analysis.analyze_case(self.qos_case(packets, status))
            self.assertEqual(expected, result["qos_control"]["verdict"], expected)

    def test_qos_packets_in_marked_capture_are_not_foreign(self):
        result = analysis.analyze_case(self.qos_case([syn(6001, 30), syn(6002, 30)]))
        self.assertEqual(0, result["foreign_marked_packets"])
        self.assertEqual(2, result["qos_control"]["marked_packets"])


class NicTests(unittest.TestCase):
    def test_nic_histogram_per_role(self):
        nic_packets = [syn(1001, 10), syn(1001, 10), syn(4001, 0), syn(9999, 0)]
        value = case(standard_roles(), all_marked_packets(), nic=dict(status="ok", packets=nic_packets))
        nic = analysis.analyze_case(value)["nic"]
        self.assertEqual("ok", nic["status"])
        self.assertEqual({"packets": 2, "dscp": {"10": 2}}, nic["roles"]["tagged-a"])
        self.assertEqual({"packets": 1, "dscp": {"0": 1}}, nic["roles"]["untagged"])
        self.assertEqual({"packets": 0, "dscp": {}}, nic["roles"]["tagged-b"])
        self.assertEqual(1, nic["unattributed"])

    def test_nic_unavailable_is_projected(self):
        value = case(standard_roles(), all_marked_packets(),
                     nic=dict(status="unavailable", step="convert", exit_code=87, detail="C:\\secret"))
        nic = analysis.analyze_case(value)["nic"]
        self.assertEqual(dict(status="unavailable", step="convert", exit_code=87), nic)


class PublicProjectionTests(unittest.TestCase):
    def test_case_result_contains_no_addresses_ports_or_paths(self):
        value = case(standard_roles(), all_marked_packets(), nic=dict(status="ok", packets=[syn(1001, 10)]))
        value["roles"][0]["launch"]["child_pid"] = 4242
        value["roles"][0]["launch"]["path"] = "C:\\runner\\probe.exe"
        result = analysis.analyze_case(value)
        analysis.validate_public(result)
        encoded = json.dumps(result)
        for token in (TARGET, LOCAL, "1001", "4242", "probe.exe", '"pid', "port\""):
            self.assertNotIn(token, encoded)

    def test_validate_public_rejects_identifiers(self):
        for bad in ({"a": "10.1.0.4"}, {"a": ["fe80::1"]}, {"a": "C:\\x"}, {"a": "/home/x"},
                    {"local_port": 5}, {"child_pid": 1}, {"a": {"remote_addr": "x"}}, {"a": 1.5e400},
                    {"a": "x" * 300}):
            with self.assertRaises(ValueError, msg=bad):
                analysis.validate_public(bad)
        analysis.validate_public({"build": 20348, "image_version": "20250105.1.0", "verdict": "NO_MARK",
                                  "dscp": {"10": 3}, "ok": True, "missing": None})

    def test_build_aggregate_and_compact_dump(self):
        cases = [analysis.analyze_case(case(standard_roles(), all_marked_packets())),
                 analysis.harness_error_case("udp-loopback", "OSError")]
        env = dict(os_major=10, os_minor=0, os_build=20348, elevated=True, connection_policy_api=True,
                   in_job=True, image="win22", image_version="20250105.1.0", pid=99, path="C:\\x")
        aggregate = analysis.build_aggregate(env, dict(status="created"), cases)
        analysis.validate_public(aggregate)
        self.assertNotIn("pid", aggregate["env"])
        self.assertNotIn("path", aggregate["env"])
        self.assertEqual({"tcp-external-syn": "MARK_AT_FIRST_PACKET", "udp-loopback": "HARNESS_ERROR"},
                         aggregate["verdicts"])
        self.assertTrue(aggregate["harness_errors"])
        text = analysis.compact_dumps(aggregate)
        self.assertEqual(aggregate, json.loads(text))
        self.assertLess(len(text.splitlines()), 60)
        self.assertIn('  "tagged-a": {"expected_dscp":10,', text)

    def test_qos_policy_status_is_a_fixed_label(self):
        aggregate = analysis.build_aggregate({}, dict(status="C:\\weird", error="x"), [])
        self.assertEqual({"status": "invalid"}, aggregate["qos_policy"])


class MarkdownTests(unittest.TestCase):
    def test_markdown_summary_lists_each_case_verdict(self):
        cases = [analysis.analyze_case(case(standard_roles(), all_marked_packets())),
                 analysis.harness_error_case("udp-loopback", "OSError")]
        aggregate = analysis.build_aggregate(dict(os_build=26100), dict(status="unavailable"), cases)
        text = analysis.markdown_summary(aggregate)
        self.assertIn("| tcp-external-syn | MARK_AT_FIRST_PACKET |", text)
        self.assertIn("| udp-loopback | HARNESS_ERROR |", text)
        self.assertIn("26100", text)


if __name__ == "__main__":
    unittest.main()
