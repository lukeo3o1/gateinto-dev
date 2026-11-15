import json
import pathlib
import tempfile
import unittest

import analysis
import harness


class FilterTests(unittest.TestCase):
    def test_observe_filter_is_built_from_the_target(self):
        self.assertEqual("outbound and ip and ip.DstAddr == 192.0.2.1 and tcp and tcp.DstPort == 443",
                         harness.observe_filter("tcp", "192.0.2.1", 443))
        self.assertEqual("outbound and ipv6 and ipv6.DstAddr == ::1 and udp and udp.DstPort == 5000",
                         harness.observe_filter("udp", "::1", 5000))

    def test_observe_filter_rejects_invalid_input(self):
        for args in (("icmp", "192.0.2.1", 1), ("tcp", "not-an-address", 1), ("tcp", "192.0.2.1", 0),
                     ("tcp", "192.0.2.1", 70000), ("tcp", "192.0.2.1 or true", 1)):
            with self.assertRaises(ValueError, msg=args):
                harness.observe_filter(*args)

    def test_marked_filter_is_the_production_prototype(self):
        self.assertEqual("outbound and ((ip and ip.TOS >= 4) or (ipv6 and ipv6.TrafficClass >= 4))",
                         harness.MARKED_FILTER)


class PlanTests(unittest.TestCase):
    def test_fixed_cases(self):
        names = [case["name"] for case in harness.CASES]
        self.assertEqual(["tcp-external-syn", "udp-external", "tcp-external-complete", "tcp-loopback",
                          "udp-loopback", "tcp6-loopback"], names)
        by_name = {case["name"]: case for case in harness.CASES}
        self.assertTrue(by_name["tcp-external-complete"]["require_connect"])
        self.assertEqual(1500, by_name["tcp-external-syn"]["timeout_ms"])
        self.assertTrue(all(case["count"] == 3 for case in harness.CASES))
        self.assertEqual({"tcp-external-syn", "udp-external", "tcp-external-complete"},
                         {case["name"] for case in harness.CASES if case["nic"]})

    def test_fixed_roles(self):
        self.assertEqual([("tagged-a", "tagged", 10, False), ("tagged-b", "tagged", 20, False),
                          ("tagged-child", "tagged", 10, True), ("untagged", "untagged", 0, False),
                          ("qos-policy", "qos", 30, False)],
                         [(r["name"], r["kind"], r["dscp"], r["spawn_child"]) for r in harness.ROLES])

    def test_role_commands(self):
        probe, qos = pathlib.Path("bin/probe.exe"), pathlib.Path("bin/probe-qos.exe")
        case = dict(name="udp-external", proto="udp", timeout_ms=1500, count=3)
        out = pathlib.Path("private/clients.jsonl")
        roles = {r["name"]: r for r in harness.ROLES}
        client = ["client", "--role", "tagged-child", "--proto", "udp", "--target", "192.0.2.1", "--port", "443",
                  "--count", "3", "--timeout-ms", "1500", "--out", str(out)]
        self.assertEqual([str(probe), "launch", "--dscp", "10", "--", str(probe)] + client + ["--spawn-child"],
                         harness.role_command(roles["tagged-child"], case, "192.0.2.1", 443, out, probe, qos))
        untagged = harness.role_command(roles["untagged"], case, "192.0.2.1", 443, out, probe, qos)
        self.assertEqual([str(probe), "client", "--role", "untagged"], untagged[:4])
        self.assertEqual(str(qos), harness.role_command(roles["qos-policy"], case, "192.0.2.1", 443, out, probe,
                                                        qos)[0])

    def test_sniff_command(self):
        command = harness.sniff_command(pathlib.Path("p.exe"), "outbound", "marked", pathlib.Path("m.jsonl"),
                                        pathlib.Path("m.stop"))
        self.assertEqual(["p.exe", "sniff", "--filter", "outbound", "--label", "marked", "--out", "m.jsonl",
                          "--stop-file", "m.stop", "--max-seconds", "300"], command)

    def test_pktmon_steps(self):
        steps = harness.pktmon_start_steps("192.0.2.1", pathlib.Path("c.etl"))
        self.assertEqual([("filter_remove", ["pktmon", "filter", "remove"]),
                          ("filter_add", ["pktmon", "filter", "add", "job-dscp", "-i", "192.0.2.1"]),
                          ("start", ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "96",
                                     "--file-name", "c.etl"])], steps)
        self.assertEqual([["pktmon", "etl2pcap", "c.etl", "--out", "c.pcapng"],
                          ["pktmon", "pcapng", "c.etl", "-o", "c.pcapng"]],
                         harness.pktmon_convert_commands(pathlib.Path("c.etl"), pathlib.Path("c.pcapng")))


class RecordTests(unittest.TestCase):
    def test_read_jsonl_skips_invalid_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "x.jsonl"
            path.write_text('{"kind":"ready"}\nnot json\n[1]\n{"kind":"packet","seq":1}\n{"kind":"summ')
            records, invalid = harness.read_jsonl(path)
            self.assertEqual([{"kind": "ready"}, {"kind": "packet", "seq": 1}], records)
            self.assertEqual(3, invalid)
            self.assertEqual(([], 0), harness.read_jsonl(pathlib.Path(directory) / "missing"))

    def test_last_launch_record(self):
        stdout = 'noise\n{"kind":"launch","dscp_set":true}\n{"kind":"other"}\n'
        self.assertEqual({"kind": "launch", "dscp_set": True}, harness.launch_record(stdout))
        self.assertIsNone(harness.launch_record("garbage"))
        self.assertIsNone(harness.launch_record(None))

    def test_sniffer_result_from_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "s.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in (
                dict(kind="ready", label="observe"),
                dict(kind="packet", seq=1, tos=40),
                dict(kind="summary", received=1, recv_errors=0, parse_errors=0))) + "\n")
            result = harness.sniffer_result(path, exit_code=0)
            self.assertTrue(result["ready"])
            self.assertEqual([1], [p["seq"] for p in result["packets"]])
            self.assertEqual(1, result["summary"]["received"])
            self.assertEqual(0, result["exit_code"])
            path.write_text("garbage\n")
            result = harness.sniffer_result(path, exit_code=None)
            self.assertFalse(result["ready"])
            self.assertIsNone(result["summary"])

    def test_role_input_groups_attempts_by_role(self):
        attempts = [dict(kind="attempt", role="tagged-a", local_port=1), dict(kind="attempt", role="untagged",
                                                                             local_port=2)]
        roles = {r["name"]: r for r in harness.ROLES}
        value = harness.role_input(roles["tagged-a"], attempts, dict(returncode=0, stdout='{"kind":"launch"}'))
        self.assertEqual(["tagged-a"], [a["role"] for a in value["attempts"]])
        self.assertEqual({"kind": "launch"}, value["launch"])
        self.assertTrue(value["exit_ok"])
        self.assertEqual(10, value["expected_dscp"])
        failed = harness.role_input(roles["untagged"], attempts, dict(returncode=None, stdout=""))
        self.assertFalse(failed["exit_ok"])
        self.assertIsNone(failed["launch"])

    def test_assembled_case_input_is_analysable(self):
        roles = {r["name"]: r for r in harness.ROLES}
        observe = dict(ready=True, exit_code=0, packets=[], summary=dict(kind="summary"))
        value = harness.case_input(dict(name="tcp-loopback", proto="tcp", require_connect=False), "127.0.0.1",
                                   5000, [harness.role_input(roles["untagged"], [], dict(returncode=0, stdout=""))],
                                   dict(observe=observe, marked=observe), dict(status="not_applicable"), None,
                                   "created")
        result = analysis.analyze_case(value)
        self.assertEqual("tcp-loopback", result["case"])
        analysis.validate_public(result)


if __name__ == "__main__":
    unittest.main()
