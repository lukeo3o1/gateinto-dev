import contextlib
import io
import json
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock

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
        self.assertEqual([("tagged-a", "tagged", 10, 0), ("tagged-b", "tagged", 20, 0),
                          ("tagged-child", "tagged", 10, 2), ("untagged", "untagged", 0, 0),
                          ("qos-policy", "qos", 30, 0)],
                         [(r["name"], r["kind"], r["dscp"], r["spawn_depth"]) for r in harness.ROLES])

    def test_role_commands(self):
        probe, qos = pathlib.Path("bin/probe.exe"), pathlib.Path("bin/probe-qos.exe")
        case = dict(name="udp-external", proto="udp", timeout_ms=1500, count=3)
        out, log = pathlib.Path("private/clients.jsonl"), pathlib.Path("private/clients.log")
        roles = {r["name"]: r for r in harness.ROLES}
        client = ["client", "--role", "tagged-child", "--proto", "udp", "--target", "192.0.2.1", "--port", "443",
                  "--count", "3", "--timeout-ms", "1500", "--out", str(out), "--log", str(log)]
        self.assertEqual([str(probe), "launch", "--dscp", "10", "--", str(probe)] + client + ["--spawn-depth", "2"],
                         harness.role_command(roles["tagged-child"], case, "192.0.2.1", 443, out, log, probe, qos))
        tagged = harness.role_command(roles["tagged-a"], case, "192.0.2.1", 443, out, log, probe, qos)
        self.assertNotIn("--spawn-depth", tagged)
        self.assertEqual([str(probe), "launch", "--dscp", "10", "--", str(probe), "client"], tagged[:7])
        untagged = harness.role_command(roles["untagged"], case, "192.0.2.1", 443, out, log, probe, qos)
        self.assertEqual([str(probe), "client", "--role", "untagged"], untagged[:4])
        self.assertNotIn("--spawn-depth", untagged)
        self.assertEqual(str(qos), harness.role_command(roles["qos-policy"], case, "192.0.2.1", 443, out, log,
                                                        probe, qos)[0])

    def test_sniff_command(self):
        command = harness.sniff_command(pathlib.Path("p.exe"), "outbound", "marked", pathlib.Path("m.jsonl"),
                                        pathlib.Path("m.stop"))
        self.assertEqual(["p.exe", "sniff", "--filter", "outbound", "--label", "marked", "--out", "m.jsonl",
                          "--stop-file", "m.stop", "--max-seconds", "900"], command)

    def test_pktmon_steps(self):
        steps = harness.pktmon_start_steps("192.0.2.1", pathlib.Path("c.etl"))
        self.assertEqual([("filter_remove", ["pktmon", "filter", "remove"]),
                          ("filter_add", ["pktmon", "filter", "add", "job-dscp", "-i", "192.0.2.1"]),
                          ("start", ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "96",
                                     "--file-name", "c.etl"])], steps)
        self.assertEqual([["pktmon", "etl2pcap", "c.etl", "--out", "c.pcapng"],
                          ["pktmon", "pcapng", "c.etl", "-o", "c.pcapng"]],
                         harness.pktmon_convert_commands(pathlib.Path("c.etl"), pathlib.Path("c.pcapng")))


class PktmonTests(unittest.TestCase):
    def test_pktmon_calls_are_bounded(self):
        self.assertEqual(30, harness.PKTMON_TIMEOUT_SECONDS)

    def test_run_quiet_maps_any_exception_to_none(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "p.log"
            for error in (OSError("C:\\secret"), ValueError("x"), subprocess.TimeoutExpired(["pktmon"], 30)):
                with mock.patch.object(harness.subprocess, "run", side_effect=error):
                    self.assertIsNone(harness.run_quiet(["pktmon", "stop"], log))
            self.assertEqual(-1, harness.run_quiet(["job-dscp-command-that-does-not-exist"], log))

    def test_nic_steps_report_exceptions(self):
        with tempfile.TemporaryDirectory() as directory:
            private = pathlib.Path(directory)
            with mock.patch.object(harness, "run_quiet", return_value=None):
                self.assertEqual(dict(status="unavailable", step="exception"), harness.nic_start("192.0.2.1", private))
                self.assertEqual(dict(status="unavailable", step="exception"), harness.nic_finish(private))
            with mock.patch.object(harness, "run_quiet", return_value=5):
                self.assertEqual(dict(status="unavailable", step="filter_remove", exit_code=5),
                                 harness.nic_start("192.0.2.1", private))


class CleanupTests(unittest.TestCase):
    def test_every_cleanup_action_runs(self):
        calls = []

        def failing():
            calls.append("a")
            raise OSError("C:\\secret")

        failed = harness.run_all([("nic", failing), ("observe", lambda: calls.append("b")),
                                  ("listener", lambda: calls.append("c"))])
        self.assertEqual(["a", "b", "c"], calls)
        self.assertEqual(["nic"], failed)


class DeadlineTests(unittest.TestCase):
    def test_role_after_deadline_is_skipped(self):
        ctx = harness.Context(pathlib.Path("p"), pathlib.Path("q"), pathlib.Path("."), "created", None,
                              deadline=time.monotonic() - 1)
        role = {r["name"]: r for r in harness.ROLES}["untagged"]
        result = harness.run_role(ctx, role, dict(count=3, timeout_ms=1500, proto="tcp"), "192.0.2.1", 443,
                                  pathlib.Path("c"), pathlib.Path("l"), pathlib.Path("."))
        self.assertEqual("deadline", result["skipped"])
        self.assertTrue(ctx.deadline_hit)


class MainTests(unittest.TestCase):
    def run_main(self, **patches):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(harness, "resolve_github", return_value=None))
                for name, value in patches.items():
                    target = analysis if name == "build_aggregate" else harness
                    stack.enter_context(mock.patch.object(target, name, value))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                code = harness.main(["--bin", str(root / "secret-bin"), "--results", str(root / "results"),
                                     "--private", str(root / "private")])
            files = {p.name: p.read_text() for p in (root / "results").glob("*") if p.is_file()}
            errors = (root / "private" / "harness-errors.log")
            return code, stdout.getvalue() + stderr.getvalue(), files, errors.read_text() if errors.exists() else ""

    def assert_private(self, output):
        for token in ("secret", "\\", "/", "192.0.2"):
            self.assertNotIn(token, output)

    def test_failing_probe_env_prints_only_the_type_and_exits_1(self):
        error = subprocess.TimeoutExpired(["C:\\secret\\probe.exe", "env"], 60)
        code, output, files, log = self.run_main(CASES=[], probe_env=mock.Mock(side_effect=error))
        self.assertEqual(1, code)
        self.assertIn("TimeoutExpired", output)
        self.assert_private(output)
        self.assertIn("secret", log)
        self.assertIn("aggregate-evidence.json", files)
        self.assertFalse(json.loads(files["ci-summary.json"])["harness_ok"])

    def test_any_main_failure_prints_only_the_type(self):
        code, output, files, log = self.run_main(
            CASES=[], probe_env=mock.Mock(return_value={}),
            build_aggregate=mock.Mock(side_effect=ValueError("C:\\secret 192.0.2.7:443")))
        self.assertEqual(1, code)
        self.assertIn("ValueError", output)
        self.assert_private(output)
        self.assertIn("secret", log)

    def test_deadline_skips_remaining_cases_but_writes_the_aggregate(self):
        run_case = mock.Mock(side_effect=AssertionError("must not run"))
        code, output, files, _ = self.run_main(probe_env=mock.Mock(return_value={}), run_case=run_case,
                                               HARNESS_DEADLINE_SECONDS=0)
        self.assertEqual(1, code)
        run_case.assert_not_called()
        aggregate = json.loads(files["aggregate-evidence.json"])
        self.assertEqual({"SKIPPED_DEADLINE"}, set(aggregate["verdicts"].values()))
        self.assertEqual(len(harness.CASES), len(json.loads(files["ci-summary.json"])["failed_cases"]))
        self.assert_private(output)

    def test_case_exception_prints_only_the_type(self):
        run_case = mock.Mock(side_effect=OSError("C:\\secret"))
        code, output, files, log = self.run_main(probe_env=mock.Mock(return_value={}), run_case=run_case)
        self.assertEqual(1, code)
        self.assertIn("HARNESS_ERROR", output)
        self.assert_private(output)


class RecordTests(unittest.TestCase):
    def test_client_error_lines_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "clients.log"
            self.assertEqual(0, harness.client_error_count(path))
            path.write_text("client error: C:\\x\n\nclient error: y\n")
            self.assertEqual(2, harness.client_error_count(path))

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
                                   "created", 3)
        result = analysis.analyze_case(value)
        self.assertEqual("tcp-loopback", result["case"])
        self.assertEqual(3, result["client_error_lines"])
        analysis.validate_public(result)


if __name__ == "__main__":
    unittest.main()
