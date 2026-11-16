import contextlib
import io
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import analysis
import harness

ROOT = pathlib.Path(__file__).parent
R = "192.0.2.10"


class PlanTests(unittest.TestCase):
    def test_roles(self):
        self.assertEqual([("untagged", "untagged", 0), ("tagged-a", "tagged", 10), ("tagged-b", "tagged", 20)],
                         [(r["name"], r["kind"], r["dscp"]) for r in harness.ROLES])
        self.assertEqual(("tagged-no-engine", "tagged", 10), (harness.BASELINE_ROLE["name"],
                                                              harness.BASELINE_ROLE["kind"],
                                                              harness.BASELINE_ROLE["dscp"]))
        self.assertEqual(3, harness.ATTEMPTS)
        for role in harness.ROLES + [harness.BASELINE_ROLE]:
            self.assertEqual(analysis.EXPECTED_DSCP.get(role["name"], 0), role["dscp"])

    def test_budgets(self):
        self.assertGreater(harness.LAB_SECONDS, harness.HARNESS_DEADLINE_SECONDS)
        self.assertGreater(harness.ENGINE_MAX_SECONDS, harness.HARNESS_DEADLINE_SECONDS)
        self.assertGreater(harness.ATTEMPT_TIMEOUT_SECONDS, 25)
        self.assertEqual(30, harness.PKTMON_TIMEOUT_SECONDS)

    def test_curl_command(self):
        self.assertEqual(["C:\\curl.exe", "--noproxy", "*", "--resolve", f"github.com:443:{R}", "--ssl-no-revoke",
                          "-sS", "-o", "NUL", "--connect-timeout", "10", "--max-time", "25", "-w",
                          harness.CURL_FORMAT, "https://github.com/"],
                         harness.curl_command("C:\\curl.exe", R))

    def test_curl_format_is_parseable_once_expanded(self):
        expanded = harness.CURL_FORMAT
        for name, value in dict(http_code="301", local_port="50011", remote_ip=R, num_connects="1",
                                time_connect="0.012", time_appconnect="0.04", time_total="0.1").items():
            self.assertIn("%{" + name + "}", expanded)
            expanded = expanded.replace("%{" + name + "}", value)
        self.assertNotIn("%", expanded)
        self.assertEqual(dict(http_code=301, local_port=50011, remote_ip=R, num_connects=1, time_connect=0.012,
                              time_appconnect=0.04, time_total=0.1), analysis.parse_curl_output(expanded))

    def test_attempt_commands(self):
        roles = {r["name"]: r for r in harness.ROLES}
        out, err = pathlib.Path("p/a.out"), pathlib.Path("p/a.err")
        curl = harness.curl_command("curl.exe", R)
        self.assertEqual(["route.exe", "launch", "--dscp", "20", "--stdout", str(out), "--stderr", str(err), "--"]
                         + curl, harness.attempt_command(roles["tagged-b"], "route.exe", "curl.exe", R, out, err))
        self.assertEqual(curl, harness.attempt_command(roles["untagged"], "route.exe", "curl.exe", R, out, err))

    def test_engine_command_and_filter(self):
        self.assertEqual(["route.exe", "engine", "--listener-port", "8443", "--map", "m.jsonl", "--stop-file",
                          "e.stop", "--max-seconds", str(harness.ENGINE_MAX_SECONDS)],
                         harness.engine_command("route.exe", 8443, pathlib.Path("m.jsonl"), pathlib.Path("e.stop")))
        self.assertEqual(["route.exe", "engine", "--listener-port", "8443", "--map", "m.jsonl", "--stop-file",
                          "e.stop", "--max-seconds", str(harness.ENGINE_MAX_SECONDS), "--match-dscp", "43", "--contain"],
                         harness.engine_command("route.exe", 8443, pathlib.Path("m.jsonl"), pathlib.Path("e.stop"),
                                                ["--match-dscp", "43", "--contain"]))
        self.assertEqual("outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == 8443)",
                         harness.engine_filter(8443))
        source = (ROOT / "route.cpp").read_text()
        self.assertIn('"outbound and !loopback and ip and tcp and (ip.TOS >= 4 or tcp.SrcPort == " +', source)
        self.assertIn('engine_filter(8443) ==\n          "' + harness.engine_filter(8443) + '"', source)
        for port in (0, 65536, "1 or true", True):
            with self.assertRaises(ValueError):
                harness.engine_filter(port)

    def test_lab_command(self):
        self.assertEqual(["lab.exe", "--manifest", "m.json", "--out", "o", "--seconds", str(harness.LAB_SECONDS)],
                         harness.lab_command("lab.exe", pathlib.Path("m.json"), pathlib.Path("o")))

    def test_firewall_commands(self):
        self.assertEqual("gateinto-job-dscp-route-bridge", harness.FIREWALL_RULE)
        self.assertEqual(["netsh", "advfirewall", "firewall", "add", "rule", f"name={harness.FIREWALL_RULE}",
                          "dir=in", "action=allow", "protocol=TCP", "localport=8443", f"remoteip={R}"],
                         harness.firewall_add_command(8443, R))
        self.assertEqual(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={harness.FIREWALL_RULE}"],
                         harness.firewall_delete_command())
        with self.assertRaises(ValueError):
            harness.firewall_add_command(8443, "192.0.2.10 dir=out")

    def test_pktmon_steps(self):
        self.assertEqual([("filter_remove", ["pktmon", "filter", "remove"]),
                          ("filter_add", ["pktmon", "filter", "add", "job-dscp-route", "-i", R]),
                          ("start", ["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "96",
                                     "--file-name", "c.etl"])],
                         harness.pktmon_start_steps(R, pathlib.Path("c.etl")))
        self.assertEqual([["pktmon", "etl2pcap", "c.etl", "--out", "c.pcapng"],
                          ["pktmon", "pcapng", "c.etl", "-o", "c.pcapng"]],
                         harness.pktmon_convert_commands(pathlib.Path("c.etl"), pathlib.Path("c.pcapng")))


class TargetTests(unittest.TestCase):
    def test_resolve_target_returns_one_ipv4_address(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (R, 443))]
        with mock.patch.object(harness.socket, "getaddrinfo", return_value=infos) as lookup:
            self.assertEqual(R, harness.resolve_target("github.com"))
        self.assertEqual(socket.AF_INET, lookup.call_args[0][2])
        with mock.patch.object(harness.socket, "getaddrinfo", side_effect=OSError("x")):
            self.assertIsNone(harness.resolve_target("github.com"))
        with mock.patch.object(harness.socket, "getaddrinfo", return_value=[]):
            self.assertIsNone(harness.resolve_target("github.com"))

    def test_local_address(self):
        self.assertEqual("127.0.0.1", harness.local_address_for("127.0.0.1"))
        self.assertIsNone(harness.local_address_for(None))
        with mock.patch.object(harness.socket, "socket", side_effect=OSError("x")):
            self.assertIsNone(harness.local_address_for(R))


class RecordTests(unittest.TestCase):
    def test_read_jsonl_skips_invalid_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "x.jsonl"
            path.write_text('{"kind":"ready"}\nnot json\n[1]\n{"kind":"summary","captured":1}\n{"kind"')
            self.assertEqual(([{"kind": "ready"}, {"kind": "summary", "captured": 1}], 3), harness.read_jsonl(path))
            self.assertEqual(([], 0), harness.read_jsonl(pathlib.Path(directory) / "missing"))

    def test_launch_record(self):
        self.assertEqual({"kind": "launch", "child_ran": True},
                         harness.launch_record('noise\n{"kind":"launch","child_ran":true}\n{"kind":"x"}\n'))
        self.assertIsNone(harness.launch_record("garbage"))
        setup = '{"kind":"launch_setup","assigned":true}\n'
        self.assertEqual({"kind": "launch_setup", "assigned": True}, harness.launch_record(setup + '{"kind":"launch'))
        self.assertEqual({"kind": "launch", "resumed": True},
                         harness.launch_record(setup + '{"kind":"launch","resumed":true}\n'))
        self.assertIsNone(harness.launch_record(None))

    def test_engine_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "engine.jsonl"
            path.write_text('{"kind":"ready"}\n{"kind":"summary","new_flows":6}\n')
            self.assertEqual(dict(ready=True, exit_code=0, summary={"kind": "summary", "new_flows": 6}),
                             harness.engine_result(path, 0))
            path.write_text("garbage\n")
            self.assertEqual(dict(ready=False, exit_code=None, summary=None), harness.engine_result(path, None))

    def test_read_gateway(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "gateway.jsonl"
            path.write_text(f'{{"kind":"gateway_connect","index":0,"request_line":"CONNECT {R}:443 HTTP/1.1"}}\n'
                            '{"kind":"other","request_line":"x"}\nbroken\n')
            self.assertEqual(dict(read=True, lines=[f"CONNECT {R}:443 HTTP/1.1"]), harness.read_gateway(path))
            self.assertEqual(dict(read=False, lines=[]), harness.read_gateway(pathlib.Path(directory) / "missing"))


def context(root, deadline=None):
    return harness.Context(route=pathlib.Path("route.exe"), curl="curl.exe", lab=pathlib.Path("lab.exe"),
                           private=root, target_ip=R, local_ip="10.1.0.4", deadline=deadline)


class AttemptTests(unittest.TestCase):
    def test_untagged_attempt_reads_curl_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)

            def fake_run(command, stdout, stderr, timeout):
                stdout.write(b'{"http_code":"200","local_port":"50001"}')
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(harness.subprocess, "run", side_effect=fake_run) as run:
                attempt = harness.run_attempt(context(root), harness.ROLES[0], 1)
            self.assertEqual("curl.exe", run.call_args[0][0][0])
            self.assertEqual(harness.ATTEMPT_TIMEOUT_SECONDS, run.call_args[1]["timeout"])
            self.assertEqual(dict(role="untagged", index=1, exit_code=0, timed_out=False, skipped=None,
                                  launch=None), {k: v for k, v in attempt.items() if k != "curl"})
            self.assertEqual(200, attempt["curl"]["http_code"])

    def test_tagged_attempt_uses_the_launch_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)

            def fake_run(command, stdout, stderr, timeout):
                pathlib.Path(command[command.index("--stdout") + 1]).write_text('{"http_code":"000"}')
                return subprocess.CompletedProcess(command, 28, stdout=b'{"kind":"launch","child_ran":true,'
                                                                        b'"child_exit_code":28}\n')

            with mock.patch.object(harness.subprocess, "run", side_effect=fake_run) as run:
                attempt = harness.run_attempt(context(root), harness.ROLES[1], 0)
            self.assertEqual(["route.exe", "launch", "--dscp", "10"], run.call_args[0][0][:4])
            self.assertEqual(28, attempt["exit_code"])
            self.assertEqual(0, attempt["curl"]["http_code"])
            self.assertTrue(attempt["launch"]["child_ran"])

            def not_ran(command, stdout, stderr, timeout):
                return subprocess.CompletedProcess(command, 125, stdout=b'{"kind":"launch","child_ran":false,'
                                                                         b'"child_exit_code":0}\n')

            with mock.patch.object(harness.subprocess, "run", side_effect=not_ran):
                attempt = harness.run_attempt(context(root), harness.ROLES[1], 1)
            self.assertIsNone(attempt["exit_code"])
            self.assertIsNone(attempt["curl"])

    def test_tagged_timeout_keeps_the_setup_record(self):
        with tempfile.TemporaryDirectory() as directory:
            error = subprocess.TimeoutExpired(["route.exe"], 45, output=b'{"kind":"launch_setup","assigned":true}\n')
            with mock.patch.object(harness.subprocess, "run", side_effect=error):
                attempt = harness.run_attempt(context(pathlib.Path(directory)), harness.ROLES[1], 0)
            self.assertTrue(attempt["timed_out"])
            self.assertEqual({"kind": "launch_setup", "assigned": True}, attempt["launch"])
            self.assertIsNone(attempt["exit_code"])

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            error = subprocess.TimeoutExpired(["curl.exe"], 45)
            with mock.patch.object(harness.subprocess, "run", side_effect=error):
                attempt = harness.run_attempt(context(pathlib.Path(directory)), harness.ROLES[2], 2)
            self.assertTrue(attempt["timed_out"])
            self.assertIsNone(attempt["exit_code"])

    def test_deadline_skips(self):
        ctx = context(pathlib.Path("."), deadline=time.monotonic() - 1)
        with mock.patch.object(harness.subprocess, "run", side_effect=AssertionError("must not run")):
            attempts = harness.run_role(ctx, harness.ROLES[0])
        self.assertEqual(["deadline"] * 3, [a["skipped"] for a in attempts])
        self.assertTrue(ctx.deadline_hit)


class FirewallTests(unittest.TestCase):
    def test_add_removes_a_stale_rule_first_and_reports_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(harness, "run_quiet", side_effect=[1, 0]) as run:
                self.assertEqual("added", harness.add_firewall(root, 8443, R))
            self.assertEqual(harness.firewall_delete_command(), run.call_args_list[0][0][0])
            self.assertEqual(harness.firewall_add_command(8443, R), run.call_args_list[1][0][0])
            for code in (1, None, -1):
                with mock.patch.object(harness, "run_quiet", side_effect=[0, code]):
                    self.assertEqual("failed", harness.add_firewall(root, 8443, R))


    def test_removal_fails_only_for_an_added_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(harness, "run_quiet", return_value=1) as run:
                harness.remove_firewall(root, "failed")
                with self.assertRaises(RuntimeError):
                    harness.remove_firewall(root, "added")
            self.assertEqual([mock.call(harness.firewall_delete_command(), root / "firewall.log")] * 2,
                             run.call_args_list)
            with mock.patch.object(harness, "run_quiet", return_value=0):
                harness.remove_firewall(root, "added")


class PktmonTests(unittest.TestCase):
    def test_run_quiet_maps_any_exception_to_none(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "p.log"
            for error in (OSError("C:\\secret"), ValueError("x"), subprocess.TimeoutExpired(["pktmon"], 30)):
                with mock.patch.object(harness.subprocess, "run", side_effect=error):
                    self.assertIsNone(harness.run_quiet(["pktmon", "stop"], log))
            self.assertEqual(-1, harness.run_quiet(["job-dscp-route-command-that-does-not-exist"], log))

    def test_nic_steps_report_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            private = pathlib.Path(directory)
            with mock.patch.object(harness, "run_quiet", return_value=None):
                self.assertEqual(dict(status="unavailable", step="exception"), harness.nic_start(R, private))
                self.assertEqual(dict(status="unavailable", step="exception"), harness.nic_finish(private))
            with mock.patch.object(harness, "run_quiet", return_value=5):
                self.assertEqual(dict(status="unavailable", step="filter_add", exit_code=5),
                                 harness.nic_start(R, private))
            with mock.patch.object(harness, "run_quiet", side_effect=[1, 0, 0]):
                self.assertIsNone(harness.nic_start(R, private))
            self.assertEqual(dict(status="unavailable", step="exception"),
                             harness.guarded_nic(mock.Mock(side_effect=OSError("x")), private))


class CleanupTests(unittest.TestCase):
    def test_every_cleanup_action_runs(self):
        calls = []

        def failing():
            calls.append("a")
            raise OSError("C:\\secret")

        self.assertEqual(["engine"], harness.run_all([("engine", failing), ("bridge", lambda: calls.append("b")),
                                                      ("lab", lambda: calls.append("c"))]))
        self.assertEqual(["a", "b", "c"], calls)

    def test_stop_process_kills_when_terminate_is_ignored(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("x", 5), 0]
        harness.stop_process(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        harness.stop_process(None)


class RunCaseOrderTests(unittest.TestCase):
    def test_phases_and_cleanup_order(self):
        calls = []
        relay = mock.Mock(port=8443)
        relay.stats.return_value = dict(started=True, close_ok=True, accepted=0, tunnels=0, errors=0, error_kinds={})

        def record(name, result=None):
            def action(*args, **kwargs):
                calls.append(name)
                return result
            return action

        engine = dict(ready=True)
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            ctx = context(pathlib.Path(directory))
            for name, value in dict(
                    start_lab=record("lab", (mock.Mock(), dict(proxy_host="127.0.0.1", proxy_port=1,
                                                               proxy_authorization="x"), pathlib.Path("g"))),
                    add_firewall=record("firewall", "added"),
                    run_role=lambda c, role: calls.append(role["name"]) or [],
                    nic_start=record("nic_start"), nic_finish=record("nic_finish", dict(status="ok", packets=[])),
                    start_engine=record("engine_start", engine),
                    stop_engine=record("engine_stop", dict(ready=True, exit_code=0, summary={})),
                    final_gateway=record("gateway", dict(read=True, lines=[])), stop_process=record("lab_stop"),
                    remove_firewall=record("firewall_remove")).items():
                stack.enter_context(mock.patch.object(harness, name, value))
            bridge_class = stack.enter_context(mock.patch.object(harness.bridge, "Bridge", return_value=relay))
            sleep = stack.enter_context(mock.patch.object(harness.time, "sleep",
                                                          side_effect=lambda s: calls.append(f"sleep {s}")))
            analyze = stack.enter_context(mock.patch.object(harness.analysis, "analyze", return_value={}))
            harness.run_case(ctx)
        self.assertEqual("0.0.0.0", bridge_class.call_args[0][0])
        self.assertEqual(["lab", "firewall", "tagged-no-engine", f"sleep {harness.BASELINE_SETTLE_SECONDS}",
                          "nic_start", "engine_start", "untagged", "tagged-a", "tagged-b",
                          f"sleep {harness.SETTLE_SECONDS}", "nic_finish", "engine_stop", "gateway", "lab_stop",
                          "firewall_remove"], calls)
        self.assertGreaterEqual(harness.BASELINE_SETTLE_SECONDS, 2)
        sleep.assert_called()
        self.assertEqual(8443, analyze.call_args[0][0]["bridge_port"])


def measured(name, verdict="NOT_ROUTED"):
    return lambda ctx: dict(case=name, verdict=verdict)


EXTENSIONS = ["load", "shared-dscp", "qos-policy", "udp-containment"]


class MainTests(unittest.TestCase):
    def run_main(self, runners=None, extra_args=(), **patches):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            if runners is None:
                runners = [("https-external", measured("https-external", "ROUTED_VIA_GATEWAY"))] + [
                    (n, measured(n)) for n in EXTENSIONS]
            with contextlib.ExitStack() as stack:
                defaults = dict(resolve_target=mock.Mock(return_value=R), probe_env=mock.Mock(return_value={}),
                                case_runners=mock.Mock(return_value=runners))
                defaults.update(patches)
                for name, value in defaults.items():
                    if value is None:
                        continue
                    stack.enter_context(mock.patch.object(analysis if name == "build_report" else harness, name,
                                                          value))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                code = harness.main(["--bin", str(root / "secret-bin"), "--lab", str(root / "secret-lab.exe"),
                                     "--curl", str(root / "secret-curl.exe"), "--results", str(root / "results"),
                                     "--private", str(root / "private")] + list(extra_args))
            files = {p.name: p.read_text() for p in (root / "results").glob("*") if p.is_file()}
            log = "".join(p.read_text() for p in sorted((root / "private").rglob("harness-errors.log")))
            return code, stdout.getvalue() + stderr.getvalue(), files, log

    def assert_private(self, output):
        for token in ("secret", "\\", "/", "192.0.2"):
            self.assertNotIn(token, output)

    def verdicts(self, files):
        return json.loads(files["aggregate-evidence.json"])["verdicts"]

    def test_budgets(self):
        self.assertEqual(20 * 60, harness.HARNESS_DEADLINE_SECONDS)
        self.assertEqual(["https-external"] + EXTENSIONS, list(harness.CASE_BUDGETS))
        self.assertLessEqual(sum(harness.CASE_BUDGETS.values()), harness.HARNESS_DEADLINE_SECONDS)
        self.assertGreaterEqual(harness.CASE_BUDGETS["https-external"], 420)
        self.assertEqual(["https-external"] + EXTENSIONS, [name for name, _ in harness.case_runners({})])

    def test_measured_verdicts_are_green(self):
        code, output, files, _ = self.run_main()
        self.assertEqual(0, code)
        self.assertEqual(["https-external"] + EXTENSIONS, list(self.verdicts(files)))
        summary = json.loads(files["ci-summary.json"])
        self.assertEqual((True, [], "ROUTED_VIA_GATEWAY"), (summary["harness_ok"], summary["harness_faults"],
                                                            summary["verdicts"]["https-external"]))
        for name in EXTENSIONS:
            self.assertIn(f"Case {name}: NOT_ROUTED", output)
        self.assertIn("| udp-containment | NOT_ROUTED |", files["summary.md"])
        self.assertNotIn("PENDING", files["aggregate-evidence.json"])

    def test_each_case_prints_its_public_result_between_markers(self):
        code, output, _, _ = self.run_main()
        lines = output.splitlines()
        for name in ["https-external"] + EXTENSIONS:
            begin = lines.index(f"=== JOB-DSCP-ROUTE CASE {name} BEGIN ===")
            self.assertEqual(f"=== JOB-DSCP-ROUTE CASE {name} END ===", lines[begin + 2])
            self.assertEqual(name, json.loads(lines[begin + 1])["case"])
        self.assertEqual({"case": "load", "verdict": "NOT_ROUTED"},
                         json.loads(lines[lines.index("=== JOB-DSCP-ROUTE CASE load BEGIN ===") + 1]))

    def test_progress_is_written_after_every_case(self):
        snapshots = []

        def inspect(name):
            def runner(ctx):
                results = ctx.private.parent.parent / "results"
                snapshots.append((json.loads((results / "aggregate-evidence.json").read_text())["verdicts"],
                                  json.loads((results / "ci-summary.json").read_text())["harness_ok"],
                                  (results / "summary.md").read_text()))
                return dict(case=name, verdict="NOT_ROUTED")
            return runner

        self.run_main(runners=[("https-external", measured("https-external", "ROUTED_VIA_GATEWAY")),
                               ("load", inspect("load")), ("shared-dscp", inspect("shared-dscp"))])
        self.assertEqual({"https-external": "ROUTED_VIA_GATEWAY", "load": "PENDING", "shared-dscp": "PENDING"},
                         snapshots[0][0])
        self.assertEqual({"https-external": "ROUTED_VIA_GATEWAY", "load": "NOT_ROUTED", "shared-dscp": "PENDING"},
                         snapshots[1][0])
        self.assertFalse(snapshots[0][1])
        self.assertIn("| shared-dscp | PENDING |", snapshots[1][2])

    def test_a_killed_run_leaves_the_finished_cases_on_disk(self):
        def killed(ctx):
            raise SystemExit(137)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runners = [("https-external", measured("https-external", "ROUTED_VIA_GATEWAY")), ("load", killed),
                       ("shared-dscp", measured("shared-dscp"))]
            with mock.patch.object(harness, "resolve_target", return_value=R), \
                    mock.patch.object(harness, "probe_env", return_value={}), \
                    mock.patch.object(harness, "case_runners", return_value=runners), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, self.assertRaises(SystemExit):
                harness.main(["--bin", str(root / "b"), "--lab", str(root / "l"), "--results", str(root / "results"),
                              "--private", str(root / "private")])
            aggregate = json.loads((root / "results" / "aggregate-evidence.json").read_text())
            summary = json.loads((root / "results" / "ci-summary.json").read_text())
        self.assertEqual({"https-external": "ROUTED_VIA_GATEWAY", "load": "PENDING", "shared-dscp": "PENDING"},
                         aggregate["verdicts"])
        self.assertFalse(summary["harness_ok"])
        self.assertEqual(["load", "shared-dscp"], summary["pending"])
        self.assertIn("=== JOB-DSCP-ROUTE CASE https-external BEGIN ===", stdout.getvalue())

    def test_intermediate_output_failures_are_recorded_once_and_never_stop_the_run(self):
        real_write, real_print = harness.write_results, harness.print_case
        calls = dict(write=0, print=0)

        def flaky_write(*args):
            calls["write"] += 1
            if calls["write"] in (1, 2):
                raise PermissionError("C:\\secret\\aggregate-evidence.json")
            return real_write(*args)

        def flaky_print(result):
            calls["print"] += 1
            if calls["print"] == 2:
                raise OSError("C:\\secret")
            return real_print(result)

        later = mock.Mock(side_effect=measured("udp-containment"))
        runners = [("https-external", measured("https-external", "ROUTED_VIA_GATEWAY")), ("load", measured("load")),
                   ("shared-dscp", measured("shared-dscp")), ("udp-containment", later)]
        code, output, files, log = self.run_main(runners=runners, write_results=flaky_write, print_case=flaky_print)
        later.assert_called_once()
        self.assertEqual(1, code)
        self.assertNotIn("PENDING", files["aggregate-evidence.json"])
        self.assertEqual(4, len(self.verdicts(files)))
        summary = json.loads(files["ci-summary.json"])
        self.assertEqual(["intermediate-write"], summary["harness_faults"])
        self.assertFalse(summary["harness_ok"])
        self.assertIn("PermissionError", output)
        self.assertIn("OSError", output)
        self.assert_private(output)
        self.assertIn("secret", log)

    def test_load_runs_only_when_the_core_routed(self):
        for core, expected in (("ROUTED_VIA_GATEWAY", "NOT_ROUTED"), ("PARTIAL", "NOT_ROUTED"),
                               ("NOT_ROUTED", "NOT_RUN_CORE_NOT_ROUTED"), ("HARNESS_ERROR", "NOT_RUN_CORE_NOT_ROUTED"),
                               ("INCONCLUSIVE_TARGET_UNREACHABLE", "NOT_RUN_CORE_NOT_ROUTED")):
            load = mock.Mock(side_effect=measured("load"))
            shared = mock.Mock(side_effect=measured("shared-dscp"))
            code, _, files, _ = self.run_main(runners=[("https-external", measured("https-external", core)),
                                                       ("load", load), ("shared-dscp", shared)])
            self.assertEqual(expected, self.verdicts(files)["load"], core)
            self.assertEqual(expected == "NOT_ROUTED", load.called, core)
            shared.assert_called_once()
            self.assertEqual(core != "HARNESS_ERROR", code == 0, core)

    def test_each_case_gets_its_own_directory_and_budget(self):
        seen = []

        def record(name):
            def runner(ctx):
                seen.append((name, ctx.private, ctx.deadline - time.monotonic()))
                return dict(case=name, verdict="ROUTED_VIA_GATEWAY" if name == "https-external" else "NOT_ROUTED")
            return runner

        self.run_main(runners=[(n, record(n)) for n in ["https-external"] + EXTENSIONS])
        self.assertEqual(len(set(path for _, path, _ in seen)), 5)
        for name, path, remaining in seen:
            self.assertEqual(name, path.name)
            self.assertLessEqual(remaining, harness.CASE_BUDGETS[name])

    def test_extension_failures_never_touch_the_core_or_later_cases(self):
        def crash(ctx):
            raise OSError("C:\\secret 192.0.2.7")

        def leaky(ctx):
            return dict(case="shared-dscp", verdict="ROUTED_AND_ATTRIBUTED", note="192.0.2.7")

        runners = [("https-external", measured("https-external", "ROUTED_VIA_GATEWAY")), ("load", crash),
                   ("shared-dscp", leaky), ("qos-policy", measured("qos-policy", "JOB_TAG_WINS")),
                   ("udp-containment", measured("udp-containment", "CONTAINED"))]
        code, output, files, log = self.run_main(runners=runners)
        self.assertEqual(1, code)
        self.assertEqual({"https-external": "ROUTED_VIA_GATEWAY", "load": "HARNESS_ERROR",
                          "shared-dscp": "HARNESS_ERROR", "qos-policy": "JOB_TAG_WINS",
                          "udp-containment": "CONTAINED"}, self.verdicts(files))
        aggregate = json.loads(files["aggregate-evidence.json"])
        self.assertEqual(("OSError", "ValueError"), (aggregate["cases"]["load"]["error_type"],
                                                     aggregate["cases"]["shared-dscp"]["error_type"]))
        self.assertEqual(["load", "shared-dscp"], aggregate["harness_errors"])
        self.assert_private(output)
        self.assertIn("secret", log)

    def test_core_exception_still_runs_later_cases(self):
        later = mock.Mock(side_effect=measured("shared-dscp"))

        def crash(ctx):
            raise RuntimeError("x")

        code, _, files, _ = self.run_main(runners=[("https-external", crash), ("shared-dscp", later)])
        self.assertEqual(1, code)
        later.assert_called_once()
        self.assertEqual({"https-external": "HARNESS_ERROR", "shared-dscp": "NOT_ROUTED"}, self.verdicts(files))

    def test_failing_env_probe_prints_only_the_type_and_exits_1(self):
        code, output, files, log = self.run_main(
            probe_env=mock.Mock(side_effect=subprocess.TimeoutExpired(["C:\\secret\\route.exe", "env"], 60)))
        self.assertEqual(1, code)
        self.assertIn("TimeoutExpired", output)
        self.assert_private(output)
        self.assertIn("secret", log)
        self.assertEqual(["env"], json.loads(files["ci-summary.json"])["harness_faults"])

    def test_any_main_failure_prints_only_the_type(self):
        code, output, _, log = self.run_main(build_report=mock.Mock(side_effect=ValueError("C:\\secret")))
        self.assertEqual(1, code)
        self.assertIn("ValueError", output)
        self.assert_private(output)
        self.assertIn("secret", log)

    def test_deadline_clock_starts_before_target_resolution(self):
        runner = mock.Mock(side_effect=AssertionError("must not run"))
        code, _, files, _ = self.run_main(runners=[("https-external", runner), ("load", runner)],
                                          resolve_target=mock.Mock(side_effect=lambda host: time.sleep(0.2)),
                                          HARNESS_DEADLINE_SECONDS=0.1)
        self.assertEqual(1, code)
        runner.assert_not_called()
        self.assertEqual({"https-external": "SKIPPED_DEADLINE", "load": "SKIPPED_DEADLINE"}, self.verdicts(files))

    def test_unresolvable_target_is_green_for_every_case(self):
        guard = mock.Mock(side_effect=AssertionError("must not run"))
        with mock.patch.object(harness, "start_lab", guard):
            code, output, files, _ = self.run_main(runners=None, case_runners=None,
                                                   resolve_target=mock.Mock(return_value=None))
        guard.assert_not_called()
        self.assertEqual(0, code)
        verdicts = self.verdicts(files)
        self.assertEqual("NOT_RUN_CORE_NOT_ROUTED", verdicts.pop("load"))
        self.assertEqual({"INCONCLUSIVE_TARGET_UNREACHABLE"}, set(verdicts.values()))
        self.assertEqual(4, len(verdicts))
        self.assertEqual({"aggregate-evidence.json", "ci-summary.json", "environment.json", "summary.md"},
                         set(files))
        self.assert_private(output)

    def test_cleanup_failure_is_red(self):
        def with_cleanup_failure(ctx):
            ctx.cleanup_failures += 1
            return dict(case="shared-dscp", verdict="NOT_ROUTED")

        code, _, files, _ = self.run_main(runners=[("https-external", measured("https-external")),
                                                   ("shared-dscp", with_cleanup_failure)])
        self.assertEqual(1, code)
        self.assertEqual(["cleanup"], json.loads(files["ci-summary.json"])["harness_faults"])

    def test_qos_arguments_reach_the_qos_case(self):
        import cases
        received = []
        with mock.patch.object(cases, "run_qos", side_effect=lambda ctx, qos: received.append(qos) or
                               dict(case="qos-policy", verdict="JOB_TAG_WINS")):
            runners = harness.case_runners(dict(status="created", reason=None, curl="c"))
            dict(runners)["qos-policy"](None)
        self.assertEqual([dict(status="created", reason=None, curl="c")], received)
        code, _, files, _ = self.run_main(extra_args=["--qos-policy-status", "failed", "--qos-policy-reason",
                                                      "create_failed", "--qos-curl", "x"])
        self.assertEqual(dict(status="failed", reason="create_failed"),
                         json.loads(files["aggregate-evidence.json"])["qos_policy"])


if __name__ == "__main__":
    unittest.main()
