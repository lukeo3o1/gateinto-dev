import json
import os
import pathlib
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

import analysis_extra as extra
import bridge
import cases
import harness

R = "192.0.2.10"

FAKE_ROUTE = """#!{python}
import json, os, subprocess, sys, time
args = sys.argv[1:]
if args[0] == "launch":
    opts, rest = args[1:args.index("--")], args[args.index("--") + 1:]
    o = dict(zip(opts[::2], opts[1::2]))
    record = dict(dscp=int(o["--dscp"]), job_created=True, assigned=True, shared_job="--job-name" in o)
    print(json.dumps(dict(record, kind="launch_setup")), flush=True)
    with open(o["--stdout"], "wb") as out, open(o["--stderr"], "wb") as err:
        code = subprocess.run(rest, stdout=out, stderr=err).returncode
    print(json.dumps(dict(record, kind="launch", child_ran=True, child_exit_code=code)), flush=True)
    sys.exit(code)
if args[0] == "owner":
    mode = os.environ.get("FAKE_OWNER", "ok")
    if mode == "slow":
        time.sleep(5)
    if mode == "exit":
        sys.exit(3)
    if mode == "garbage":
        print("garbage")
        sys.exit(0)
    print(json.dumps(dict(kind="owner", found=True, args=args[1:])))
if args[0] == "udp-send":
    print(json.dumps(dict(kind="udp_send", local_port=40001, sent=3, error=0)))
"""


def script(path, body):
    path.write_text(body.format(python=sys.executable))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def python_payload(code):
    return [sys.executable, "-c", code]


POSIX_ONLY = unittest.skipUnless(os.name == "posix", "the fake route executable needs a POSIX shebang")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.route = script(self.root / "route", FAKE_ROUTE)
        self.ctx = harness.Context(route=self.route, curl="curl", lab="lab", private=self.root, target_ip=R,
                                   local_ip="10.1.0.4", deadline=time.monotonic() + 60)

    def tearDown(self):
        self.directory.cleanup()


class CommandTests(unittest.TestCase):
    def test_child_commands(self):
        ctx = harness.Context(route="route.exe", curl="curl", lab="lab", private=pathlib.Path("p"), target_ip=R,
                              local_ip=None)
        payload = ["curl", "x"]
        self.assertEqual(payload, cases.child_command(ctx, dict(name="u", kind="untagged"), "o", "e", payload))
        self.assertEqual(["route.exe", "launch", "--dscp", "43", "--stdout", "o", "--stderr", "e", "--job-name",
                          "Local\\job", "--"] + payload,
                         cases.child_command(ctx, dict(name="s", kind="tagged", dscp=43, job="Local\\job"), "o", "e",
                                             payload))
        self.assertEqual(["route.exe", "launch", "--dscp", "10", "--stdout", "o", "--stderr", "e", "--"] + payload,
                         cases.child_command(ctx, dict(name="t", kind="tagged", dscp=10), "o", "e", payload))

    def test_udp_payload_and_parse(self):
        self.assertEqual(["route.exe", "udp-send", "--target", R, "--port", "443", "--count", "3", "--interval-ms",
                          "100"], cases.udp_payload("route.exe", R))
        self.assertEqual(dict(local_port=1, sent=3, error=0),
                         cases.parse_udp('x\n{"kind":"udp_send","local_port":1,"sent":3,"error":0}\n'))
        self.assertIsNone(cases.parse_udp("garbage"))
        self.assertIsNone(cases.parse_udp('{"kind":"udp_send","local_port":"1"}'))

    def test_constants(self):
        self.assertEqual((10, 10), (cases.LOAD_SEQUENTIAL, cases.LOAD_BURST))
        self.assertEqual((3, 3), (cases.SHARED_SEQUENTIAL, cases.SHARED_BURST))
        self.assertTrue(cases.SESSION_PREFIX.startswith("Local\\"))
        self.assertEqual(["--match-dscp", "43"], cases.EXACT_ENGINE)
        self.assertEqual(["--match-dscp", "43", "--contain"], cases.CONTAIN_ENGINE)


@POSIX_ONLY
class AttemptTests(Fixture):
    def test_untagged_and_tagged_attempts_run_concurrently(self):
        output = '{"http_code":"200","local_port":"50001"}'
        payload = python_payload(f"import time; time.sleep(0.5); print({output!r})")
        start = time.monotonic()
        handles = [cases.start_attempt(self.ctx, dict(name="untagged", kind="untagged"), 0, "burst", payload),
                   cases.start_attempt(self.ctx, dict(name="tagged-a", kind="tagged", dscp=10), 0, "burst", payload)]
        untagged, tagged = [cases.finish_attempt(h) for h in handles]
        self.assertLess(time.monotonic() - start, 0.95)
        self.assertEqual(("untagged", "burst", 0, 200), (untagged["role"], untagged["phase"], untagged["exit_code"],
                                                         untagged["curl"]["http_code"]))
        self.assertIsNone(untagged["launch"])
        self.assertEqual(("launch", 0, 200), (tagged["launch"]["kind"], tagged["exit_code"],
                                              tagged["curl"]["http_code"]))

    def test_timeout_keeps_the_setup_record(self):
        with mock.patch.object(harness, "ATTEMPT_TIMEOUT_SECONDS", 1):
            attempt = cases.finish_attempt(cases.start_attempt(
                self.ctx, dict(name="tagged-a", kind="tagged", dscp=10), 0, "sequential",
                python_payload("import time; time.sleep(4)")))
        self.assertTrue(attempt["timed_out"])
        self.assertEqual("launch_setup", attempt["launch"]["kind"])
        self.assertIsNone(attempt["exit_code"])

    def test_sequential_stops_after_three_consecutive_failures(self):
        counter = self.root / "counter"
        script_text = ("import pathlib, sys\n"
                       f"p = pathlib.Path({str(counter)!r})\n"
                       "n = int(p.read_text()) if p.exists() else 0\n"
                       "p.write_text(str(n + 1))\n"
                       "ok = sys.argv[1][n] == 'o'\n"
                       "print('{\"http_code\":\"%s\"}' % ('200' if ok else '000'))\n"
                       "sys.exit(0 if ok else 7)\n")
        role = dict(name="untagged", kind="untagged")
        for pattern, count, made, stopped in (("oooo", 4, 4, False), ("xxxxx", 5, 3, True),
                                              ("xxoxxxoo", 8, 6, True), ("xxoxxo", 6, 6, False)):
            counter.unlink(missing_ok=True)
            attempts, early = cases.sequential(self.ctx, role, count, "sequential",
                                               python_payload(script_text) + [pattern])
            self.assertEqual((made, stopped), (len(attempts), early), pattern)
            self.assertEqual(list(range(made)), [a["index"] for a in attempts])
        self.assertEqual(3, cases.STOP_AFTER_FAILURES)

    def test_udp_attempt(self):
        attempt = cases.finish_attempt(cases.start_attempt(
            self.ctx, dict(name="udp-untagged", kind="untagged"), 0, "sequential", cases.udp_payload(self.route, R),
            kind="udp"))
        self.assertEqual(dict(local_port=40001, sent=3, error=0), attempt["udp"])
        self.assertNotIn("curl", attempt)

    def test_deadline_skips_without_starting(self):
        self.ctx.deadline = time.monotonic() - 1
        handle = cases.start_attempt(self.ctx, dict(name="untagged", kind="untagged"), 0, "burst",
                                     python_payload("raise SystemExit(9)"))
        self.assertIsNone(handle["process"])
        self.assertEqual("deadline", cases.finish_attempt(handle)["skipped"])
        self.assertTrue(self.ctx.deadline_hit)


@POSIX_ONLY
class OwnerTests(Fixture):
    def lookup(self, mode):
        function = cases.owner_lookup(self.route, ["Local\\a", "Local\\b"])
        connection = dict(local_ip="10.1.0.4", local_port=50001, remote_ip=R, remote_port=443)
        with mock.patch.dict(os.environ, FAKE_OWNER=mode), mock.patch.object(cases, "OWNER_TIMEOUT_SECONDS", 1):
            return function(connection)

    def test_lookup_arguments(self):
        record = self.lookup("ok")
        self.assertEqual(["--local", "10.1.0.4", "--local-port", "50001", "--remote", R, "--remote-port", "443",
                          "--jobs", "Local\\a,Local\\b"], record["args"])

    def test_lookup_failures_are_labelled(self):
        for mode, label in (("slow", "owner_timeout"), ("exit", "owner_exit_3"), ("garbage", "owner_output")):
            with self.assertRaises(bridge.AttributionError) as raised:
                self.lookup(mode)
            self.assertEqual(label, raised.exception.label)


class CaseTests(Fixture):
    def test_qos_case_without_a_policy_does_not_start_anything(self):
        with mock.patch.object(cases, "run_segment", side_effect=AssertionError("must not run")):
            result = cases.run_qos(self.ctx, dict(status="failed", reason="create_failed", curl=None))
            self.assertEqual("INCONCLUSIVE_POLICY_NOT_APPLIED", result["verdict"])
            result = cases.run_qos(self.ctx, dict(status="created", reason=None, curl=self.root / "missing.exe"))
            self.assertEqual(("INCONCLUSIVE_POLICY_NOT_APPLIED", "copy_failed"),
                             (result["verdict"], result["policy"]["reason"]))

    def test_unresolved_target(self):
        self.ctx.target_ip = None
        with mock.patch.object(cases, "run_segment", side_effect=AssertionError("must not run")):
            for result in (cases.run_load(self.ctx), cases.run_shared(self.ctx), cases.run_udp(self.ctx),
                           cases.run_qos(self.ctx, dict(status="created", curl=self.route))):
                self.assertEqual("INCONCLUSIVE_TARGET_UNREACHABLE", result["verdict"], result["case"])

    def test_shared_holder_failure_skips_the_segment_and_stops_holders(self):
        holder = mock.Mock()
        holder.poll.return_value = None
        records = {"session-a": dict(kind="session", ready=True), "session-b": dict(kind="session", ready=False,
                                                                                    job_error=183)}
        with mock.patch.object(cases, "start_holders", return_value=({s: holder for s in extra.SESSIONS}, records)), \
                mock.patch.object(cases, "stop_holders") as stop, \
                mock.patch.object(cases, "run_segment", side_effect=AssertionError("must not run")):
            result = cases.run_shared(self.ctx)
        self.assertEqual("INCONCLUSIVE_JOB_SETUP_FAILED", result["verdict"])
        stop.assert_called_once()

    def test_shared_holders_are_stopped_after_an_exception(self):
        records = {s: dict(kind="session", ready=True) for s in extra.SESSIONS}
        with mock.patch.object(cases, "start_holders", return_value=({}, records)), \
                mock.patch.object(cases, "stop_holders") as stop, \
                mock.patch.object(cases, "run_segment", side_effect=OSError("x")):
            with self.assertRaises(OSError):
                cases.run_shared(self.ctx)
        stop.assert_called_once()

    def test_holder_commands_and_records(self):
        holders, records = cases.start_holders(self.ctx, {"session-a": "Local\\a"}, command=lambda name, stop: (
            python_payload("import json, os, time; print(json.dumps(dict(kind='session', ready=True)), flush=True)\n"
                           f"while not os.path.exists({str(stop)!r}): time.sleep(0.05)")))
        self.assertEqual({"session-a": dict(kind="session", ready=True)}, records)
        cases.stop_holders(holders, self.ctx.private)
        self.assertTrue(all(h.poll() is not None for h in holders.values()))
        self.assertEqual([str(self.route), "session", "--dscp", "43", "--job-name", "Local\\a", "--stop-file", "s",
                          "--max-seconds", str(harness.ENGINE_MAX_SECONDS)],
                         cases.holder_command(self.ctx, "Local\\a", "s"))


if __name__ == "__main__":
    unittest.main()
