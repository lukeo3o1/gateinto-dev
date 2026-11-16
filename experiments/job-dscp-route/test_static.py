import pathlib
import re
import unittest

import harness

ROOT = pathlib.Path(__file__).parent
REPO = ROOT.parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "job-dscp-route.yml"
REFERENCE_WORKFLOW = REPO / ".github" / "workflows" / "wfp-divert-poc.yml"
VERDICTS = ("ROUTED_VIA_GATEWAY", "NOT_ROUTED", "ROUTING_BROKE_TAGGED", "PARTIAL", "INCONCLUSIVE_TARGET_UNREACHABLE",
            "INCONCLUSIVE_JOB_SETUP_FAILED", "INCONCLUSIVE_FIREWALL_RULE_FAILED", "HARNESS_ERROR", "SKIPPED_DEADLINE",
            "ROUTED_AND_ATTRIBUTED", "ROUTED_ATTRIBUTION_INCOMPLETE", "JOB_TAG_WINS", "POLICY_WINS", "MIXED",
            "INCONCLUSIVE_POLICY_NOT_APPLIED", "CONTAINED", "LEAKED", "INCONCLUSIVE_NO_BASELINE")

try:
    import yaml
except ImportError:
    yaml = None


def read(path):
    return path.read_text(encoding="utf-8")


class RouteSourceTests(unittest.TestCase):
    def test_single_divert_handle_with_the_static_filter(self):
        source = read(ROOT / "route.cpp")
        opens = re.findall(r"WinDivertOpen\(([^;]*)\);", source)
        self.assertEqual(["filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, kDivertFlags"], opens)
        self.assertIn("constexpr UINT64 kDivertFlags = 0;", source)
        self.assertIn("const std::string filter = engine_filter(listener_port, match_dscp, contain);", source)
        self.assertNotIn("WINDIVERT_FLAG_", source)

    def test_fail_open_shutdown_and_buffers(self):
        source = read(ROOT / "route.cpp")
        for snippet in ("WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV)", "error == ERROR_NO_DATA",
                        "WinDivertClose(handle)", "std::vector<uint8_t> buffer(WINDIVERT_MTU_MAX);",
                        "address.Outbound = 0;", "WinDivertHelperCalcChecksums(buffer.data(), length, &address, 0)",
                        "--max-seconds", "--stop-file"):
            self.assertIn(snippet, source)

    def test_jobs_kill_on_close_and_inherit_only_listed_handles(self):
        source = read(ROOT / "route.cpp")
        for snippet in ("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
                        "EXTENDED_STARTUPINFO_PRESENT", "CREATE_SUSPENDED"):
            self.assertIn(snippet, source)


class BuildScriptTests(unittest.TestCase):
    def test_signed_driver_and_compiler_flags(self):
        source = read(ROOT / "build.ps1")
        for snippet in ("WinDivert-2.2.2-A.zip", "Get-AuthenticodeSignature", "driver-manifest.json",
                        "Invoke-DownloadWithRetry", "/std:c++17 /EHsc /W4", "route.cpp", "/Fe:route.exe",
                        "WinDivert.lib Advapi32.lib Ws2_32.lib Iphlpapi.lib",
                        "Enter-VsDevShell"):
            self.assertIn(snippet, source)


class CiScriptTests(unittest.TestCase):
    def setUp(self):
        self.source = read(ROOT / "ci.ps1")

    def test_aggregate_markers_summary_and_harness(self):
        self.assertIn("'=== JOB-DSCP-ROUTE AGGREGATE BEGIN ==='", self.source)
        self.assertIn("'=== JOB-DSCP-ROUTE AGGREGATE END ==='", self.source)
        self.assertIn("GITHUB_STEP_SUMMARY", self.source)
        self.assertIn("harness.py", self.source)
        self.assertIn("'--lab', $Lab", self.source)
        self.assertIn("self-test", self.source)
        self.assertIn("python -m unittest discover -s $PSScriptRoot -p 'test_*.py' -v", self.source)

    def test_finally_restores_system_state(self):
        cleanup = self.source[self.source.index("} finally {"):]
        self.assertIn(f"name={harness.FIREWALL_RULE}", cleanup)
        self.assertIn("'advfirewall', 'firewall', 'delete', 'rule'", cleanup)
        self.assertIn("@('pktmon', 'stop')", cleanup)
        self.assertIn("@('pktmon', 'filter', 'remove')", cleanup)
        self.assertIn("Get-Process -Name 'route', 'wfp_lab', 'curl-qos'", cleanup)
        self.assertIn("Remove-QosPolicies", cleanup)

    def test_fallback_records_use_the_current_schema(self):
        self.assertNotIn("job-dscp-route-v1", self.source)
        self.assertEqual(4, self.source.count("job-dscp-route-v2"))

    def test_pending_cases_are_a_harness_failure(self):
        self.assertIn("$failures.Add('aggregate-pending')", self.source)
        self.assertIn("-eq 'PENDING'", self.source)

    def test_qos_policy_lifecycle(self):
        self.assertIn("-AppPathNameMatchCondition 'curl-qos.exe' -DSCPAction 46", self.source)
        self.assertIn("-PolicyStore ActiveStore", self.source)
        self.assertIn("Where-Object { $_.Name -like 'gateinto-job-dscp-route-qos*' }", self.source)
        self.assertLess(self.source.index("Remove-QosPolicies\n"), self.source.index("New-NetQosPolicy"))
        for argument in ("'--qos-policy-status', $qosStatus", "'--qos-curl', $qosCurl"):
            self.assertIn(argument, self.source)
        self.assertIn("if ($qosReason) { $harnessArgs += @('--qos-policy-reason', $qosReason) }", self.source)

    def test_errors_print_only_type_names_and_exit_explicitly(self):
        self.assertNotIn("Exception.Message", self.source)
        self.assertIn("Exception.GetType().Name", self.source)
        lines = [line for line in self.source.splitlines() if line.strip()]
        self.assertEqual("exit 0", lines[-1])
        self.assertEqual(["if ($failures.Count) {",
                          "  Write-Host \"Job DSCP route harness failures: $($failures -join ', ')\"", "  exit 1", "}"],
                         lines[-5:-1])

    def test_setup_inside_try_and_elevation_required(self):
        self.assertGreater(self.source.index("Restrict-Directory $OutDir"), self.source.index("\ntry {"))
        self.assertIn("WindowsBuiltInRole]::Administrator", self.source)


class ReadmeTests(unittest.TestCase):
    def test_readme_documents_verdicts_and_limits(self):
        source = read(ROOT / "README.md")
        for verdict in VERDICTS:
            self.assertIn(verdict, source)
        for word in ("## Limits", "firewall", "tagged-no-engine", "IPv4", "IPv6", "orphan_dropped",
                     "bridge_segments_on_wire", "launch_setup", "--match-dscp", "--contain", "p95", "PENDING",
                     "NOT_RUN_CORE_NOT_ROUTED", "stopped_early", "=== JOB-DSCP-ROUTE CASE <name> BEGIN ===",
                     "NETWORK layer", "loopback", "60-minute"):
            self.assertIn(word, source)


@unittest.skipIf(yaml is None, "PyYAML is not installed")
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = read(WORKFLOW)
        self.workflow = yaml.safe_load(self.text)

    def test_triggers_permissions_and_concurrency(self):
        triggers = self.workflow[True]
        self.assertIn("workflow_dispatch", triggers)
        self.assertEqual(["experiments/job-dscp-route/**", ".github/workflows/job-dscp-route.yml",
                          "examples/wfp_lab.rs", "tests/fixture/**"], triggers["pull_request"]["paths"])
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        self.assertIn("group", self.workflow["concurrency"])

    def test_model_job(self):
        steps = self.workflow["jobs"]["model"]["steps"]
        self.assertEqual("ubuntu-latest", self.workflow["jobs"]["model"]["runs-on"])
        commands = "\n".join(step.get("run", "") for step in steps)
        self.assertIn("python3 -m unittest discover -s experiments/job-dscp-route -p 'test_*.py' -v", commands)
        self.assertIn("g++ -std=c++17 -Wall -Wextra -Werror experiments/job-dscp-route/route.cpp -o "
                      "/tmp/job-dscp-route-test", commands)
        self.assertIn("/tmp/job-dscp-route-test", commands.split("route.cpp", 1)[1])

    def test_windows_job(self):
        job = self.workflow["jobs"]["windows"]
        self.assertEqual({"fail-fast": False, "matrix": {"os": ["windows-2022", "windows-2025"]}}, job["strategy"])
        self.assertEqual(60, job["timeout-minutes"])
        self.assertEqual("pwsh", job["defaults"]["run"]["shell"])
        runs = [step.get("run") for step in job["steps"] if "run" in step]
        self.assertEqual(["cargo build --release --locked --example wfp_lab", "experiments/job-dscp-route/build.ps1",
                          "experiments/job-dscp-route/ci.ps1"], runs)
        upload = job["steps"][-1]
        self.assertEqual("always()", upload["if"])
        self.assertTrue(upload["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(["${{ runner.temp }}/job-dscp-route-results/aggregate-evidence.json",
                          "${{ runner.temp }}/job-dscp-route-results/ci-summary.json",
                          "${{ runner.temp }}/job-dscp-route-results/environment.json",
                          "${{ runner.temp }}/job-dscp-route-bin/driver-manifest.json"],
                         upload["with"]["path"].splitlines())

    def test_toolchain_steps_match_the_existing_experiment(self):
        reference = yaml.safe_load(read(REFERENCE_WORKFLOW))["jobs"]["windows"]["steps"]
        steps = self.workflow["jobs"]["windows"]["steps"]
        pinned = [s for s in reference if "dtolnay" in s.get("uses", "") or "rust-cache" in s.get("uses", "")]
        self.assertEqual(2, len(pinned))
        for step in pinned:
            self.assertIn(step, steps)


if __name__ == "__main__":
    unittest.main()
