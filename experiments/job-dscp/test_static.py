import pathlib
import re
import unittest

import harness

ROOT = pathlib.Path(__file__).parent


class CaptureOnlyTests(unittest.TestCase):
    def test_every_windivert_handle_is_sniff_and_recv_only(self):
        source = (ROOT / "probe.cpp").read_text()
        opens = re.findall(r"WinDivertOpen\(([^;]*)\);", source)
        self.assertTrue(opens)
        for call in opens:
            self.assertIn("kCaptureFlags", call)
        self.assertIn("constexpr UINT64 kCaptureFlags = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;", source)
        for forbidden in ("WinDivertSend", "WINDIVERT_FLAG_DROP"):
            self.assertNotIn(forbidden, source)

    def test_native_self_test_compiles_the_harness_marked_filter(self):
        self.assertIn(f'kMarkedFilter[] = "{harness.MARKED_FILTER}";', (ROOT / "probe.cpp").read_text())

    def test_jobs_kill_on_close(self):
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", (ROOT / "probe.cpp").read_text())


class CiScriptTests(unittest.TestCase):
    def test_aggregate_markers_and_cleanup(self):
        source = (ROOT / "ci.ps1").read_text()
        self.assertIn("'=== JOB-DSCP AGGREGATE BEGIN ==='", source)
        self.assertIn("'=== JOB-DSCP AGGREGATE END ==='", source)
        self.assertIn("Remove-NetQosPolicy", source)
        self.assertIn("finally", source)
        self.assertIn("GITHUB_STEP_SUMMARY", source)

    def test_errors_print_only_type_names(self):
        source = (ROOT / "ci.ps1").read_text()
        self.assertNotIn("Exception.Message", source)
        self.assertNotIn("throw \"Job DSCP harness failures", source)
        self.assertIn("exit 1", source)

    def test_directory_setup_runs_inside_try(self):
        source = (ROOT / "ci.ps1").read_text()
        body = source[source.index("\ntry {"):]
        self.assertGreater(source.index("Restrict-Directory $OutDir"), source.index("\ntry {"))
        self.assertIn("Restrict-Directory $privateDir", body)

    def test_empty_qos_reason_is_not_passed(self):
        source = (ROOT / "ci.ps1").read_text()
        self.assertNotIn("--qos-policy-reason $qosReason", source)
        self.assertIn("if ($qosReason) { $harnessArgs += @('--qos-policy-reason', $qosReason) }", source)

    def test_build_produces_identical_qos_copy(self):
        source = (ROOT / "build.ps1").read_text()
        self.assertIn("probe-qos.exe", source)
        self.assertIn("Get-AuthenticodeSignature", source)
        self.assertIn("driver-manifest.json", source)


if __name__ == "__main__":
    unittest.main()
