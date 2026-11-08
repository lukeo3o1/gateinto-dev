import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


BUILD = pathlib.Path(__file__).with_name("build.ps1")
PWSH = shutil.which("pwsh")
HARNESS = r"""
param([string] $Build, [string] $Plan)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Build, [ref]$null, [ref]$null)
$functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

$script:plan = @($Plan -split ',')
$script:calls = 0
$script:sleeps = [System.Collections.Generic.List[int]]::new()
$script:logs = [System.Collections.Generic.List[string]]::new()
function Invoke-WebRequest {
  $script:calls++
  $step = $script:plan[$script:calls - 1]
  $message = "attempt $($script:calls) $step"
  switch -Regex ($step) {
    '^ok$' { return }
    '^\d+$' { throw [Microsoft.PowerShell.Commands.HttpResponseException]::new($message, [System.Net.Http.HttpResponseMessage]::new([int]$step)) }
    '^timeout$' { throw [System.TimeoutException]::new($message) }
    '^network$' { throw [System.Net.Http.HttpRequestException]::new($message, [System.Net.Sockets.SocketException]::new(10054)) }
    '^canceled$' { throw [System.Threading.Tasks.TaskCanceledException]::new($message) }
    default { throw [System.InvalidOperationException]::new($message) }
  }
}
function Start-Sleep([int] $Seconds) { $script:sleeps.Add($Seconds) }
function Write-Host { $script:logs.Add("$args") }

$result = 'ok'
try { Invoke-DownloadWithRetry 'https://example.invalid/a.zip' 'a.zip' } catch { $result = "error: $($_.Exception.Message)" }
@{ calls = $script:calls; sleeps = @($script:sleeps); logs = @($script:logs); result = $result } | ConvertTo-Json -Compress
"""


class BuildScriptTests(unittest.TestCase):
    def test_windivert_download_uses_retry(self):
        line = next(line for line in BUILD.read_text().splitlines() if "/releases/download/" in line)
        self.assertTrue(line.startswith("Invoke-DownloadWithRetry "), line)


@unittest.skipUnless(PWSH, "pwsh is not installed")
class DownloadRetryTests(unittest.TestCase):
    def run_plan(self, *steps):
        with tempfile.TemporaryDirectory() as directory:
            harness = pathlib.Path(directory, "harness.ps1")
            harness.write_text(HARNESS)
            output = subprocess.run(
                [PWSH, "-NoProfile", "-NonInteractive", "-File", str(harness), "-Build", str(BUILD), "-Plan", ",".join(steps)],
                check=True, capture_output=True, text=True, timeout=60,
            ).stdout
        return json.loads(output)

    def test_transient_failures_retry_with_backoff_and_log(self):
        result = self.run_plan("504", "429", "timeout", "network", "ok")
        self.assertEqual("ok", result["result"])
        self.assertEqual(5, result["calls"])
        self.assertEqual([2, 4, 8, 16], result["sleeps"])
        self.assertEqual(4, len(result["logs"]))
        self.assertIn("attempt 1 504", result["logs"][0])

    def test_canceled_request_is_transient(self):
        result = self.run_plan("canceled", "ok")
        self.assertEqual("ok", result["result"])
        self.assertEqual([2], result["sleeps"])

    def test_non_transient_failures_fail_immediately(self):
        for step in ["404", "403", "other"]:
            result = self.run_plan(step, "ok")
            self.assertEqual(f"error: attempt 1 {step}", result["result"])
            self.assertEqual(1, result["calls"])
            self.assertEqual([], result["sleeps"])
            self.assertEqual([], result["logs"])

    def test_exhausted_attempts_throw_last_error(self):
        result = self.run_plan("503", "503", "503", "503", "503", "ok")
        self.assertEqual("error: attempt 5 503", result["result"])
        self.assertEqual(5, result["calls"])
        self.assertEqual([2, 4, 8, 16], result["sleeps"])
        self.assertEqual(4, len(result["logs"]))


if __name__ == "__main__":
    unittest.main()
