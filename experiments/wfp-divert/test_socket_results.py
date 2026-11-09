import json
import pathlib
import tempfile
import unittest

import socket_results


class SocketResultsTests(unittest.TestCase):
    def test_broad_socket_controls_are_in_the_fixed_case_list(self):
        self.assertIn("tcp-control", socket_results.CASE_NAMES)
        self.assertIn("udp-control", socket_results.CASE_NAMES)

    def test_only_fixed_cases_and_projected_counts_are_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in socket_results.CASE_NAMES:
                case = root / name
                case.mkdir()
                (case / "public-summary.json").write_text(json.dumps(dict(
                    status="PASS_SOCKET_OBSERVATION", protocol="tcp", pid=1234,
                    app_path="PRIVATE-TOKEN", endpoint_id=5678, recv_qpc=999999,
                    rows=[dict(remote_ip="PRIVATE-TOKEN")], error="PRIVATE-TOKEN")))
            private = root / "PRIVATE-TOKEN"
            private.mkdir()
            (private / "public-summary.json").write_text('{"secret":"PRIVATE-TOKEN"}')
            report = socket_results.aggregate(root)
            self.assertEqual(len(socket_results.CASE_NAMES), report["available_cases"])
            self.assertEqual(set(socket_results.CASE_NAMES), {c["case"] for c in report["cases"]})
            encoded = json.dumps(report)
            for private in ("PRIVATE-TOKEN", '"pid"', '"endpoint_id"', '"recv_qpc"', '"rows"'):
                self.assertNotIn(private, encoded)

    def test_missing_and_unreadable_results_are_explicit_without_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case = root / socket_results.CASE_NAMES[0]
            case.mkdir()
            (case / "public-summary.json").write_text("PRIVATE-TOKEN invalid JSON")
            result = socket_results.aggregate(root)
            self.assertEqual(0, result["available_cases"])
            self.assertEqual(1, result["unreadable_cases"])
            self.assertEqual(len(socket_results.CASE_NAMES) - 1, result["missing_cases"])
            self.assertNotIn("PRIVATE-TOKEN", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
