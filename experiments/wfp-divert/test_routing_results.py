import json
import pathlib
import tempfile
import unittest

import routing_results


class RoutingResultsTests(unittest.TestCase):
    def test_only_controlled_cases_and_projected_fields_are_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in routing_results.CASE_NAMES:
                case = root / name
                case.mkdir()
                (case / "summary.json").write_text(json.dumps(dict(
                    status="PASS_RESTRICTED_CASE", engine="inproc", protocol="tcp", mode="redirect",
                    gateway_connect_count=20, pid=1234, selected_app="PRIVATE-TOKEN",
                    clients=[dict(returncode=0, nonce="PRIVATE-TOKEN", attempts=[dict(local_port=1234)])],
                    engine_summary=dict(success=True, decided_proxy=20, selected_app="PRIVATE-TOKEN",
                                        capture_qpc=98765, rows=[dict(app_path="PRIVATE-TOKEN")]))))
            private = root / "PRIVATE-TOKEN"
            private.mkdir()
            (private / "summary.json").write_text('{"secret":"PRIVATE-TOKEN"}')
            result = routing_results.aggregate(root)
            self.assertEqual(9, result["available_cases"])
            self.assertEqual(set(routing_results.CASE_NAMES), {c["case"] for c in result["cases"]})
            for case in result["cases"]:
                self.assertEqual(20, case["summary"]["gateway_connect_count"])
                self.assertEqual(dict(total=1, success=1, failure=0), case["summary"]["clients"])
            encoded = json.dumps(result)
            for private in ("PRIVATE-TOKEN", '"pid"', '"selected_app"', '"capture_qpc"', '"rows"', '"local_port"'):
                self.assertNotIn(private, encoded)

    def test_absent_and_invalid_private_results_do_not_leak_exception_details(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case = root / routing_results.CASE_NAMES[0]
            case.mkdir()
            (case / "summary.json").write_text("PRIVATE-TOKEN not JSON")
            result = routing_results.aggregate(root)
            self.assertEqual(0, result["available_cases"])
            self.assertEqual(1, result["unreadable_cases"])
            self.assertEqual(8, result["missing_cases"])
            self.assertNotIn("PRIVATE-TOKEN", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
