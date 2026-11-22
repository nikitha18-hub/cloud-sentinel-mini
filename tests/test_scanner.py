import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as web_app
from scanner import calculate_score, run_scan, validate_config


SAFE_CONFIG = {
    "public_storage_access": False,
    "encryption_enabled": True,
    "logging_enabled": True,
    "unrestricted_ssh": False,
    "excessive_iam_admin": False,
}


class ScannerTests(unittest.TestCase):
    def test_scan_returns_five_results(self):
        results = run_scan(SAFE_CONFIG)

        self.assertEqual(len(results), 5)
        self.assertEqual(
            set(results[0]),
            {"check_name", "status", "risk_level", "recommendation"},
        )
        self.assertTrue(all(result["status"] == "SECURE" for result in results))

    def test_scan_marks_risky_settings(self):
        config = {**SAFE_CONFIG, "public_storage_access": True}

        result = run_scan(config)[0]

        self.assertEqual(result["status"], "RISK DETECTED")
        self.assertEqual(result["risk_level"], "HIGH")

    def test_config_requires_all_boolean_fields(self):
        with self.assertRaises(ValueError):
            validate_config({**SAFE_CONFIG, "logging_enabled": "yes"})
        with self.assertRaises(ValueError):
            validate_config({key: value for key, value in SAFE_CONFIG.items() if key != "logging_enabled"})

    def test_score_is_reduced_for_findings_and_never_below_zero(self):
        findings = [
            {"status": "RISK DETECTED", "risk_level": "HIGH"},
            {"status": "RISK DETECTED", "risk_level": "MEDIUM"},
        ]
        many_findings = findings * 10

        self.assertEqual(calculate_score(findings), 70)
        self.assertEqual(calculate_score(many_findings), 0)
        self.assertEqual(calculate_score(run_scan(SAFE_CONFIG)), 100)


class FlaskRouteTests(unittest.TestCase):
    def setUp(self):
        web_app.app.config["TESTING"] = True
        self.client = web_app.app.test_client()

    def test_page_and_sample_config(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.get("/api/sample")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.get_json()), set(SAFE_CONFIG))

    def test_scan_rejects_invalid_json_config(self):
        response = self.client.post("/api/scan", json={"logging_enabled": True})

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_scan_returns_summary_and_five_results(self):
        response = self.client.post("/api/scan", json=SAFE_CONFIG)
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data["results"]), 5)
        self.assertEqual((data["risks"], data["secure"], data["not_checked"]), (0, 5, 0))
        self.assertEqual(data["score"], 100)

    def test_report_saves_and_downloads_csv(self):
        results = run_scan(SAFE_CONFIG)
        temporary_directory = Path(tempfile.mkdtemp())
        try:
            with patch.object(web_app, "REPORTS_DIR", Path(temporary_directory)):
                response = self.client.post("/api/report", json={"results": results})
                try:
                    response_data = response.data
                finally:
                    response.close()
                saved_reports = list(Path(temporary_directory).glob("*.csv"))
                self.assertEqual(len(saved_reports), 1)
                csv_file_data = saved_reports[0].read_bytes()
        finally:
            shutil.rmtree(temporary_directory, ignore_errors=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertEqual(len(saved_reports), 1)
        self.assertIn(b"check_name,status,risk_level,recommendation", response_data)
        self.assertIn(b"check_name,status,risk_level,recommendation", csv_file_data)


if __name__ == "__main__":
    unittest.main()