"""Offline unit tests; no network requests or target scanning required."""

import csv
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from recon_utils import (
    ReconCommandError,
    ReconNetworkError,
    export_session,
    make_scan_record,
    parse_ipv4_answers,
    run_command,
    safe_get,
)


class ReconUtilsTests(unittest.TestCase):
    def test_dig_parser_ignores_cname_and_invalid_records(self):
        output = "www.example.net.\n192.0.2.1\n192.0.2.1\nnot-an-ip\n2001:db8::1\n198.51.100.7\n"
        self.assertEqual(parse_ipv4_answers(output), ["192.0.2.1", "198.51.100.7"])

    def test_empty_scan_is_recorded(self):
        record = make_scan_record({"tool": "DNS", "target": "example.net", "data": []})
        self.assertEqual(record["status"], "no_results")
        self.assertEqual(record["data"], [])
        self.assertTrue(record["timestamp"].endswith("+00:00"))

    def test_export_all_formats_and_csv_formula_safety(self):
        history = [
            make_scan_record({"tool": "DNS", "target": "=2+2", "data": [{"ip": "192.0.2.1"}]}),
            make_scan_record({"tool": "WHOIS", "target": "example.net", "data": "Registered\n"}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            json_file = export_session(history, "json", tmp)
            self.assertEqual(len(json.loads(json_file.read_text(encoding="utf-8"))), 2)
            csv_file = export_session(history, "csv", tmp)
            with csv_file.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["target"], "'=2+2")
            text_file = export_session(history, "txt", tmp)
            self.assertIn("Registered", text_file.read_text(encoding="utf-8"))

    @patch("recon_utils.requests.get")
    def test_http_timeout_and_credential_redaction(self, request):
        request.side_effect = requests.Timeout("https://example.net/?apikey=SECRET")
        with self.assertRaises(ReconNetworkError) as raised:
            safe_get("https://example.net/?apikey=SECRET")
        self.assertNotIn("SECRET", str(raised.exception))
        self.assertEqual(request.call_args.kwargs["timeout"], 15)

    @patch("recon_utils.subprocess.run")
    def test_missing_executable_is_helpful(self, run):
        run.side_effect = FileNotFoundError("dig")
        with self.assertRaisesRegex(ReconCommandError, "dig"):
            run_command(["dig", "+short", "example.net"])
        self.assertEqual(run.call_args.kwargs["timeout"], 20)

    @patch("recon_utils.subprocess.run")
    def test_subprocess_timeout_is_helpful(self, run):
        run.side_effect = subprocess.TimeoutExpired("dig", 20)
        with self.assertRaisesRegex(ReconCommandError, "timeout"):
            run_command(["dig", "example.net"])


if __name__ == "__main__":
    unittest.main()
