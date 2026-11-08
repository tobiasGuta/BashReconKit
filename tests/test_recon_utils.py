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
    parse_dig_response,
    is_whois_rejection,
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

    def test_dig_authority_soa_is_not_an_soa_answer(self):
        sample = (
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60957\n"
            ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
            ";; QUESTION SECTION:\n"
            ";diggingforanswers.chals.mctf.io. IN NS\n"
            ";; AUTHORITY SECTION:\n"
            "mctf.io. 900 IN SOA ns-1774.awsdns-29.co.uk. "
            "awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400\n"
        )
        ns = parse_dig_response(sample, "NS")
        soa = parse_dig_response(sample, "SOA")
        self.assertEqual(ns["rcode"], "NOERROR")
        self.assertEqual(ns["answers"], [])
        self.assertEqual(soa["answers"], [])
        self.assertEqual(ns["authority_soa"]["name"], "mctf.io")
        self.assertEqual(ns["authority_soa"]["value"].split()[0], "ns-1774.awsdns-29.co.uk.")

    def test_dig_parser_matches_only_requested_answer_type(self):
        sample = (
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
            ";; ANSWER SECTION:\n"
            "example.com. 300 IN NS ns1.example.com.\n"
            "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 2 3 4 5\n"
            ";; AUTHORITY SECTION:\n"
            "com. 300 IN SOA a.gtld-servers.net. hostmaster.example.com. 1 2 3 4 5\n"
        )
        self.assertEqual(len(parse_dig_response(sample, "NS")["answers"]), 1)
        self.assertEqual(len(parse_dig_response(sample, "SOA")["answers"]), 1)

    def test_dig_nxdomain_has_no_answers(self):
        sample = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n"
        self.assertEqual(parse_dig_response(sample, "SOA")["rcode"], "NXDOMAIN")
        self.assertEqual(parse_dig_response(sample, "NS")["answers"], [])

    def test_whois_malformed_banner_is_rejected(self):
        self.assertTrue(is_whois_rejection(
            "Malformed request.\n>>> Last update of WHOIS database: 2026-11-08 <<<"
        ))
        self.assertFalse(is_whois_rejection("Domain Name: EXAMPLE.COM\nRegistrar: Demo"))

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
