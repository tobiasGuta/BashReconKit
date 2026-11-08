"""Regression tests for DNS/WHOIS CLI behavior without network calls."""

import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import recon


EMPTY_NS_REPLY = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60957
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; QUESTION SECTION:
;diggingforanswers.chals.mctf.io. IN NS
;; AUTHORITY SECTION:
mctf.io. 900 IN SOA ns-1774.awsdns-29.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
"""

VALID_NS_REPLY = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10
;; ANSWER SECTION:
mctf.io. 900 IN NS ns-1774.awsdns-29.co.uk.
"""

VALID_SOA_REPLY = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10
;; ANSWER SECTION:
mctf.io. 900 IN SOA ns-1774.awsdns-29.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
"""


class ReconCliTests(unittest.TestCase):
    @patch("recon.run_command")
    def test_ns_empty_answer_shows_parent_zone_instead_of_success(self, run):
        run.return_value = SimpleNamespace(stdout=EMPTY_NS_REPLY)
        out = io.StringIO()
        with redirect_stdout(out):
            result = recon.dig_custom_ns_lookup("diggingforanswers.chals.mctf.io", "1.1.1.1")
        self.assertEqual(result, [])
        self.assertIn("No NS answer", out.getvalue())
        self.assertIn("mctf.io", out.getvalue())
        self.assertIn("parent-zone context", out.getvalue())

    @patch("recon.run_command")
    def test_soa_authority_is_not_a_host_soa(self, run):
        run.return_value = SimpleNamespace(stdout=EMPTY_NS_REPLY)
        out = io.StringIO()
        with redirect_stdout(out):
            result = recon.dig_soa_lookup("diggingforanswers.chals.mctf.io")
        self.assertEqual(result, [])
        self.assertIn("No SOA answer", out.getvalue())
        self.assertIn("SOA records belong to DNS zones", out.getvalue())

    @patch("recon.run_command")
    def test_positive_ns_answer_is_printed(self, run):
        run.return_value = SimpleNamespace(stdout=VALID_NS_REPLY)
        with redirect_stdout(io.StringIO()):
            result = recon.dig_custom_ns_lookup("mctf.io", "1.1.1.1")
        self.assertEqual(result, VALID_NS_REPLY)

    @patch("recon.run_command")
    def test_positive_soa_answer_is_printed(self, run):
        run.return_value = SimpleNamespace(stdout=VALID_SOA_REPLY)
        with redirect_stdout(io.StringIO()):
            result = recon.dig_soa_lookup("mctf.io")
        self.assertEqual(result, VALID_SOA_REPLY)

    @patch("recon.run_command")
    def test_whois_malformed_output_not_treated_as_success(self, run):
        run.return_value = SimpleNamespace(stdout=(
            "Malformed request.\n>>> Last update of WHOIS database <<<\n"
            "Long registry terms of use should not be printed."
        ))
        out = io.StringIO()
        with redirect_stdout(out):
            result = recon.whois_lookup("diggingforanswers.chals.mctf.io")
        self.assertEqual(result, [])
        self.assertIn("registered domain", out.getvalue())
        self.assertNotIn("Long registry terms", out.getvalue())


if __name__ == "__main__":
    unittest.main()
