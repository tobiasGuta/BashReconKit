"""Shared helpers for reliable recon commands, API calls, and session exports."""

import csv
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests

HTTP_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 20


class ReconCommandError(RuntimeError):
    """A local reconnaissance command could not be executed."""


class ReconNetworkError(RuntimeError):
    """An API call failed without exposing its URL or credentials."""


def run_command(command, **kwargs):
    """Run a local tool with a deadline and friendly dependency failures."""
    kwargs.setdefault("timeout", COMMAND_TIMEOUT_SECONDS)
    try:
        return subprocess.run(command, **kwargs)
    except FileNotFoundError:
        raise ReconCommandError(
            f"Required executable '{command[0]}' was not found in PATH."
        ) from None
    except subprocess.TimeoutExpired:
        raise ReconCommandError(
            f"Command '{command[0]}' exceeded the {kwargs['timeout']}s timeout."
        ) from None


def safe_get(url, **kwargs):
    """Make a bounded request without disclosing API keys in exception text."""
    kwargs.setdefault("timeout", HTTP_TIMEOUT_SECONDS)
    try:
        return requests.get(url, **kwargs)
    except requests.RequestException as exc:
        raise ReconNetworkError(
            f"Network request failed ({type(exc).__name__})."
        ) from None


def parse_ipv4_answers(output):
    """Extract actual IPv4 addresses from dig +short A output, without CNAMEs."""
    addresses = []
    for line in output.splitlines():
        value = line.strip()
        try:
            address = str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses



def parse_dig_response(output, record_type):
    """Parse a standard dig response without treating authority records as answers.

    The SOA in an AUTHORITY SECTION commonly describes the enclosing zone;
    it must not be reported as an SOA response for a queried hostname.
    """
    match = re.search(r"\bstatus:\s*([A-Z]+)", output, re.IGNORECASE)
    rcode = match.group(1).upper() if match else None
    section = None
    answers = []
    authority_soa = None
    wanted = record_type.upper()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith(";; ANSWER SECTION:"):
            section = "answer"
            continue
        if line.startswith(";; AUTHORITY SECTION:"):
            section = "authority"
            continue
        if line.startswith(";;") and "SECTION:" in line:
            section = None
            continue
        if not line or line.startswith(";") or section not in ("answer", "authority"):
            continue

        columns = line.split()
        if len(columns) < 5 or columns[2].upper() != "IN":
            continue
        record = {
            "name": columns[0].rstrip("."),
            "type": columns[3].upper(),
            "value": " ".join(columns[4:]),
        }
        if section == "answer" and record["type"] == wanted:
            answers.append(record)
        elif section == "authority" and record["type"] == "SOA":
            authority_soa = record

    return {"rcode": rcode, "answers": answers, "authority_soa": authority_soa}


def is_whois_rejection(output):
    """Recognize common WHOIS rejection banners even when whois exits zero."""
    nonempty = (line.strip().lower() for line in output.splitlines() if line.strip())
    first_line = next(nonempty, "")
    return first_line.startswith((
        "malformed request",
        "invalid query",
        "invalid request",
    ))


def make_scan_record(record):
    """Keep empty, successful scans in history instead of losing them."""
    data = record["data"]
    return {
        "tool": record["tool"],
        "target": record["target"],
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "no_results" if data is None or data == "" or data == [] or data == {} else "ok",
        "data": data,
    }


def _csv_safe(value):
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def export_session(history, fmt, output_dir="."):
    """Export all collected scans in a stable, tool-independent format."""
    if not history:
        raise ValueError("No scan results are available to export.")
    if fmt not in ("json", "csv", "txt"):
        raise ValueError(f"Unsupported export format: {fmt}")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    destination = Path(output_dir) / f"reconn3t_session_{timestamp}.{fmt}"

    if fmt == "json":
        with destination.open("w", encoding="utf-8") as file:
            json.dump(history, file, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with destination.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["timestamp", "tool", "target", "status", "data"])
            writer.writeheader()
            for item in history:
                writer.writerow({
                    "timestamp": _csv_safe(item["timestamp"]),
                    "tool": _csv_safe(item["tool"]),
                    "target": _csv_safe(item["target"]),
                    "status": _csv_safe(item["status"]),
                    "data": _csv_safe(json.dumps(item["data"], ensure_ascii=False)),
                })
    else:
        with destination.open("w", encoding="utf-8") as file:
            for index, item in enumerate(history, start=1):
                file.write(f"=== Scan {index}: {item['tool']} ({item['target']}) ===\n")
                file.write(f"Time: {item['timestamp']} UTC | Status: {item['status']}\n")
                file.write(item["data"] if isinstance(item["data"], str)
                           else json.dumps(item["data"], indent=2, ensure_ascii=False))
                file.write("\n\n")

    return destination
