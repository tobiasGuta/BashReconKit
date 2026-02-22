ReconN3t - Advanced OSINT & Reconnaissance Framework
====================================================

ReconN3t is a command-line based network reconnaissance and Open-Source Intelligence (OSINT) framework. It provides a centralized suite of tools useful for information gathering, threat intelligence pivoting, and vulnerability assessment in the context of cybersecurity.

It integrates core command-line techniques (DNS, WHOIS) with powerful third-party APIs to gather passive DNS data, detect malicious infrastructure, retrieve historical DNS records, and automatically generate structured incident response reports.

Features
--------

ReconN3t is categorized into local system binaries, free OSINT APIs, and premium/key-required APIs.

### Local System Reconnaissance

-   **WHOIS Lookup:** Retrieves domain registration and contact details.

-   **DIG SOA Lookup:** Fetches the Start of Authority (SOA) record to identify the primary nameserver and admin email.

-   **DIG NS Lookup (Custom Nameserver):** Performs a Nameserver lookup using a specified custom DNS server.

-   **DIG Zone Transfer (AXFR):** Attempts a DNS zone transfer to retrieve all DNS records from a misconfigured nameserver.

-   **Subdomain Enumeration (DIG + Wordlist):** Brute-forces subdomains using a local wordlist and active DNS resolution.

-   **NSLOOKUP (Custom Record Types):** Queries specific DNS record types (A, MX, TXT, AAAA, etc.) against custom DNS servers.

### Free OSINT APIs (No Key Required)

-   **Robtex Passive DNS:** Queries Robtex to find domains that previously resolved to a target IP.

-   **ThreatMiner Passive DNS:** Leverages ThreatMiner's threat intelligence API to map IPs to historical domains and potential malware associations.

### Key-Required APIs (Configured via `.env`)

-   **Subdomain Enumeration (DNSDumpster):** Passively discovers subdomains (A, NS, MX, CNAME) without sending direct traffic to the target.

-   **Ping (ViewDNS):** Performs a remote ping to a domain to retrieve round-trip time (RTT) network diagnostics.

-   **Reverse IP Lookup (ViewDNS):** Finds other domains hosted on the exact same IP address (Virtual Host mapping).

-   **Port Scan (ViewDNS):** Passively detects open ports and associated services on a target domain/IP.

-   **VirusTotal IP Pivot:** Maps an IP address to associated domains/resolutions and automatically flags potential typosquatting or high-interest domains.

-   **SecurityTrails DNS History:** Retrieves historical "A" records for a domain to track infrastructure changes and old IP addresses over time.

### Universal Data Export & Reporting

-   Captures the output of *any* reconnaissance module run during the session.

-   Allows the analyst to instantly export the findings into cleanly formatted **JSON**, **CSV**, or **TXT** files for use in official incident response reports or ingestion into other tools.

Prerequisites
-------------

ReconN3t requires Python 3 and a few standard system networking tools (whois, dig, nslookup).

You will also need to install the required Python libraries:

```bash
pip install requests colorama pyfiglet python-dotenv
```

Configuration (API Keys)
------------------------

To use the advanced API features without manually entering your keys every time, create a .env file in the same directory as the script and add your API keys:

DNSDUMPSTER_API_KEY=your_key_here
VIEWDNS_API_KEY=your_key_here
VT_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here

*(Note: If an API key is missing from the .env file, ReconN3t will securely prompt you to enter it during execution.)*

Usage
-----

You can launch the interactive menu directly:
```bash
python3 recon.py
```

Or, use the new help flag to see a breakdown of all tools and their specific requirements before running:

```bash
python3 recon.py -h
```
