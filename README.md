# ReconN3t - Advanced OSINT & Reconnaissance Framework

ReconN3t is a command-line based network reconnaissance and Open-Source Intelligence (OSINT) framework. It provides a centralized suite of tools useful for information gathering, threat intelligence pivoting, and vulnerability assessment in the context of cybersecurity. 

It integrates core command-line techniques (DNS, WHOIS) with powerful third-party APIs to gather passive DNS data, detect malicious infrastructure, and automatically generate structured incident response reports.

## Features

### WHOIS Lookup
- Performs a WHOIS query to retrieve registration details about a domain or IP address.

### DIG SOA Lookup
- Retrieves the Start of Authority (SOA) record for a domain using the `dig` tool, which helps in understanding the authoritative DNS information for the domain.

### DIG NS Lookup (Custom Nameserver)
- Performs DNS NS (Nameserver) lookup using a specified custom nameserver to identify DNS routing infrastructure.

### DIG Zone Transfer (AXFR) Lookup
- Attempts a DNS zone transfer (AXFR) using a custom nameserver to retrieve all DNS records associated with a domain. Useful for gathering massive amounts of information from a misconfigured nameserver.

### Subdomain Enumeration (Wordlist & DIG)
- Enumerates subdomains of a given target domain using a local wordlist and performs active DNS resolution for each via a targeted DNS server.

### Subdomain Enumeration (DNSDumpster API)
- Leverages the DNSDumpster API to passively discover subdomains, retrieving A, NS, MX, and CNAME records without sending direct traffic to the target infrastructure.

### Ping (ViewDNS API)
- Uses the ViewDNS API to perform a ping to a domain and retrieve round-trip time (RTT) values for network diagnostics.

### Reverse IP Lookup (ViewDNS API)
- Performs a reverse IP lookup using the ViewDNS API to find other domains hosted on the exact same IP address (Virtual Host mapping).

### Port Scan Lookup (ViewDNS API)
- Queries the ViewDNS API to perform a remote port scan on the target domain or IP to passively detect open ports and associated services.

### NSLOOKUP (Custom Record Types)
- A flexible wrapper around `nslookup` that allows you to query specific record types (A, MX, TXT, AAAA, etc.) against custom DNS servers.

### Deep Investigate IP (Threat Intel Pivot)
- **Production-Grade OSINT feature:** Automates threat intelligence pivoting against a suspect IP address. 
- Queries **Robtex** and **ThreatMiner** for historical Passive DNS (PDNS) records to see what domains used to resolve to the IP.
- Queries **VirusTotal v3** to find related malicious files and automatically flags domains that appear to be typosquatting attacks.

### Universal Data Export & Reporting
- Captures the output of *any* reconnaissance module run during the session.
- Allows the analyst to instantly export the findings into cleanly formatted **JSON**, **CSV**, or **TXT** files for use in official incident response reports or ingestion into other tools (like Pandas or Splunk).



# Installation 

    git clone https://github.com/tobiasGuta/BashReconKit.git
    cd BashReconKit
    
# Usage

    python3 recon.py [options]


![image](https://github.com/user-attachments/assets/adb1ffe6-d03f-4f0b-a127-41bc2589296c)



    
