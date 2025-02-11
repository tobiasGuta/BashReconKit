Reconnaissance Script
This tool is a command-line based network reconnaissance tool with various functionalities useful for information gathering and vulnerability assessment in the context of cybersecurity. It integrates several techniques to gather DNS and WHOIS information, perform subdomain enumeration, and utilize external APIs for additional services like port scanning and reverse IP lookup.

Here's a breakdown of its features:

WHOIS Lookup:
Performs a WHOIS query to retrieve registration details about a domain or IP address.

DIG SOA Lookup:
Retrieves the Start of Authority (SOA) record for a domain using the dig tool, which helps in understanding the authoritative DNS information for the domain.

DIG NS Lookup (Custom Nameserver):
Performs DNS NS (Nameserver) lookup using a specified custom nameserver.

DIG Zone Transfer (AXFR) Lookup:
Attempts a DNS zone transfer (AXFR) using a custom nameserver to retrieve all DNS records associated with a domain. This can be useful for gathering more information from a misconfigured nameserver.

Subdomain Enumeration:
Enumerates subdomains of a given target domain using a wordlist and performs DNS resolution for each subdomain using a DNS server.

Ping (ViewDNS API):
Uses the ViewDNS API to perform a ping to a domain and retrieve round-trip time (RTT) values for network diagnostics.

Reverse IP Lookup (ViewDNS API):
Performs a reverse IP lookup using the ViewDNS API to find domains hosted on the same IP address.

Port Scan Lookup (ViewDNS API):
Queries the ViewDNS API to perform a port scan on the target domain or IP to detect open ports and associated services.


# Installation 

    git clone https://github.com/tobiasGuta/BashReconKit.git
    cd BashReconKit
    
# Usage

    python3 recon.py [options]


![image](https://github.com/user-attachments/assets/adb1ffe6-d03f-4f0b-a127-41bc2589296c)



    
