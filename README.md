Reconnaissance Script
This script provides a suite of tools for performing reconnaissance tasks on a specified domain or IP address. It is designed to facilitate various network and DNS investigations from a single interface.

# Features

WHOIS Lookup: Retrieves WHOIS information for the target domain or IP address.
Reverse WHOIS Lookup: (Not implemented) Intended for reverse WHOIS lookups.
nslookup: Performs DNS lookups to retrieve DNS information about the target.
Reverse IP Lookup: Identifies domains associated with a given IP address.
ASN Lookup: Retrieves Autonomous System Number (ASN) information.
DNS Lookups:

    A record: IPv4 address
    AAAA record: IPv6 address
    MX records: Mail servers
    NS records: Authoritative name servers
    TXT records: Text records
    CNAME record: Canonical name
    SOA record: Start of authority
    ANY record: All available DNS records
    DNS Trace: Shows the path of DNS resolution.
    Reverse DNS Lookup (dig -x): Performs a reverse lookup on an IP address to find the associated hostname.
    Short Answer DNS Lookup: Provides concise DNS query results.
    Answer Section DNS Lookup: Displays only the answer section of DNS query output.
    DNS Lookup with Specific Nameserver: Allows querying through a specified nameserver.
    Change Target: Easily switch the target domain or IP address.
    Exit: Exit the script.


# Installation 

    git clone https://github.com/tobiasGuta/BashReconKit.git
    cd BashReconKit
    chmod +x recon.sh
    
# Usage

    ./recon_script.sh [options]

    -h, --help: Display the help menu.
    -t, --target <target>: Specify the target domain or IP address.


![recon](https://github.com/user-attachments/assets/0ef8a136-a138-415c-8a37-0b9619271e31)

# Example

To perform a WHOIS lookup on example.com:

    ./recon_script.sh -t example.com
    
# Reconnaissance Tasks Available:
WHOIS lookup
Reverse WHOIS lookup
nslookup
Reverse IP lookup
ASN lookup
DNS lookup (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY records)
DNS trace
Reverse DNS lookup (dig -x)
Change target
Exit
The script provides flexibility by allowing the user to specify a target domain or IP address and execute multiple reconnaissance tasks in a single session.

Notes:
Some features, like reverse WHOIS lookup, are not yet implemented.
DNS queries are executed using dig, whois, and other network tools commonly available on Unix-based systems.
