Reconnaissance Script
This Python script is a tool for performing various network reconnaissance tasks, primarily aimed at gathering information about a target domain or IP address. Here's a breakdown of what it does:

WHOIS Lookup (whois_lookup):

Uses the whois command to retrieve domain registration details (such as registrant, contact info, etc.) for a given domain or IP address.
DNS SOA Lookup (dig_soa_lookup):

Uses the dig command to perform a Start of Authority (SOA) lookup, which provides authoritative information about a domain, including the primary nameserver and other metadata.
DNS NS Lookup with Custom Nameserver (dig_custom_ns_lookup):

Uses the dig command to query the Name Server (NS) records for a domain, but with the ability to specify a custom nameserver.
DNS Zone Transfer Lookup (dig_zone_transfer_lookup):

Uses dig to attempt a DNS zone transfer (AXFR), which is an operation where a secondary DNS server retrieves a complete zone file from the primary nameserver. This can sometimes leak DNS data about the domain if misconfigured.
Subdomain Enumeration (dig_subdomain_enum):

This function performs subdomain enumeration by reading a wordlist and using dig to try resolving possible subdomains for the target domain. If a subdomain resolves to an IP address, it is saved and displayed.
Interactive Menu (main):

The script provides an interactive menu where the user can select one of the above operations and input the necessary information (such as the target domain, IP addresses, or custom wordlist paths). The results are displayed in the terminal, and relevant data is saved (e.g., found subdomains are written to a file named subdomains.txt).


# Installation 

    git clone https://github.com/tobiasGuta/BashReconKit.git
    cd BashReconKit
    
# Usage

    python3 recon.py [options]


![image](https://github.com/user-attachments/assets/8af87f55-2840-42af-a81c-136dd23bd06d)


    
