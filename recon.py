import argparse
import subprocess
import os
import time
import getpass
from datetime import datetime
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from dotenv import load_dotenv
from recon_utils import (
    ReconCommandError, export_session, make_scan_record,
    parse_ipv4_answers, run_command, safe_get,
)

# Initialize colorama and load .env variables
init(autoreset=True)
load_dotenv()

def print_banner():
    print(Fore.MAGENTA + figlet_format("ReconN3t", font="slant"))

def print_section(title):
    print(Fore.CYAN + Style.BRIGHT + f"\n[+] {title}" + Style.RESET_ALL)

def get_api_key(env_var_name, prompt_text):
    """Fetches an API key from the .env file or prompts the user securely."""
    key = os.getenv(env_var_name)
    if key:
        print(Fore.GREEN + f"[*] Successfully loaded {env_var_name} from .env file.")
        return key
    else:
        # getpass hides the user's input while they type
        return getpass.getpass(Fore.MAGENTA + prompt_text + Style.RESET_ALL).strip()

# Recon Functions (All now return data)

def whois_lookup(target):
    print_section("WHOIS Lookup")
    try:
        result = run_command(["whois", target], capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
        return result.stdout
    except (subprocess.CalledProcessError, ReconCommandError) as e:
        print(Fore.RED + f"Error running WHOIS lookup: {e}")
        return None

def dig_soa_lookup(target):
    print_section("DIG SOA Lookup")
    try:
        result = run_command(["dig", "soa", target], capture_output=True, text=True, check=True)
        if "ANSWER SECTION" in result.stdout and " SOA " in result.stdout:
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"No SOA record found for {target}.")
            return None
    except (subprocess.CalledProcessError, ReconCommandError) as e:
        print(Fore.RED + f"Error running DIG SOA lookup: {e}")
        return None

def nslookup_record(domain, record_type, dns_server=None):
    print_section(f"NSLOOKUP - Type: {record_type.upper()}")
    cmd = ["nslookup", f"-type={record_type}", domain]
    if dns_server:
        cmd.append(dns_server)
    try:
        result = run_command(cmd, capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
        return result.stdout
    except (subprocess.CalledProcessError, ReconCommandError) as e:
        print(Fore.RED + f"Error running nslookup: {e}")
        return None

def dig_custom_ns_lookup(target, nameserver):
    print_section("DIG NS Lookup (Custom Nameserver)")
    try:
        result = run_command(["dig", "ns", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"No NS record found for {target}.")
            return None
    except (subprocess.CalledProcessError, ReconCommandError) as e:
        print(Fore.RED + f"Error running DIG query: {e}")
        return None

def dig_zone_transfer_lookup(target, nameserver):
    print_section("Zone Transfer Lookup (AXFR)")
    try:
        result = run_command(["dig", "axfr", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if "XFR size:" in result.stdout:
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"Zone transfer not allowed or no data returned for {target}.")
            return None
    except (subprocess.CalledProcessError, ReconCommandError) as e:
        print(Fore.RED + f"Error running zone transfer lookup: {e}")
        return None

def dig_subdomain_enum(target, dns_server, wordlist_path):
    print_section("Subdomain Enumeration")
    if not os.path.isfile(wordlist_path):
        print(Fore.RED + f"Error: The file {wordlist_path} does not exist.")
        return None

    found_subdomains = []
    seen = set()
    server_args = ["@" + dns_server] if dns_server else []
    try:
        with open(wordlist_path, "r", encoding="utf-8") as wordlist_file:
            for word in wordlist_file:
                subdomain = word.strip().lower()
                if not subdomain or subdomain.startswith("#"):
                    continue
                full_domain = f"{subdomain}.{target}"
                try:
                    result = run_command(
                        ["dig", "+short", "A", full_domain, *server_args],
                        capture_output=True, text=True, check=True,
                    )
                    for ip in parse_ipv4_answers(result.stdout):
                        entry = (full_domain, ip)
                        if entry not in seen:
                            seen.add(entry)
                            found_subdomains.append({"domain": full_domain, "ip": ip})
                            print(Fore.YELLOW + f"[+] Subdomain: {Fore.GREEN}{full_domain} "
                                  + Fore.YELLOW + f"→ IP: {Fore.CYAN}{ip}")
                except (subprocess.CalledProcessError, ReconCommandError) as e:
                    print(Fore.RED + f"Error resolving {full_domain}: {e}")
    except OSError as e:
        print(Fore.RED + f"Cannot read wordlist: {e}")
        return None
    return found_subdomains


def subdomain_enum_dnsdumpster(domain, api_key):
    print_section("Subdomain Enumeration - DNSDumpster")
    if not api_key:
        print(Fore.RED + "API key is required for DNSDumpster.")
        return None
        
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": api_key, "User-Agent": "ReconN3t/1.0", "Accept": "application/json"}
    found_records = []

    try:
        time.sleep(2)
        response = safe_get(url, headers=headers)
        if response.status_code == 429:
            print(Fore.RED + "Rate limit exceeded.")
            return None
        elif response.status_code != 200:
            print(Fore.RED + f"Error: Received status code {response.status_code}")
            return None

        data = response.json()
        for section in ["a", "ns", "mx", "cname"]:
            for record in data.get(section, []):
                host = record.get("host")
                for ip_info in record.get("ips", []):
                    ip = ip_info.get("ip")
                    if host and ip:
                        found_records.append({"host": host, "ip": ip, "type": section.upper()})
                        print(Fore.GREEN + f"{host} → {ip}")

        if not found_records:
            print(Fore.YELLOW + "No subdomains found.")
        return found_records
    except Exception as e:
        print(Fore.RED + f"Error during DNSDumpster lookup: {e}")
        return None

def ping_viewdns(target, api_key):
    print_section("Ping using ViewDNS")
    try:
        url = f"https://api.viewdns.info/ping/?host={target}&apikey={api_key}&output=json"
        response = safe_get(url)
        data = response.json()
        if "response" in data and "replys" in data["response"]:
            for reply in data["response"]["replys"]:
                print(Fore.GREEN + f"RTT: {reply['rtt']}")
            return data["response"]["replys"]
        print(Fore.YELLOW + "No ping response or invalid data.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error during ping: {e}")
        return None

def reverse_ip_lookup(target, api_key):
    print_section("Reverse IP Lookup")
    try:
        url = f"https://api.viewdns.info/reverseip/?host={target}&apikey={api_key}&output=json"
        response = safe_get(url)
        data = response.json()
        if "response" in data and "domains" in data["response"]:
            print(Fore.GREEN + f"Total domains found: {data['response']['domain_count']}")
            for domain in data["response"]["domains"]:
                print(Fore.CYAN + f"Domain: {domain['name']}, Last Resolved: {domain['last_resolved']}")
            return data["response"]["domains"]
        print(Fore.YELLOW + "No domains found.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error during lookup: {e}")
        return None

def port_scan_lookup(target, api_key):
    print_section("Port Scan using ViewDNS")
    try:
        url = f"https://api.viewdns.info/portscan/?host={target}&apikey={api_key}&output=json"
        response = safe_get(url)
        data = response.json()
        if "response" in data and "port" in data["response"]:
            for port in data["response"]["port"]:
                print(Fore.YELLOW + f"Port {port['number']} ({port['service']}): {Fore.GREEN}{port['status']}")
            return data["response"]["port"]
        print(Fore.YELLOW + "No port scan results.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error during scan: {e}")
        return None

# OSINT Pivoting Functions

def robtex_ip_lookup(ip):
    print_section(f"Robtex - Passive DNS Lookup ({ip})")
    url = f"https://freeapi.robtex.com/ipquery/{ip}"
    found_domains = []
    try:
        response = safe_get(url)
        if response.status_code == 200:
            pdns = response.json().get("pas", [])
            for item in pdns:
                domain = item.get("o")
                found_domains.append({"domain": domain})
                print(Fore.CYAN + f"[*] {domain}")
            if not pdns:
                print(Fore.YELLOW + "No passive DNS records found.")
        return found_domains
    except Exception as e:
        print(Fore.RED + f"Error during Robtex lookup: {e}")
        return []

def threatminer_ip_lookup(ip):
    print_section(f"ThreatMiner - Passive DNS Lookup ({ip})")
    url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt=2"
    
    headers = {
        "User-Agent": "ReconN3t/1.0 (OSINT Framework)",
        "Accept": "application/json"
    }
    found_domains = []
    
    try:
        response = safe_get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if str(data.get("status_code")) == "200" and data.get("results"):
                results = data.get("results")
                print(Fore.GREEN + f"ThreatMiner found {len(results)} associated domains:")
                for item in results:
                    domain = item.get("domain")
                    last_seen = item.get("last_seen", "Unknown")
                    if domain:
                        found_domains.append({"domain": domain, "last_seen": last_seen})
                        print(Fore.CYAN + f"[*] {domain} " + Fore.WHITE + f"(Last seen: {last_seen})")
            else:
                print(Fore.YELLOW + "No passive DNS records found on ThreatMiner (Empty results).")
        elif response.status_code == 404:
            print(Fore.YELLOW + "No passive DNS records found on ThreatMiner (404 Not Found).")
        elif response.status_code == 500:
            print(Fore.YELLOW + "[!] ThreatMiner returned a 500 Internal Server Error.")
        else:
            print(Fore.RED + f"Error: Received HTTP status code {response.status_code}")
        return found_domains
    except Exception as e:
        print(Fore.RED + f"Error during ThreatMiner lookup: {e}")
        return []

def virustotal_ip_pivot(ip, api_key):
    print_section(f"VirusTotal v3 - IP to Domain Pivot ({ip})")
    if not api_key:
        print(Fore.RED + "API key is required for VirusTotal.")
        return None

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=20"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    vt_results = []

    try:
        response = safe_get(url, headers=headers)
        if response.status_code == 200:
            resolutions = response.json().get("data", [])
            for res in resolutions:
                domain = res['attributes']['host_name']
                try:
                    date_str = datetime.fromtimestamp(res['attributes']['date']).strftime('%Y-%m-%d')
                except Exception:
                    date_str = str(res['attributes']['date'])
                
                keywords = [word.strip().lower() for word in
                                     os.getenv("RECON_HIGH_INTEREST_KEYWORDS", "").split(",")
                                     if word.strip()]
                is_high_interest = any(word in domain.lower() for word in keywords)
                vt_results.append({"domain": domain, "last_resolved": date_str, "high_interest": is_high_interest})
                
                print(Fore.CYAN + f"[*] {domain} " + Fore.WHITE + f"(Last resolved: {date_str})")
                if is_high_interest:
                    print(Fore.RED + Style.BRIGHT + f"    [!] HIGH INTEREST DOMAIN: {domain}")
            
            if not resolutions:
                print(Fore.YELLOW + "No domains found resolving to this IP on VirusTotal.")
        elif response.status_code == 401:
            print(Fore.RED + "Invalid VirusTotal API Key.")
        return vt_results
    except Exception as e:
        print(Fore.RED + f"Error during VirusTotal lookup: {e}")
        return []

def securitytrails_dns_history(domain, api_key):
    print_section(f"SecurityTrails - DNS 'A' Record History ({domain})")
    if not api_key:
        print(Fore.RED + "API key is required for SecurityTrails.")
        return None

    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json"
    }
    st_results = []

    try:
        response = safe_get(url, headers=headers)
        if response.status_code == 200:
            records = response.json().get("records", [])
            print(Fore.GREEN + f"Found {len(records)} historical records:")
            
            for rec in records:
                first_seen = rec.get("first_seen", "Unknown")
                last_seen = rec.get("last_seen", "Unknown")
                orgs = ", ".join(rec.get("organizations", []))
                
                for val in rec.get("values", []):
                    ip = val.get("ip")
                    st_results.append({
                        "ip": ip,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "organizations": orgs
                    })
                    print(Fore.CYAN + f"[*] IP: {ip} | First Seen: {first_seen} | Last Seen: {last_seen} | Org: {orgs}")
            
            if not records:
                print(Fore.YELLOW + "No DNS history records found.")
        elif response.status_code == 401:
            print(Fore.RED + "Invalid SecurityTrails API Key.")
        elif response.status_code == 429:
            print(Fore.RED + "Rate limit exceeded for SecurityTrails.")
        else:
            print(Fore.RED + f"Error: Received HTTP status code {response.status_code}")
        
        return st_results
    except Exception as e:
        print(Fore.RED + f"Error during SecurityTrails lookup: {e}")
        return []

# Universal Export Function

def export_scan_history(scan_history):
    if not scan_history:
        print(Fore.YELLOW + "\n[!] No scan data available to export. Please run a tool first.")
        return

    print_section(f"Exporting {len(scan_history)} scan(s) from this session")
    choice = input(Fore.MAGENTA + "Export format (j = JSON, c = CSV, t = TXT): ").strip().lower()
    fmt = {"j": "json", "c": "csv", "t": "txt"}.get(choice)
    if fmt is None:
        print(Fore.RED + "Invalid format selected.")
        return

    try:
        destination = export_session(scan_history, fmt)
        print(Fore.GREEN + Style.BRIGHT + f"[+] Saved to {destination}")
    except (OSError, ValueError) as e:
        print(Fore.RED + f"Error exporting data: {e}")


# Help Menu / Argparse Setup

def setup_argparse():
    help_text = """
ReconN3t - DNS & OSINT Reconnaissance Framework

========================================================================================
Tool Descriptions & Requirements:
========================================================================================

Local System / System Binary Required:
  1.  WHOIS Lookup                  - Gathers domain registration info. (Req: `whois`)
  2.  DIG SOA Lookup                - Fetches Start of Authority records. (Req: `dig`)
  3.  DIG NS Lookup (Custom)        - Fetches Nameserver records. (Req: `dig`)
  4.  DIG Zone Transfer (AXFR)      - Attempts a DNS zone transfer. (Req: `dig`)
  5.  Subdomain Enum (DIG)          - Brute-forces subdomains. (Req: `dig`, wordlist)
  10. NSLOOKUP Custom Record        - Queries specific DNS records. (Req: `nslookup`)

Free / No-Key OSINT APIs:
  11. Robtex Passive DNS            - Finds passive DNS entries via Robtex. 
  12. ThreatMiner Passive DNS       - Queries ThreatMiner's threat intelligence API.

Key-Required APIs (Add to .env file or input securely at prompt):
  6.  DNSDumpster Subdomains        - (Req: DNSDUMPSTER_API_KEY)
  7.  ViewDNS Ping                  - (Req: VIEWDNS_API_KEY)
  8.  ViewDNS Reverse IP            - (Req: VIEWDNS_API_KEY)
  9.  ViewDNS Port Scan             - (Req: VIEWDNS_API_KEY)
  13. VirusTotal IP Pivot           - (Req: VT_API_KEY)
  14. SecurityTrails DNS History    - (Req: SECURITYTRAILS_API_KEY)
========================================================================================
"""
    parser = argparse.ArgumentParser(
        description="ReconN3t Interactive Framework",
        epilog=help_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Just parse args to hook '-h' or '--help'. Standard running continues if no args.
    parser.parse_args()


# Main Menu Execution

def main():
    setup_argparse()  # Catch -h/--help before starting the interactive menu
    print_banner()
    scan_history = []  # Retains all completed scans, including empty results
    
    while True:
        print(Fore.BLUE + Style.BRIGHT + "\n=== DNS & Recon Tool Menu ===" + Style.RESET_ALL)
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} WHOIS Lookup")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} DIG SOA Lookup")
        print(f"{Fore.CYAN}3.{Style.RESET_ALL} DIG NS Lookup with Custom Nameserver")
        print(f"{Fore.CYAN}4.{Style.RESET_ALL} DIG Zone Transfer (AXFR) Lookup")
        print(f"{Fore.CYAN}5.{Style.RESET_ALL} Subdomain Enumeration (DIG)")
        print(f"{Fore.CYAN}6.{Style.RESET_ALL} Subdomain Enumeration (DNSDumpster API)")
        print(f"{Fore.CYAN}7.{Style.RESET_ALL} Ping using ViewDNS API")
        print(f"{Fore.CYAN}8.{Style.RESET_ALL} Reverse IP Lookup using ViewDNS API")
        print(f"{Fore.CYAN}9.{Style.RESET_ALL} Port Scan using ViewDNS API")
        print(f"{Fore.CYAN}10.{Style.RESET_ALL} NSLOOKUP with Custom Record Type & DNS")
        print(f"{Fore.MAGENTA}11.{Style.RESET_ALL} Robtex Passive DNS Lookup")
        print(f"{Fore.MAGENTA}12.{Style.RESET_ALL} ThreatMiner Passive DNS Lookup")
        print(f"{Fore.MAGENTA}13.{Style.RESET_ALL} VirusTotal IP to Domain Pivot")
        print(f"{Fore.MAGENTA}14.{Style.RESET_ALL} SecurityTrails DNS History (A Records)")
        print(f"{Fore.YELLOW}15.{Style.RESET_ALL} Export Session Results (CSV/JSON/TXT)")
        print(f"{Fore.CYAN}16.{Style.RESET_ALL} Exit")

        choice = input(Fore.MAGENTA + "\nEnter your choice: ").strip()

        if choice == "1":
            target = input("Enter domain/IP for WHOIS: ").strip()
            data = whois_lookup(target)
            if data is not None: scan_history.append(make_scan_record({"tool": "WHOIS Lookup", "target": target, "data": data}))
            
        elif choice == "2":
            target = input("Enter domain for SOA: ").strip()
            data = dig_soa_lookup(target)
            if data is not None: scan_history.append(make_scan_record({"tool": "DIG SOA", "target": target, "data": data}))
            
        elif choice == "3":
            target = input("Enter domain: ").strip()
            data = dig_custom_ns_lookup(target, input("Enter custom nameserver IP: ").strip())
            if data is not None: scan_history.append(make_scan_record({"tool": "DIG NS", "target": target, "data": data}))
            
        elif choice == "4":
            target = input("Enter domain: ").strip()
            data = dig_zone_transfer_lookup(target, input("Enter custom nameserver IP: ").strip())
            if data is not None: scan_history.append(make_scan_record({"tool": "DIG AXFR", "target": target, "data": data}))
            
        elif choice == "5":
            target = input("Enter target domain: ").strip()
            data = dig_subdomain_enum(target, input("Enter DNS server IP: ").strip(), input("Enter wordlist path: ").strip())
            if data is not None: scan_history.append(make_scan_record({"tool": "DIG Subdomain Enum", "target": target, "data": data}))
            
        elif choice == "6":
            target = input("Enter domain: ").strip()
            data = subdomain_enum_dnsdumpster(target, get_api_key("DNSDUMPSTER_API_KEY", "Enter DNSDumpster API key: "))
            if data is not None: scan_history.append(make_scan_record({"tool": "DNSDumpster", "target": target, "data": data}))
            
        elif choice == "7":
            target = input("Enter target IP/domain: ").strip()
            data = ping_viewdns(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data is not None: scan_history.append(make_scan_record({"tool": "ViewDNS Ping", "target": target, "data": data}))
            
        elif choice == "8":
            target = input("Enter target IP: ").strip()
            data = reverse_ip_lookup(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data is not None: scan_history.append(make_scan_record({"tool": "ViewDNS Reverse IP", "target": target, "data": data}))
            
        elif choice == "9":
            target = input("Enter target IP: ").strip()
            data = port_scan_lookup(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data is not None: scan_history.append(make_scan_record({"tool": "ViewDNS Port Scan", "target": target, "data": data}))
            
        elif choice == "10":
            target = input("Enter domain: ").strip()
            dns_server = input("Enter DNS server IP (optional, leave blank for default): ").strip()
            data = nslookup_record(target, input("Enter record type: ").strip().upper(), dns_server if dns_server else None)
            if data is not None: scan_history.append(make_scan_record({"tool": "NSLOOKUP", "target": target, "data": data}))
            
        elif choice == "11":
            target_ip = input("Enter suspect IP address: ").strip()
            data = robtex_ip_lookup(target_ip)
            if data is not None: scan_history.append(make_scan_record({"tool": "Robtex Passive DNS", "target": target_ip, "data": data}))

        elif choice == "12":
            target_ip = input("Enter suspect IP address: ").strip()
            data = threatminer_ip_lookup(target_ip)
            if data is not None: scan_history.append(make_scan_record({"tool": "ThreatMiner Passive DNS", "target": target_ip, "data": data}))

        elif choice == "13":
            target_ip = input("Enter suspect IP address: ").strip()
            vt_key = get_api_key("VT_API_KEY", "Enter VirusTotal v3 API Key: ")
            data = virustotal_ip_pivot(target_ip, vt_key)
            if data is not None: scan_history.append(make_scan_record({"tool": "VirusTotal Pivot", "target": target_ip, "data": data}))

        elif choice == "14":
            target_domain = input("Enter target domain for DNS History (e.g., oracle.com): ").strip()
            st_key = get_api_key("SECURITYTRAILS_API_KEY", "Enter SecurityTrails API Key: ")
            data = securitytrails_dns_history(target_domain, st_key)
            if data is not None: scan_history.append(make_scan_record({"tool": "SecurityTrails DNS History", "target": target_domain, "data": data}))

        elif choice == "15":
            export_scan_history(scan_history)
            
        elif choice == "16":
            print(Fore.RED + "Exiting ReconN3t...")
            break
        else:
            print(Fore.RED + "Invalid option, try again.")

if __name__ == "__main__":
    main()
