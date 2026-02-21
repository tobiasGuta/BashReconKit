import subprocess
import os
import requests
import re
import time
import json
import csv
import getpass
from datetime import datetime
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from dotenv import load_dotenv

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
        result = subprocess.run(["whois", target], capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running WHOIS lookup: {e}")
        return None

def dig_soa_lookup(target):
    print_section("DIG SOA Lookup")
    try:
        result = subprocess.run(["dig", "soa", target], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"No SOA record found for {target}.")
            return None
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running DIG SOA lookup: {e}")
        return None

def nslookup_record(domain, record_type, dns_server=None):
    print_section(f"NSLOOKUP - Type: {record_type.upper()}")
    cmd = ["nslookup", f"-type={record_type}", domain]
    if dns_server:
        cmd.append(dns_server)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running nslookup: {e}")
        return None

def dig_custom_ns_lookup(target, nameserver):
    print_section("DIG NS Lookup (Custom Nameserver)")
    try:
        result = subprocess.run(["dig", "ns", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"No NS record found for {target}.")
            return None
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running DIG query: {e}")
        return None

def dig_zone_transfer_lookup(target, nameserver):
    print_section("Zone Transfer Lookup (AXFR)")
    try:
        result = subprocess.run(["dig", "axfr", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
            return result.stdout
        else:
            print(Fore.YELLOW + f"Zone transfer not allowed or no data returned for {target}.")
            return None
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running zone transfer lookup: {e}")
        return None

def dig_subdomain_enum(target, dns_server, wordlist_path):
    print_section("Subdomain Enumeration")
    found_subdomains = []
    if not os.path.isfile(wordlist_path):
        print(Fore.RED + f"Error: The file {wordlist_path} does not exist.")
        return None

    with open(wordlist_path, "r") as wordlist_file:
        for subdomain in wordlist_file:
            subdomain = subdomain.strip()
            if subdomain:
                subdomain_full = f"{subdomain}.{target}"
                try:
                    result = subprocess.run(["dig", subdomain_full, "@" + dns_server], capture_output=True, text=True, check=True)
                    output = result.stdout
                    if "ANSWER SECTION" in output and "A" in output:
                        matches = re.findall(rf"([\w.-]+\.{target})\s+\d+\s+IN\s+A\s+([\d.]+)", output)
                        for domain, ip in matches:
                            found_subdomains.append({"domain": domain, "ip": ip})
                            print(Fore.YELLOW + f"[+] Subdomain: {Fore.GREEN}{domain} {Fore.YELLOW}→ IP: {Fore.CYAN}{ip}")
                except subprocess.CalledProcessError as e:
                    print(Fore.RED + f"Error with {subdomain_full}: {e}")
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
        response = requests.get(url, headers=headers)
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
        response = requests.get(url)
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
        response = requests.get(url)
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
        response = requests.get(url)
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
        response = requests.get(url)
        if response.status_code == 200:
            pdns = response.json().get("pas", [])
            for item in pdns:
                domain = item.get("o")
                found_domains.append(domain)
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
    
    # Adding headers prevents the API from blocking default Python requests
    headers = {
        "User-Agent": "ReconN3t/1.0 (OSINT Framework)",
        "Accept": "application/json"
    }
    
    found_domains = []
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # ThreatMiner returns its own internal status_code inside the JSON
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
                
        # Gracefully handling API backend issues
        elif response.status_code == 404:
            print(Fore.YELLOW + "No passive DNS records found on ThreatMiner (404 Not Found).")
            
        elif response.status_code == 500:
            print(Fore.YELLOW + "[!] ThreatMiner returned a 500 Internal Server Error.")
            print(Fore.YELLOW + "    (This usually means they have no data for this IP, or their database is temporarily down).")
            
        else:
            print(Fore.RED + f"Error: Received HTTP status code {response.status_code}")
            
        return found_domains
        
    except Exception as e:
        print(Fore.RED + f"Error during ThreatMiner lookup: {e}")
        return []

def virustotal_ip_pivot(ip, api_key):
    print_section(f"VirusTotal v3 - IP to Domain Pivot ({ip})")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=20"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    vt_results = []

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            resolutions = response.json().get("data", [])
            for res in resolutions:
                domain = res['attributes']['host_name']
                try:
                    date_str = datetime.fromtimestamp(res['attributes']['date']).strftime('%Y-%m-%d')
                except Exception:
                    date_str = str(res['attributes']['date'])
                
                is_high_interest = "wayne" in domain.lower() or "po1s0n" in domain.lower()
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

# Universal Export Function

def export_last_scan(last_recon_data):
    if not last_recon_data:
        print(Fore.YELLOW + "\n[!] No scan data available to export. Please run a tool first.")
        return

    print_section(f"Exporting {last_recon_data['tool']} Results for {last_recon_data['target']}")
    choice = input(Fore.MAGENTA + "Export format (j = JSON, c = CSV, t = TXT for raw output): ").strip().lower()
    
    if choice not in ['j', 'c', 't']:
        print(Fore.RED + "Invalid format selected.")
        return
        
    tool_name = last_recon_data['tool'].replace(' ', '_').lower()
    target_name = last_recon_data['target'].replace('.', '_').replace(':', '_')
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"{tool_name}_{target_name}_{timestamp_str}"
    data = last_recon_data['data']
    
    try:
        if choice == 'j':
            with open(f"{base_filename}.json", 'w', encoding='utf-8') as f:
                json.dump(last_recon_data, f, indent=4)
            print(Fore.GREEN + Style.BRIGHT + f"[+] Saved to {base_filename}.json")
            
        elif choice == 'c':
            with open(f"{base_filename}.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Handle raw text (WHOIS/DIG)
                if isinstance(data, str):
                    writer.writerow(["Raw Output"])
                    writer.writerow([data])
                    
                # Handle standard structured lists (ViewDNS, Subdomains)
                elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                    dict_writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    dict_writer.writeheader()
                    dict_writer.writerows(data)
                    
                # Handle custom Option 11 nested dictionary payload
                elif isinstance(data, dict):
                    if "robtex_domains" in data or "virustotal_resolutions" in data or "threatminer_domains" in data:
                        writer.writerow(["Source", "Target IP", "Domain", "Last Resolved", "Notes"])
                        
                        # Export Robtex
                        for domain in data.get("robtex_domains", []):
                            writer.writerow(["Robtex", last_recon_data['target'], domain, "N/A", "Passive DNS"])
                            
                        # Export ThreatMiner
                        for item in data.get("threatminer_domains", []):
                            writer.writerow(["ThreatMiner", last_recon_data['target'], item['domain'], item['last_seen'], "Passive DNS"])
                            
                        # Export VirusTotal
                        for item in data.get("virustotal_resolutions", []):
                            notes = "High Interest (Typosquat)" if item['high_interest'] else ""
                            writer.writerow(["VirusTotal", last_recon_data['target'], item['domain'], item['last_resolved'], notes])
                    else:
                        writer.writerow(["Key", "Value"])
                        for k, v in data.items():
                            writer.writerow([k, v])
            print(Fore.GREEN + Style.BRIGHT + f"[+] Saved to {base_filename}.csv")
            
        elif choice == 't':
            with open(f"{base_filename}.txt", 'w', encoding='utf-8') as f:
                f.write(data if isinstance(data, str) else json.dumps(last_recon_data, indent=4))
            print(Fore.GREEN + Style.BRIGHT + f"[+] Saved to {base_filename}.txt")
            
    except Exception as e:
        print(Fore.RED + f"Error exporting data: {e}")

# Main Menu Execution

def main():
    print_banner()
    last_recon_data = None  # Stores the results of the last tool run
    
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
        print(f"{Fore.CYAN}11.{Style.RESET_ALL} Deep Investigate IP (Robtex + ThreatMiner + VirusTotal)")
        print(f"{Fore.YELLOW}12.{Style.RESET_ALL} Export Last Scan Results (CSV/JSON/TXT)")
        print(f"{Fore.CYAN}13.{Style.RESET_ALL} Exit")

        choice = input(Fore.MAGENTA + "\nEnter your choice: ").strip()

        if choice == "1":
            target = input("Enter domain/IP for WHOIS: ").strip()
            data = whois_lookup(target)
            if data: last_recon_data = {"tool": "WHOIS Lookup", "target": target, "data": data}
            
        elif choice == "2":
            target = input("Enter domain for SOA: ").strip()
            data = dig_soa_lookup(target)
            if data: last_recon_data = {"tool": "DIG SOA", "target": target, "data": data}
            
        elif choice == "3":
            target = input("Enter domain: ").strip()
            data = dig_custom_ns_lookup(target, input("Enter custom nameserver IP: ").strip())
            if data: last_recon_data = {"tool": "DIG NS", "target": target, "data": data}
            
        elif choice == "4":
            target = input("Enter domain: ").strip()
            data = dig_zone_transfer_lookup(target, input("Enter custom nameserver IP: ").strip())
            if data: last_recon_data = {"tool": "DIG AXFR", "target": target, "data": data}
            
        elif choice == "5":
            target = input("Enter target domain: ").strip()
            data = dig_subdomain_enum(target, input("Enter DNS server IP: ").strip(), input("Enter wordlist path: ").strip())
            if data: last_recon_data = {"tool": "DIG Subdomain Enum", "target": target, "data": data}
            
        elif choice == "6":
            target = input("Enter domain: ").strip()
            data = subdomain_enum_dnsdumpster(target, get_api_key("DNSDUMPSTER_API_KEY", "Enter DNSDumpster API key: "))
            if data: last_recon_data = {"tool": "DNSDumpster", "target": target, "data": data}
            
        elif choice == "7":
            target = input("Enter target IP/domain: ").strip()
            data = ping_viewdns(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data: last_recon_data = {"tool": "ViewDNS Ping", "target": target, "data": data}
            
        elif choice == "8":
            target = input("Enter target IP: ").strip()
            data = reverse_ip_lookup(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data: last_recon_data = {"tool": "ViewDNS Reverse IP", "target": target, "data": data}
            
        elif choice == "9":
            target = input("Enter target IP: ").strip()
            data = port_scan_lookup(target, get_api_key("VIEWDNS_API_KEY", "Enter ViewDNS API key: "))
            if data: last_recon_data = {"tool": "ViewDNS Port Scan", "target": target, "data": data}
            
        elif choice == "10":
            target = input("Enter domain: ").strip()
            dns_server = input("Enter DNS server IP (optional, leave blank for default): ").strip()
            data = nslookup_record(target, input("Enter record type: ").strip().upper(), dns_server if dns_server else None)
            if data: last_recon_data = {"tool": "NSLOOKUP", "target": target, "data": data}
            
        elif choice == "11":
            target_ip = input("Enter suspect IP address (e.g., 23.22.63.114): ").strip()
            vt_key = get_api_key("VT_API_KEY", "Enter VirusTotal v3 API Key (leave blank to skip VT): ")
            
            robtex_data = robtex_ip_lookup(target_ip)
            time.sleep(1) # Polite delay between external API calls
            
            threatminer_data = threatminer_ip_lookup(target_ip)
            
            vt_data = []
            if vt_key:
                time.sleep(1) 
                vt_data = virustotal_ip_pivot(target_ip, vt_key)
            else:
                print(Fore.YELLOW + "\nSkipping VirusTotal lookup (No API key provided).")
                
            last_recon_data = {
                "tool": "Deep Investigation",
                "target": target_ip,
                "data": {
                    "robtex_domains": robtex_data,
                    "threatminer_domains": threatminer_data,
                    "virustotal_resolutions": vt_data
                }
            }
            print(Fore.CYAN + "\n[!] Investigation complete. Select Option 12 from the menu to export these combined results.")
            
        elif choice == "12":
            export_last_scan(last_recon_data)
            
        elif choice == "13":
            print(Fore.RED + "Exiting ReconN3t...")
            break
        else:
            print(Fore.RED + "Invalid option, try again.")

if __name__ == "__main__":
    main()
