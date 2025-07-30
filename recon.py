import subprocess
import os
import requests
import re
import time
from colorama import Fore, Style, init
from pyfiglet import figlet_format

init(autoreset=True)

def print_banner():
    print(Fore.MAGENTA + figlet_format("ReconN3t", font="slant"))

def print_section(title):
    print(Fore.CYAN + Style.BRIGHT + f"\n[+] {title}" + Style.RESET_ALL)

def whois_lookup(target):
    print_section("WHOIS Lookup")
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error running WHOIS lookup:", e)

def dig_soa_lookup(target):
    print_section("DIG SOA Lookup")
    try:
        result = subprocess.run(["dig", "soa", target], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
        else:
            print(Fore.YELLOW + f"No SOA record found for {target}.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error running DIG SOA lookup:", e)

def nslookup_record(domain, record_type, dns_server=None):
    print_section(f"NSLOOKUP - Type: {record_type.upper()}")

    cmd = ["nslookup", f"-type={record_type}", domain]
    if dns_server:
        cmd.append(dns_server)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running nslookup: {e}")

def dig_custom_ns_lookup(target, nameserver):
    print_section("DIG NS Lookup (Custom Nameserver)")
    try:
        result = subprocess.run(["dig", "ns", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
        else:
            print(Fore.YELLOW + f"No NS record found for {target}.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error running DIG query:", e)

def dig_zone_transfer_lookup(target, nameserver):
    print_section("Zone Transfer Lookup (AXFR)")
    try:
        result = subprocess.run(["dig", "axfr", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(Fore.GREEN + result.stdout)
        else:
            print(Fore.YELLOW + f"Zone transfer not allowed or no data returned for {target}.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error running zone transfer lookup:", e)

def dig_subdomain_enum(target, dns_server, wordlist_path):
    print_section("Subdomain Enumeration")
    if not os.path.isfile(wordlist_path):
        print(Fore.RED + f"Error: The file {wordlist_path} does not exist.")
        return

    with open(wordlist_path, "r") as wordlist_file:
        for subdomain in wordlist_file:
            subdomain = subdomain.strip()
            if subdomain:
                subdomain_full = f"{subdomain}.{target}"
                try:
                    result = subprocess.run(["dig", subdomain_full, "@" + dns_server], capture_output=True, text=True, check=True)
                    output = result.stdout
                    if "ANSWER SECTION" in output and "A" in output:
                        matches = re.findall(rf"([\w.-]+\\.{target})\\s+\\d+\\s+IN\\s+A\\s+([\\d.]+)", output)
                        for domain, ip in matches:
                            with open("subdomains.txt", "a") as f:
                                f.write(f"{domain} IN A {ip}\n")
                            print(Fore.YELLOW + f"[+] Subdomain: {Fore.GREEN}{domain} {Fore.YELLOW}→ IP: {Fore.CYAN}{ip}")
                except subprocess.CalledProcessError as e:
                    print(Fore.RED + f"Error with {subdomain_full}: {e}")

def subdomain_enum_dnsdumpster(domain, api_key):
    print_section("Subdomain Enumeration - DNSDumpster")
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {
        "X-API-Key": api_key,
        "User-Agent": "ReconN3t/1.0 (Python)",
        "Accept": "application/json",
    }

    try:
        time.sleep(2)
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            print(Fore.RED + "Rate limit exceeded. Please wait 2 seconds between requests.")
            return

        elif response.status_code != 200:
            print(Fore.RED + f"Error: Received status code {response.status_code}")
            print(Fore.YELLOW + f"Raw Response: {response.text}")
            return

        data = response.json()

        found = False
        for section in ["a", "ns", "mx", "cname"]:
            for record in data.get(section, []):
                host = record.get("host")
                ips = record.get("ips", [])
                for ip_info in ips:
                    ip = ip_info.get("ip")
                    if host and ip:
                        found = True
                        print(Fore.GREEN + f"{host} → {ip}")
                        with open("subdomains_dnsdumpster.txt", "a") as f:
                            f.write(f"{host} → {ip}\n")

        if not found:
            print(Fore.YELLOW + "No subdomains found or API response was empty.")

    except Exception as e:
        print(Fore.RED + f"Error during DNSDumpster lookup: {e}")

def ping_viewdns(target, api_key):
    print_section("Ping using ViewDNS")
    try:
        url = f"https://api.viewdns.info/ping/?host={target}&apikey={api_key}&output=json"
        response = requests.get(url)
        data = response.json()
        if "response" in data and "replys" in data["response"]:
            for reply in data["response"]["replys"]:
                print(Fore.GREEN + f"RTT: {reply['rtt']}")
        else:
            print(Fore.YELLOW + "No ping response or invalid data.")
    except Exception as e:
        print(Fore.RED + f"Error during ping: {e}")

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
        else:
            print(Fore.YELLOW + "No domains found or invalid data.")
    except Exception as e:
        print(Fore.RED + f"Error during reverse IP lookup: {e}")

def port_scan_lookup(target, api_key):
    print_section("Port Scan using ViewDNS")
    try:
        url = f"https://api.viewdns.info/portscan/?host={target}&apikey={api_key}&output=json"
        response = requests.get(url)
        data = response.json()
        if "response" in data and "port" in data["response"]:
            for port in data["response"]["port"]:
                print(Fore.YELLOW + f"Port {port['number']} ({port['service']}): {Fore.GREEN}{port['status']}")
        else:
            print(Fore.YELLOW + "No port scan results or invalid data.")
    except Exception as e:
        print(Fore.RED + f"Error during port scan lookup: {e}")

def main():
    print_banner()
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
        print(f"{Fore.CYAN}11.{Style.RESET_ALL} Exit")

        choice = input(Fore.MAGENTA + "\nEnter your choice: ")

        if choice == "1":
            whois_lookup(input("Enter domain/IP for WHOIS: "))
        elif choice == "2":
            dig_soa_lookup(input("Enter domain for SOA: "))
        elif choice == "3":
            dig_custom_ns_lookup(input("Enter domain: "), input("Enter custom nameserver IP: "))
        elif choice == "4":
            dig_zone_transfer_lookup(input("Enter domain: "), input("Enter custom nameserver IP: "))
        elif choice == "5":
            dig_subdomain_enum(
                input("Enter target domain: "),
                input("Enter DNS server IP: "),
                input("Enter subdomain wordlist path: ")
            )
        elif choice == "6":
            subdomain_enum_dnsdumpster(
                input("Enter domain to query with DNSDumpster: "),
                input("Enter your DNSDumpster API key: ")
            )
        elif choice == "7":
            ping_viewdns(input("Enter target domain: "), input("Enter ViewDNS API key: "))
        elif choice == "8":
            reverse_ip_lookup(input("Enter target domain: "), input("Enter ViewDNS API key: "))
        elif choice == "9":
            port_scan_lookup(input("Enter target domain: "), input("Enter ViewDNS API key: "))
        elif choice == "10":
            domain = input("Enter domain to lookup (e.g., example.com): ")
            record_type = input("Enter record type (A, MX, TXT, AAAA, etc): ").strip().upper()
            dns_server = input("Enter DNS server IP (optional, leave blank for default): ").strip()

            if dns_server == "":
                dns_server = None

            nslookup_record(domain, record_type, dns_server)
        elif choice == "11":
            print(Fore.RED + "Exiting ReconN3t...")
            break
        else:
            print(Fore.RED + "Invalid option, try again.")

if __name__ == "__main__":
    main()
