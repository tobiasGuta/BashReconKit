import subprocess
import os
import re

art = """
                                     @@@@@@@                               
                                   @@       @                              
                                 @         @@@                             
                             @@@@@     @@@  @@                             
                            @@    @@@@@@@@@@                               
                         @@@@@@@@@@@@       @  @@                          
                             @@@@    @@@     @@  @                         
                           @@ @ @@@   @@  @@     @                         
              @@@@@      @@   @@    @@@ @@       @                         
             @@  @@@    @@      @@@@    @        @                         
             @@    @@@ @@                @      @@                         
             @@@ @@ @@@ @       @@@@     @      @@                         
              @@@   @@@  @@@@@@ @@@      @@     @                          
               @@@@  @@         @ @@      @@    @                          
                 @@@@@          @  @@@  @@@@    @@@@@                      
                      @@        @       @@    @@@@@ @                      
                      @@@        @@     @@     @@@ @@ @@                   
                       @@@@@@      @@@@@@@      @    @@  @@                
                      @  @  @@@@@@     @    @@@@@ @@@ @@@                  
                        @@@@@ @  @   @@ @@@@    @@    @@                   
                          @@@@     @@  @   @        @@                     
                                       @  @@@@@@  @@@@                     
                               @@@     @ @@@    @@@ @@@                    
                               @@@@     @@@          @@@@                  
                                 @@@@@ @@@            @@@@                 
                                  @@@@@@@@              @@@@               
                                    @@@@@@      @@@@@@@@@@@@@@             
"""

def whois_lookup(target):
    """Performs a WHOIS lookup."""
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error running WHOIS lookup:", e)

def dig_soa_lookup(target):
    """Performs a DNS SOA (Start of Authority) lookup using dig."""
    try:
        result = subprocess.run(["dig", "soa", target], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(f"SOA Record for {target}:\n{result.stdout}")
        else:
            print(f"No SOA record found for {target}.")
    except subprocess.CalledProcessError as e:
        print("Error running DIG SOA lookup:", e)

def dig_custom_ns_lookup(target, nameserver):
    """Performs a DNS query using a custom nameserver."""
    try:
        result = subprocess.run(["dig", "ns", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(f"NS Record for {target} using nameserver {nameserver}:\n{result.stdout}")
        else:
            print(f"No NS record found for {target}.")
    except subprocess.CalledProcessError as e:
        print("Error running DIG query:", e)

def dig_zone_transfer_lookup(target, nameserver):
    """Performs a DNS zone transfer (AXFR) lookup using a custom nameserver."""
    try:
        result = subprocess.run(["dig", "axfr", target, "@"+nameserver], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(f"Zone Transfer (AXFR) for {target} using nameserver {nameserver}:\n{result.stdout}")
        else:
            print(f"Zone transfer not allowed or no data returned for {target}.")
    except subprocess.CalledProcessError as e:
        print("Error running DNS zone transfer lookup:", e)

def dig_subdomain_enum(target, dns_server, wordlist_path):
    """Enumerate subdomains using a wordlist."""
    # Check if the wordlist exists
    if not os.path.isfile(wordlist_path):
        print(f"Error: The file {wordlist_path} does not exist.")
        return

    with open(wordlist_path, "r") as wordlist_file:
        for subdomain in wordlist_file:
            subdomain = subdomain.strip()  # Remove extra whitespace/newlines
            if subdomain:  # Skip empty lines
                subdomain_full = f"{subdomain}.{target}"

                try:
                    # Run dig command to resolve the subdomain
                    result = subprocess.run(
                        ["dig", subdomain_full, "@" + dns_server],
                        capture_output=True,
                        text=True,
                        check=True
                    )

                    # Filter the output and only keep valid A records
                    output = result.stdout
                    if "ANSWER SECTION" in output and "A" in output:
                        # Extract domain and IP from the ANSWER SECTION
                        answer_section = re.findall(r"([^\s]+\.{}[\.\w]*)\s+\d+\s+IN\s+A\s+([^\s]+)".format(target), output)

                        # If matches are found, write them to the file and print them
                        for domain, ip in answer_section:
                            with open("subdomains.txt", "a") as f:
                                f.write(f"Found: {domain}\n")
                                f.write(f"{domain} IN A {ip}\n")
                            print(f"Found: {domain}")
                            print(f"{domain} IN A {ip}")

                except subprocess.CalledProcessError as e:
                    print(f"Error with {subdomain_full}: {e}")

def main():
    while True:
        # Display menu
        print(art)
        print("\nSelect an option:")
        print("1. WHOIS Lookup")
        print("2. DIG SOA Lookup")
        print("3. DIG NS Lookup with Custom Nameserver")
        print("4. DIG Zone Transfer (AXFR) Lookup with Custom Nameserver")
        print("5. Subdomain Enumeration (using a wordlist)")
        print("6. Exit")
        
        # Get user choice
        choice = input("Enter your choice: ")
        
        if choice == "1":
            target = input("Enter the domain or IP for WHOIS lookup: ")
            whois_lookup(target)
        elif choice == "2":
            target = input("Enter the domain for SOA lookup: ")
            dig_soa_lookup(target)
        elif choice == "3":
            target = input("Enter the domain for NS lookup: ")
            nameserver = input("Enter the DNS nameserver IP (e.g., 10.129.14.128): ")
            dig_custom_ns_lookup(target, nameserver)
        elif choice == "4":
            target = input("Enter the domain for Zone Transfer lookup: ")
            nameserver = input("Enter the DNS nameserver IP (e.g., 10.129.14.128): ")
            dig_zone_transfer_lookup(target, nameserver)
        elif choice == '5':
            target = input("Enter the target domain (e.g., example.com): ")
            dns_server = input("Enter the DNS server IP (e.g., 10.129.14.128): ")
            wordlist_path = input("Enter the path to your subdomain wordlist (e.g., /path/to/wordlist.txt): ")

            # Perform subdomain enumeration
            dig_subdomain_enum(target, dns_server, wordlist_path)

        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid option, please choose again.")

if __name__ == "__main__":
    main()
