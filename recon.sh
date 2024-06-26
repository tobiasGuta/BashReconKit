#!/bin/bash

# Function to display help
function display_help {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, 							--help           Display this help menu"
    echo "  -t, 							--target <target> Specify the target domain or IP address"
    echo
    echo "Description:"
    echo "This script allows you to perform various reconnaissance tasks on a target domain or IP address."
    echo "You can choose from the following options:"
    echo
    echo
    echo "1. WHOIS lookup 					- Retrieves WHOIS information for the target domain or IP address."
    echo "2. Reverse WHOIS lookup 				- (Not implemented) Perform a reverse WHOIS lookup based on the provided information."
    echo "3. nslookup 						- Performs a DNS lookup to retrieve DNS information about the target."
    echo "4. Reverse IP lookup 					- Performs a reverse DNS lookup to find domains associated with an IP address."
    echo "5. ASN lookup 						- Retrieves Autonomous System Number (ASN) information for the target."
    echo "6. DNS lookup (A record) 				- Retrieves the IPv4 address associated with the domain."
    echo "7. DNS lookup (AAAA record) 				- Retrieves the IPv6 address associated with the domain."
    echo "8. DNS lookup (MX records) 				- Finds the mail servers responsible for the domain."
    echo "9. DNS lookup (NS records) 				- Identifies the authoritative name servers for the domain."
    echo "10. DNS lookup (TXT records) 				- Retrieves any TXT records associated with the domain."
    echo "11. DNS lookup (CNAME record) 				- Retrieves the canonical name (CNAME) record for the domain."
    echo "12. DNS lookup (SOA record) 				- Retrieves the start of authority (SOA) record for the domain."
    echo "13. DNS lookup with specific nameserver 		- Performs DNS lookup using a specific nameserver."
    echo "14. DNS trace 						- Shows the full path of DNS resolution."
    echo "15. Reverse DNS lookup (dig -x) 			- Performs a reverse lookup on the IP address to find the associated host name."
    echo "16. Short answer DNS lookup 				- Provides a short, concise answer to the DNS query."
    echo "17. Answer section DNS lookup 				- Displays only the answer section of the DNS query output."
    echo "18. DNS lookup (ANY record) 				- Retrieves all available DNS records for the domain."
    echo "19. Change target 					- Change the target domain or IP address."
    echo "20. Exit 						- Exit the script."
    exit 1
}

# Function to perform WHOIS lookup
function whois_lookup {
    echo -e "\nWHOIS Information:"
    whois "$1"
}

# Function to perform reverse WHOIS lookup
function reverse_whois {
    echo -e "\nReverse WHOIS lookup not implemented yet"
}

# Function to perform nslookup
function nslookup_target {
    echo -e "\nNslookup Result:"
    nslookup "$1"
}

# Function to perform reverse IP lookup
function reverse_ip_lookup {
    echo -e "\nReverse IP Lookup:"
    host "$1"
}

# Function to perform ASN lookup
function asn_lookup {
    echo -e "\nASN Information:"
    output=$(whois -h whois.cymru.com " -v $1 " | awk 'NR==2' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    echo "$output"
}

# Main function
function main {
    # Prompt the user for the target domain or IP address
    if [ -z "$target" ]; then
        read -p "Enter the target domain or IP address: " target
    fi

    while true; do
        echo -e "\nWhat would you like to do?"
        echo "1. WHOIS lookup"
        echo "2. Reverse WHOIS lookup"
        echo "3. nslookup"
        echo "4. Reverse IP lookup"
        echo "5. ASN lookup"
        echo "6. DNS lookup (A record)"
        echo "7. DNS lookup (AAAA record)"
        echo "8. DNS lookup (MX records)"
        echo "9. DNS lookup (NS records)"
        echo "10. DNS lookup (TXT records)"
        echo "11. DNS lookup (CNAME record)"
        echo "12. DNS lookup (SOA record)"
        echo "13. DNS lookup with specific nameserver"
        echo "14. DNS trace"
        echo "15. Reverse DNS lookup (dig -x)"
        echo "16. Short answer DNS lookup"
        echo "17. Answer section DNS lookup"
        echo "18. DNS lookup (ANY record)"
        echo "19. Change target"
        echo "20. Exit"

        # Read the user's choice
        read -p "Enter your choice: " choice

        case $choice in
            1) whois_lookup "$target" ;;
            2) reverse_whois "$target" ;;
            3) nslookup_target "$target" ;;
            4) reverse_ip_lookup "$target" ;;
            5) asn_lookup "$target" ;;
            6) dig "$target" ;;
            7) dig "$target" AAAA ;;
            8) dig "$target" MX ;;
            9) dig "$target" NS ;;
            10) dig "$target" TXT ;;
            11) dig "$target" CNAME ;;
            12) dig "$target" SOA ;;
            13) read -p "Enter the nameserver: " nameserver
                dig "@$nameserver" "$target" ;;
            14) dig +trace "$target" ;;
            15) read -p "Enter the IP address: " ip_address
                dig -x "$ip_address" ;;
            16) dig +short "$target" ;;
            17) dig +noall +answer "$target" ;;
            18) dig "$target" ANY ;;
            19) read -p "Enter the new target domain or IP address: " target ;;
            20) echo "Exiting..."; exit ;;
            *) echo "Invalid choice!" ;;
        esac

        # Ask if user wants to continue with the same target
        read -p "Do you want to continue with the same target? (yes/no/exit): " continue_target
        if [ "$continue_target" != "yes" ] && [ "$continue_target" != "exit" ]; then
            read -p "Enter the new target domain or IP address: " target
        elif [ "$continue_target" == "exit" ]; then
            echo "Exiting..."
            exit
        fi
    done
}

# Process command-line options
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -h|--help)
        display_help
        ;;
        -t|--target)
        target="$2"
        shift # past argument
        shift # past value
        ;;
        *)    # unknown option
        echo "Unknown option: $1"
        display_help
        ;;
    esac
done

# Call the main function if no command-line options were provided
if [ -z "$target" ]; then
    main
else
    # If target is provided via command-line, directly execute the corresponding action
    dig "$target"
fi
