#!/bin/bash

# Function to perform WHOIS lookup
function whois_lookup {
    echo "WHOIS Information:"
    whois $1
}

# Function to perform reverse WHOIS lookup
function reverse_whois {
    # Placeholder for reverse WHOIS lookup function
    echo "Reverse WHOIS lookup not implemented yet"
}

# Function to perform nslookup
function nslookup_target {
    echo "Nslookup Result:"
    nslookup $1
}

# Function to perform reverse IP lookup
function reverse_ip_lookup {
    # Placeholder for reverse IP lookup function
    echo "Reverse IP lookup not implemented yet"
}

# Function to perform ASN lookup
function asn_lookup {
    echo "ASN Information:"
    output=$(whois -h whois.cymru.com " -v $1 " | awk 'NR==2' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    echo "$output"
}


# Main function
function main {
    # Prompt the user for the target domain or IP address
    read -p "Enter the target domain or IP address: " target
    
    # Present options to the user
    echo "What would you like to do?"
    echo "1. WHOIS lookup"
    echo "2. Reverse WHOIS lookup"
    echo "3. nslookup"
    echo "4. Reverse IP lookup"
    echo "5. ASN lookup"
    
    # Read the user's choice
    read -p "Enter your choice: " choice
    
    # Perform the chosen action
    case $choice in
        1) whois_lookup $target ;;
        2) reverse_whois $target ;;
        3) nslookup_target $target ;;
        4) reverse_ip_lookup $target ;;
        5) asn_lookup $target ;;
        *) echo "Invalid choice!" ;;
    esac
}

# Call the main function
main
