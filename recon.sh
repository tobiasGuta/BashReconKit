#!/bin/bash

# Function to perform WHOIS lookup
function whois_lookup {
    echo -e "\nWHOIS Information:"
    whois "$1"
}

# Function to perform reverse WHOIS lookup
function reverse_whois {
    # Placeholder for reverse WHOIS lookup function
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
    read -p "Enter the target domain or IP address: " target
    
    while true; do
        echo -e "\nWhat would you like to do?"
        echo "1. WHOIS lookup"
        echo "2. Reverse WHOIS lookup"
        echo "3. nslookup"
        echo "4. Reverse IP lookup"
        echo "5. ASN lookup"
        echo "6. Change target"
        echo "7. Exit"
        
        # Read the user's choice
        read -p "Enter your choice: " choice
        
        case $choice in
            1) whois_lookup "$target" ;;
            2) reverse_whois "$target" ;;
            3) nslookup_target "$target" ;;
            4) reverse_ip_lookup "$target" ;;
            5) asn_lookup "$target" ;;
            6) read -p "Enter the new target domain or IP address: " target ;;
            7) echo "Exiting..."; exit ;;
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

# Call the main function
main
