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

# Function to perform DNS lookup for A record
function dig_a_record {
    local domain="$1"
    echo -e "\nA Record Lookup:"
    dig "$domain" A +short
}

# Function to perform DNS lookup for AAAA record (IPv6)
function dig_aaaa_record {
    local domain="$1"
    echo -e "\nAAAA Record Lookup:"
    dig "$domain" AAAA +short
}

# Function to perform DNS lookup for MX records
function dig_mx_records {
    local domain="$1"
    echo -e "\nMX Records:"
    dig "$domain" MX +short
}

# Function to perform DNS lookup for NS records
function dig_ns_records {
    local domain="$1"
    echo -e "\nNS Records:"
    dig "$domain" NS +short
}

# Function to perform DNS lookup for TXT records
function dig_txt_records {
    local domain="$1"
    echo -e "\nTXT Records:"
    dig "$domain" TXT +short
}

# Function to perform DNS lookup for CNAME record
function dig_cname_record {
    local domain="$1"
    echo -e "\nCNAME Record:"
    result=$(dig "$domain" CNAME +short)
    if [ -z "$result" ]; then
        echo "No CNAME record found."
    else
        echo "$result"
    fi
}

# Function to perform DNS lookup for SOA record
function dig_soa_record {
    local domain="$1"
    echo -e "\nSOA Record:"
    dig "$domain" SOA +short
}

# Function to perform DNS lookup with specific name server
function dig_with_nameserver {
    local nameserver="$1"
    local domain="$2"
    echo -e "\nDNS Lookup with specific nameserver ($nameserver):"
    dig "@$nameserver" "$domain" +short
}

# Function to perform DNS trace
function dig_trace {
    local domain="$1"
    echo -e "\nDNS Trace:"
    dig "$domain" +trace
}

# Function to perform reverse DNS lookup
function dig_reverse_lookup {
    local ip_address="$1"
    echo -e "\nReverse DNS Lookup:"
    dig -x "$ip_address" +short
}

# Function to perform short answer DNS lookup
function dig_short_answer {
    local domain="$1"
    echo -e "\nShort Answer DNS Lookup:"
    dig "$domain" +short
}

# Function to display only answer section of DNS lookup
function dig_answer_section {
    local domain="$1"
    echo -e "\nAnswer Section:"
    dig "$domain" +noall +answer
}

# Function to perform ANY record DNS lookup
function dig_any_record {
    local domain="$1"
    echo -e "\nANY Record Lookup:"
    dig "$domain" ANY
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
            6) dig_a_record "$target" ;;
            7) dig_aaaa_record "$target" ;;
            8) dig_mx_records "$target" ;;
            9) dig_ns_records "$target" ;;
            10) dig_txt_records "$target" ;;
            11) dig_cname_record "$target" ;;
            12) dig_soa_record "$target" ;;
            13) 
                read -p "Enter the specific nameserver (e.g., 1.1.1.1): " nameserver
                dig_with_nameserver "$nameserver" "$target" ;;
            14) dig_trace "$target" ;;
            15) dig_reverse_lookup "$target" ;;
            16) dig_short_answer "$target" ;;
            17) dig_answer_section "$target" ;;
            18) dig_any_record "$target" ;;
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

# Call the main function
main
