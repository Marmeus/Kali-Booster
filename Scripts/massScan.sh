#!/bin/bash

#       TO DO
# ------------------
# - Show some nmap progress bar or show the whole nmap`output
# - Do not create a folder if no open port is discovered
# - Accept more network masks 

NETWORK_MASKS="32 24 16"

trap "echo Exited!; exit;" SIGINT SIGTERM

# =======================================
#             CHECK PARAMETERS
# =======================================

if [ "$#" -ne 2 ]; then
    >&2 echo "Illegal number of parameters"
    >&2 echo "Usage: $0 192.168.1.1/24 /tmp/"
    exit 1
fi

output_dir=$2

if [[ $1 != *"/"* ]]; then
    >&2 echo "Network mask not set up."
    >&2 echo "Usage: $0 192.168.1.1/24 /tmp/"
    exit 1
fi

network_mask=$(echo $1 | cut -d '/' -f 2)
if [[ ! $NETWORK_MASKS =~ (^|[[:space:]])$network_mask($|[[:space:]]) ]]; then
    >&2 echo "Network mask not valid"
    >&2 echo "Accepted maks: 32, 24, 16"
    exit 1
fi

# =======================================
#             GET LIST OF IPs 
# =======================================
TEMP_FOLDER=$(mktemp -d -t massScan_XXXXXX)
nmap -sL -n $1 -oN $TEMP_FOLDER/nmap_ips_list.txt >/dev/null
grep -i "scan report for" $TEMP_FOLDER/nmap_ips_list.txt | awk '{print $5}' > $TEMP_FOLDER/ips_list.txt


# =======================================
#             START SCANNING
# =======================================
for ip in $(cat $TEMP_FOLDER/ips_list.txt)
do
    echo -e "\n\n============================"
    echo "Scanning IP: $ip"
    echo -e "n============================"
    if [[ $network_mask == 32 || $network_mask == 24 ]]; then
        # folder = OUTPUT_DIR + HOST
        folder=$output_dir$(echo $ip | cut -d '.' -f 4)
        mkdir -p $folder 2>/dev/null
        sudo nmap -Pn --max-retries 1 -T4 --min-rate 4500 --max-rtt-timeout 1500ms -sS -p- $ip -oA $folder/AllPorts >/dev/null
    elif [[ $network_mask == 16 ]]; then
        # folder = OUTPUT_DIR + NETWORK + HOST
        folder=$output_dir$(echo $ip | cut -d '.' -f 3,4 --output-delimiter '/') 
        mkdir -p $folder 2>/dev/null
        sudo nmap -Pn --max-retries 1 -T4 --min-rate 4500 --max-rtt-timeout 1500ms -sS -p- $ip -oA $folder/AllPorts >/dev/null
    else
        echo "ERROR: Wrong network mask"
        exit 1
    fi
done

rm -rf $TEMP_FOLDER
