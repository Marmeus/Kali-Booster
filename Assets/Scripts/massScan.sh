#!/bin/bash

#       TO DO
# ------------------
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


# =======================================
#             GET LIST OF IPs 
# =======================================
TEMP_FOLDER=$(mktemp -d -t massScan_XXXXXX)
nmap -sL -n $1 -oN $TEMP_FOLDER/nmap_ips_list.txt >/dev/null
grep -i "scan report for" $TEMP_FOLDER/nmap_ips_list.txt | awk '{print $5}' > $TEMP_FOLDER/ips_list.txt

mkdir -p $TEMP_FOLDER/tmp_scan/
# =======================================
#             START SCANNING
# =======================================
for ip in $(cat $TEMP_FOLDER/ips_list.txt)
do
    echo -e "\n\n============================"
    echo "Scanning IP: $ip"
    echo -e "============================"
    # folder = OUTPUT_DIR + HOST
    folder=$output_dir/$ip
    sudo nmap -Pn --max-retries 1 -T4 --min-rate 4500 --max-rtt-timeout 1500ms -sS -p- $ip -oA $TEMP_FOLDER/tmp_scan/AllPorts 
    result=$(grep -lE "/tcp (open|filtered)" $TEMP_FOLDER/tmp_scan/AllPorts.nmap)
    if [[ $result == "" ]]; then
        rm -rf $TEMP_FOLDER/tmp_scan/*
    else
        mkdir -p $folder 2>/dev/null
        mv $TEMP_FOLDER/tmp_scan/* $folder
    fi
done

rm -rf $TEMP_FOLDER
