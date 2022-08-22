#!/bin/bash

#       TO DO
# ------------------
# - Show some nmap progress bar or show the whole nmap output


NETWORK_MASKS="32 24 16"

trap "echo Exited!; exit;" SIGINT SIGTERM
TEMP_FOLDER=$(mktemp -d -t massScan_depth_XXXXXX)

# =======================================
#             CHECK PARAMETERS
# =======================================

if [ "$#" -ne 1 ]; then
    >&2 echo "Illegal number of parameters"
    >&2 echo "Usage: $0 <massScan_output_folder>"
    exit 1
fi

# Obtain all open or filetered ports
input_dir=$1
grep -lE "/tcp (open|filtered)" $(find $input_dir -name *.nmap) > $TEMP_FOLDER/open_ports_files.txt
# =======================================
#             START SCANNING
# =======================================
for file in $(cat $TEMP_FOLDER/open_ports_files.txt)
do
    ip=$(grep "Nmap scan report for " $file | awk '{print $5}')
    output_dir=${file%/*}
    puertos=$(cat $file | tail -n +2 | grep open | awk -F/  '{print $1}'  ORS=',' | sed 's/.$//')
    echo -e "\n\n============================"
    echo "Scanning IP: $ip"
    echo -e "============================"
    sudo nmap -Pn -sC -sV -n -T4 -oN $output_dir/PortsDepth.txt $ip >/dev/null
done

rm -rf $TEMP_FOLDER
