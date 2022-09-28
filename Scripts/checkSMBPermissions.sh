#!/bin/bash
if [ "$#" -ne 3 ]; then
    echo "./checkSMBPermissions.sh '<DOMAIN\\USER>' '<PASSWORD>' <HOST_IP>"
fi

cd "${TMPDIR:-/tmp}"
touch tmp_$$.tmp           # Required locally to copy to target

username=$1    # Double backslash
password=$2    # For demonstration purposes only
hostname=$3    # SMB hostname of target


aux=$(smbclient -L "//$hostname" -U "$username%$password")
if [[ ! $aux == *"Sharename"* ]]; then
    echo $aux
    exit 0
fi

shares=$(smbclient -L "//$hostname" -g -U "$username%$password" 2>/dev/null  | awk -F'|' '$1 == "Disk" {print $2}')

while read -r share
do
    echo "Checking share:'$share'"
    status=NONE 
    if smbclient "//$hostname/$share/" -U "$username%$password" -c "dir" >/dev/null 2>&1
    then
        status=" READ"
    fi  
    if smbclient "//$hostname/$share/" -U "$username%$password" -c "put tmp_$$.tmp ; rm tmp_$$.tmp" >/dev/null 2>&1 
    then
        status=$status" WRITE"
    fi  
    if [[ ! $status == "NONE" ]];then
        echo "  - $username has:$status permissions"
    fi  
done <<< "$shares"
rm -f tmp_$$.tmp