#!/bin/bash

# Requirements:
# sudo apt install -yqq bat curl virtualenv python3 golang-go

if [ "$#" -ne 1 ]; then
    >&2 echo "Illegal number of parameters"
    >&2 echo "Usage: $0 <URL>"
    exit 1
fi

STORED_PATH=$(pwd)

echo BYP4XX
echo ======
cd ~/Tools/Web/byp4xx/
python3 byp4xx.py $1
cd ..

echo bypass-url-parser
echo =================
cd ~/Tools/Web/bypass-url-parser/
source .py3/bin/activate
./bypass-url-parser.py --url=$1
deactivate
cd ..

echo dontgo403
echo =========
cd ~/Tools/Web/dontgo403/
./dontgo403 -u $1
cd ..

echo forbidden
echo =========
cd ~/Tools/Web/forbidden/src/
python3 forbidden.py -t all -u $1

cd $STORED_PATH

