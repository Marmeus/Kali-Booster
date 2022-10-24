#!/bin/bash

sudo apt -qq update 2>&1 >/dev/null
sudo apt -qq install -y python3-pip  bat curl virtualenv python3 golang-go 2>&1 >/dev/null
mkdir ~/Tools

echo Installing bypass-url-parser...
git clone -q https://github.com/laluka/bypass-url-parser.git ~/Tools/Web/bypass-url-parser
cd ~/Tools/Web/bypass-url-parser
virtualenv -p python3 .py3
source .py3/bin/activate
pip install -q -r requirements.txt 2>&1 >/dev/null
deactivate 

echo Installing dontgo403...
git clone -q https://github.com/devploit/dontgo403 ~/Tools/Web/dontgo403; 
cd ~/Tools/Web/dontgo403; 
go get 2>&1 >/dev/null
go build 2>&1 >/dev/null

echo Installing forbidden...
git clone -q https://github.com/ivan-sincek/forbidden ~/Tools/Web/forbidden
cd ~/Tools/Web/forbidden/src/
pip3 install -q -r requirements.txt 2>&1 >/dev/null

echo Installing byp4xx...
git clone https://github.com/lobuhi/byp4xx.git ~/Tools/Web/byp4xx
cd ~/Tools/Web/byp4xx
chmod u+x byp4xx.py
