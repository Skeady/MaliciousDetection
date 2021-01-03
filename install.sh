#!/bin/bash

apt install python3-pip
pip3 install python-decouple
pip3 install virustotal-api
touch .env
echo "Enter VirusTotal API Key: "
read api_key
echo -e KEY=$api_key >> .env
python3 setup.py develop
GREEN= '\033[0;32m'
echo -e "\n\e[32mMalicious-detection is now installed run malicious-detection --help for available commands\n\n"