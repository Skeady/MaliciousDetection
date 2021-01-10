#!/bin/bash

if [ "$(whoami)" != "root" ]; then
	echo -e "\e[31mPlease run as root or use \e[4msudo ./install.sh !"
	exit 1
fi
apt install python3-pip
pip3 install setuptools
pip3 install python-decouple
pip3 install virustotal-api
pip3 install tqdm
touch .env
echo "Enter VirusTotal API Key: "
read api_key
if grep -Fxq "KEY='$api_key'" .env
then
	echo "Key already exists continuing install!"
else
	echo -e KEY="'$api_key'" >> .env
fi
python3 setup.py develop
GREEN= '\033[0;32m'
echo -e "\n\e[32mMalicious-detection is now installed run \e[1m\e[4mmalware-detection --help\e[0m\e[32m for available commands\n\n"