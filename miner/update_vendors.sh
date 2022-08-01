#!/usr/bin/env bash

curl -s https://raw.githubusercontent.com/royhills/arp-scan/master/ieee-oui.txt | grep -v "^#" > vendors.txt
