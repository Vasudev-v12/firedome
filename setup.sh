#!/bin/bash

# run this before executing this file: chmod +x setup.sh
# to execute: ./setup.sh

sudo apt update
sudo apt install nftables
sudo systemctl enable nftables
sudo systemctl start nftables
sudo nft add table inet firedome_firewall

#chains
sudo nft add chain inet firewall input '{ type filter hook input priority 0; policy accept; }'
sudo nft add chain inet firewall output '{ type filter hook output priority 0; policy accept; }'
sudo nft add chain inet firewall forward '{ type filter hook forward priority 0; policy accept; }'
