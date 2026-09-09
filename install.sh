#!/bin/bash
# provide execution permissions before running
# RUN THIS: sudo chmod +x install.sh

# installing nftables
sudo apt update
sudo apt install nftables
sudo systemctl enable nftables
sudo systemctl start nftables

# check if firedome is already running, stop it
if systemctl is-active --quiet "firedomed"; then
    sudo systemctl stop firedomed;
fi

# write firewall rules to etc/firedome/rules.conf
sudo cp ~/firedome/firedome/config/rules.conf /etc/firedome/rules.conf

# copy the firedome daemon to /usr/local/bin
sudo cp ~/firedome/firedome/firedomed/target/release/firedomed /usr/local/bin
FDIR="/etc/systemd/system"

# create service file for firedome deamon
sudo tee "$FDIR/firedomed.service" > /dev/null << 'EOF'
[Unit]
Description=Firedome Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/firedomed
User=root
Group=root
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# reload deamon
sudo systemctl daemon-reload

# enable and start the service
sudo systemctl enable firedomed
sudo systemctl start firedomed
