# Loki-ng
Refonte du logiciel d'attaques réseaux Loki-NG

# Install smcroute
sudo apt-get update
sudo apt-get install smcroute

# Edit smcroute configuration file
echo "mgroup from eth0 group 224.0.0.9" | sudo tee -a /etc/smcroute.conf

# Start and enable smcroute service
sudo systemctl start smcroute
sudo systemctl enable smcroute

# Join the multicast group manually
sudo ip maddr add 224.0.0.9 dev eth0

# Verify multicast group subscription
ip maddr show dev eth0
