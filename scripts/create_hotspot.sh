#!/usr/bin/bash
AP_INTERFACE=wlan1
OUT_INTERFACE=wlan0
CONNECTION_NAME=testhotspot
SSID_PASSWORD="somepassword"
MY_IP="10.13.37.1"

# https://gist.github.com/narate/d3f001c97e1c981a59f94cd76f041140
sudo nmcli con add type wifi ifname $AP_INTERFACE con-name $CONNECTION_NAME autoconnect yes ssid $CONNECTION_NAME
sudo nmcli con modify $CONNECTION_NAME 802-11-wireless.mode ap ipv4.method manual ipv4.addresses $MY_IP/24 ipv4.gateway $MY_IP
sudo nmcli con modify $CONNECTION_NAME wifi-sec.key-mgmt wpa-psk 
sudo nmcli con modify $CONNECTION_NAME wifi-sec.psk $SSID_PASSWORD

sudo sysctl -w net.ipv4.ip_forward=1 # Enable IP forwarding
sudo iptables -t nat -A POSTROUTING -o $OUT_INTERFACE -j MASQUERADE # Allow PNAT via OUT_INTERFACE
sudo nmcli con up $CONNECTION_NAME # Actually turn on the connection
sudo ip route del default via $MY_IP dev $AP_INTERFACE # Delete the default route for the AP_INTERFACE if it exists
sudo iptables -I OUTPUT -o $AP_INTERFACE -p icmp --icmp-type destination-unreachable -j DROP # Don't send ICMP unreachable answers to devices. This is because Arcane doesn't actually open ports
