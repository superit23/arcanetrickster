#!/usr/bin/bash
AP_INTERFACE=wlan1
OUT_INTERFACE=wlan0
CONNECTION_NAME=testhotspot
MY_IP="10.13.37.1"

sudo nmcli con add type wifi ifname $AP_INTERFACE con-name $CONNECTION_NAME autoconnect yes ssid $CONNECTION_NAME
sudo nmcli con modify $CONNECTION_NAME 802-11-wireless.mode ap ipv4.method manual ipv4.addresses $MY_IP/24 ipv4.gateway $MY_IP
sudo nmcli con modify $CONNECTION_NAME wifi-sec.key-mgmt wpa-psk 
sudo nmcli con modify $CONNECTION_NAME wifi-sec.psk "somepassword"

sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o $OUT_INTERFACE -j MASQUERADE
sudo nmcli con $CONNECTION_NAME up
