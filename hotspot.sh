INTERFACE=wlan1 # My wifi card interface
CONNECTION_NAME=testhotspot
MY_IP="10.13.37.1"

sudo nmcli con add type wifi ifname $INTERFACE con-name $CONNECTION_NAME autoconnect yes ssid $CONNECTION_NAME
sudo nmcli con modify $CONNECTION_NAME 802-11-wireless.mode ap ipv4.method manual ipv4.addresses $MY_IP/24 ipv4.gateway $MY_IP
sudo nmcli con modify $CONNECTION_NAME wifi-sec.key-mgmt wpa-psk 
sudo nmcli con modify $CONNECTION_NAME wifi-sec.psk "somepassword"
