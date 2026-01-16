sudo pkill dnsmasq
sudo systemctl restart NetworkManager
nmcli connection delete Hotspot 
nmcli device wifi hotspot ifname wlan0 ssid test_root password 12345678
