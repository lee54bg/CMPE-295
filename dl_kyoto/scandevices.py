import sys
from scapy.all import *

devices = set()

wifi_packets = rdpcap('WiFI.pcap')

def wifipackethandler(packet):
	if packet.haslayer(Dot11):
		dot11_layer = packet.getlayer(Dot11)

		if dot11_layer.addr2 and ( dot11_layer.addr2 not in devices):
			devices.add(dot11_layer.addr2)
			print(len(devices), dot11_layer.addr2, dot11_layer.payload.name)

wifipackethandler(wifi_packets)