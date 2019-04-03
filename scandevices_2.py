import sys
from scapy.all import *

devices = set()

def packethandler(packet):
	if packet.haslayer(Dot11):
		dot11_layer = packet.getlayer(Dot11)

		if dot11_layer.addr2 and ( dot11_layer.addr2 not in devices):
			devices.add(dot11_layer.addr2)
			print(len(devices), dot11_layer.addr2, dot11_layer.payload.name)

sniff(iface = sys.argv[1], prn = packethandler)