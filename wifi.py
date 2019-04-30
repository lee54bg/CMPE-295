import sys
import os
from scapy.all import *

iface = sys.argv[1]

def sniff_80211(packet):
    packet.show()
    # if Dot11 in packet:
    #     print("True")

if len(sys.argv) == 1:
    print("Usage: python wifi.py {Interface}")
    sys.exit()
else:
    try:
        sniff(prn=sniff_80211, iface=iface)
    
    except KeyboardInterrupt:
        print("\nTerminating Program...")

# packets = rdpcap("wifi.pcap")

# for packet in packets:
# 	# packet[Dot11Elt].info
# 	# if packet.haslayer(RadioTap):
# 	# 	try:
# 	# 		print("Radio Tap: {}".format(packet[RadioTap].Flags))
# 	# 	except:
# 	# 		print("Error")
# 	if packet.haslayer(Dot11):
# 		# print("Subtype:  {}".format(packet[Dot11].subtype))
# 		fcfield = packet[Dot11].FCfield
# 		print(format(fcfield, '08b'))
		
# 		# print("Flags:  {}".format(packet[Dot11].FCfield))
# 		# print("Duration:  {}".format(packet[Dot11].ID))
# 		# print("Length:  {}".format(len(packet[Dot11])))