from scapy.all import *
import sys
import json

counter = 0

def write_dns_json(packet):
	dns = packet[DNS]
	dns_json = dict()
	
	dns_fields = ["length", "id", "qr", 
		"opcode", "aa", "tc", "rd", "ra",
		"z", "ad", "cd", "rcode", "qdcount",
		"ancount", "nscount", "arcount", "ar"]

	for key in dns_fields:
		dns_json[key] = getattr(dns, key)
	
	with open('dns.json', 'a') as fp:
		json.dump(dns_json,fp,indent=2)

def write_icmp_json(packet):
	icmp = packet[ICMP]
	icmp_json = dict()
	
	icmp_fields = ["type","code","chksum","id","seq"]

	for key in icmp_fields:
		icmp_json[key] = getattr(icmp, key)
	
	with open('icmp.json', 'a') as fp:
		json.dump(icmp_json,fp,indent=2)


def write_ip_json(packet):
	ip = packet[IP]
	ip_json = dict()
	
	ip_fields = ["version","ihl","tos","len","id","flags",
				"frag","ttl","proto","chksum","src","dst"]
				
	for key in ip_fields:
		ip_json[key] = getattr(ip, key)
	
	with open('ip.json', 'a') as fp:
		json.dump(ip_json,fp,indent=2)

def write_ether_json(packet):
	ether = packet[Ether]
	ether_json = dict()
	
	ether_fields = ["src","dst","type"]
				
	for key in ether_fields:
		ether_json[key] = getattr(ether, key)
	
	with open('ethernet.json', 'a') as fp:
		json.dump(ether_json,fp,indent=2)
	
def write_tcp_json(packet):
	tcp_json = dict()
	tcp = packet[TCP]
	tcp_fields = ["sport","dport","seq","ack","dataofs","reserved",
				"flags","window","chksum","urgptr"]
	
	for key in tcp_fields:
		tcp_json[key] = getattr(tcp, key)

	with open('tcp.json', 'a') as fp:
		json.dump(tcp_json,fp,indent=2)

def write_udp_json(packet):
	udp_json = dict()
	udp = packet[UDP]
	udp_fields = ["sport","dport","len","chksum"]
	
	for key in udp_fields:
		udp_json[key] = getattr(udp, key)

	with open('udp.json', 'a') as fp:
		json.dump(udp_json,fp,indent=2)

def write_arp_json(packet):
	arp = packet[ARP]
	arp_json = dict()
	
	arp_fields = ["hwtype","ptype","hwlen","plen","op","hwsrc",
				"psrc","hwdst","pdst"]
				
	for key in arp_fields:
		arp_json[key] = getattr(arp, key)
	
	with open('arp.json', 'a') as fp:
		json.dump(arp_json,fp,indent=2)

## Printing packet to console
def classify_traffic(packet):
	global counter
	#print(packet.show())
	if DNS in packet:
		write_dns_json(packet)
		print("#" + str(counter) + " DNS")
		
	## Check UDP
	elif UDP in packet:
		write_udp_json(packet)
		print("#" + str(counter) + " UDP")
		
	## Check TCP
	elif TCP in packet:
		write_tcp_json(packet)
		print("#" + str(counter) + " TCP")
		
	elif ICMP in packet:
		write_icmp_json(packet)
		print("#" + str(counter) + " ICMP")

	## Check ARP
	elif ARP in packet:
		write_arp_json(packet)
		print("#" + str(counter) + " ARP")
	
	elif Ether in packet:
		write_ether_json(packet)
		print("#" + str(counter) + " Ether")
	
	counter += 1

'''
if len(sys.argv) == 1:
	print("Usage: python3 trafclas [Interface]")
	sys.exit()
else:
	iface = sys.argv[1]
	print("Interface: " + iface)
'''
## Sniff General Traffic
sniff(prn=classify_traffic, iface="eth0")
