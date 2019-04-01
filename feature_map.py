from scapy.all import *
import sys
import json
import datetime
import hashlib
import collections
import threading

counter = 0

de = deque()

features = {
	"Duration": 0,
	"Service": "",
	"Source Bytes": 0,
	"Destination Bytes": 0,
	"Count": 0,
	"Same srv rate": 0,
	"Serror rate": 0,
	"Srv serror rate": 0,
	"Dst host count": 0,
	"Dst host srv count": 0,
	"Dst host same src port rate": 0,
	"Dst host serror rate": 0,
	"Dst host srv serror rate": 0
}

tcp_connections = {}
udp_connections = {}

# Service Types
svclist = {
	7: 'echo',
	21: 'ftp',
	22: 'ssh',
	23: 'telnet',
	25: 'smtp',
	69: 'tftp',
	80: 'http',
	443: 'https'
}

def map_stats(packet):
	global counter

	# Reinitialize these variables everytime you get a packet
	# This will be used when calculating for features 8 - 13
	# in the Kyoto Dataset
	same_dst = 0.0
	same_dst_srv = 0.0

	# 11. Dst host same src port rate
	dst_same_src_port = 0.0

	if IP in packet:
		de.append(packet[IP])
		
		# 2 Service
		features["Service"] = check_service(packet[IP])

		# If the length of the Deque is greater than or equal to 100
		# then start calculating the features
		if len(de) >= 100:
			deq_count = 0

			# Iterate through 100 items of the deque and calculate 
			# the same destination for Kyoto Dataset
			for item in de:

				# 9. Dst host count				
				if packet[IP].dst == item.dst:
					if packet[IP].src == item.src:
						same_dst += 1

						# Check for Dst host srv count:
						if TCP in packet and TCP in item:
							if packet[TCP].dport in svclist and packet[TCP].dport == item[TCP].dport:
								same_dst_srv += 1

							# Check for number 11. Dst host same src port rate
							# of the Kyoto Dataset
							if packet[TCP].sport == item[TCP].sport:
								dst_same_src_port += 1

							
						elif UDP in packet and UDP in item:
							if packet[UDP].dport in svclist and packet[UDP].dport == item[UDP].dport:
								same_dst_srv += 1

							# Check for number 11. Dst host same src port rate
							# of the Kyoto Dataset
							if packet[UDP].sport == item[UDP].sport:
								dst_same_src_port += 1

				if deq_count == 99:
					break
				
				deq_count += 1

			# At the end of the calculations, popped the left item of the deque
			# so that more items can be appended
			de.popleft()
		
		src_port_rate = 0.0

		if same_dst != 0:
			src_port_rate = dst_same_src_port / same_dst

		print("{}, {}, Same src port: {}".format(same_dst, same_dst_srv, src_port_rate))
	counter += 1

def extract_udp_feat(packet):
	if UDP in packet:
		src = packet[IP].src
		dst = packet[IP].dst
		sprt = packet[UDP].sport
		dprt = packet[UDP].dport

		uniq = src+':'+str(sprt)+':'+dst
		dup = dst+':'+str(dprt)+':'+src

		if uniq not in udp_connections and dup not in udp_connections:
			# 3 Source Bytes
			features["Source Bytes"] = len(packet)
		elif dup in udp_connections:
			# 4 Destination Bytes
			features["Destination Bytes"] = len(packet)

def extract_tcp_feat(packet):
	if TCP in packet:
		# TCP Flags
		flags = {
			'F': 'FIN',
			'S': 'SYN',
			'R': 'RST',
			'P': 'PSH',
			'A': 'ACK',
			'U': 'URG',
			'E': 'ECE',
			'C': 'CWR',
		}

		# Set the IP addresses and ports
		# to variables
		src = packet[IP].src
		dst = packet[IP].dst
		sprt = packet[TCP].sport
		dprt = packet[TCP].dport

		# Used to specify the unique connection
		uniq = src + ':' + str(sprt) + ':' + dst
		dup = dst + ':' + str(dprt) + ':' + src

		global cursvc
		cursvc = {}
		syncnt = 0
		synsvcnt = 0

		"""
	    Dictionary with elemets:
	        0 - source IP
	        1 - dest IP
	        2 - packet count
	        3 - duration
	        4 - last packet time
	        5 - Source bytes
	        6 - Dest bytes
	        7 - service type
	        8 - Count: the number of tcp_connections whose source IP address and destination IP address are the same 
	            to those of the current connection in the past two seconds
	        9 - Same srv rate: % of tcp_connections to the same service in Count feature
	        10 - SYN Error Check
	        11 - Serror rate: % of tcp_connections that have "SYN" errors in Count feature
	        12 - Srv serror rate: % of tcp_connections that have "SYN" errors in Srv count(the
	             number of tcp_connections whose service type is the same to that of the cur-
	             rent connection in the past two seconds) feature    
		"""

		# If this is a new TCP connection, log it in the connection dictionary
		if uniq not in tcp_connections and dup not in tcp_connections:
			tcp_connections[uniq] = [
				src,			# 0
				dst,			# 1
				0,				# 2
				0,				# 3
				packet.time,	# 4
				len(packet),	# 5
				0,				# 6
				0,				# 7
				-1,				# 8
				0,				# 9
				3,				# 10
				0,				# 11
				0				# 12
			]

			# Decrements the value 3 to signify that a TCP connection is being established
			if packet[TCP].flags == 'S':
				tcp_connections[uniq][10] -= 1

			# Check service
			if dprt in svclist:
				tcp_connections[uniq][7] = svclist[dprt]

			# Iterate through all of the entries that have been added in the dictionary
			for key,value in tcp_connections.items():
				# Calculate the number of TCP connections that have the same connection
				if src + dst in key[:len(src)] + key[len(key) - len(dst):] and tcp_connections[key][4] - packet.time <= 2:
					tcp_connections[uniq][8] += 1 

					if value[7] not in cursvc:
						cursvc[value[7]] = 1
					else:
						cursvc[value[7]] += 1

			for key,value in cursvc.items():
				if tcp_connections[uniq][8] != 0:
					tcp_connections[uniq][9] += (value/tcp_connections[uniq][8])

			print(tcp_connections[uniq])

		elif uniq in tcp_connections:
			# Duration
			tcp_connections[uniq][3] += packet.time - tcp_connections[uniq][4]
			# Last Packet count
			tcp_connections[uniq][4] = packet.time
			# Size of packet
			tcp_connections[uniq][5] += len(packet)
			
			tcp_connections[uniq][8] = -1
			
			tcp_connections[uniq][9] = 0

			# Decrease the value 
			if tcp_connections[uniq][2] == 2 and  packet[TCP].flags == 'A':
				tcp_connections[uniq][10] -= 1

			for key,value in tcp_connections.items():
				if value[7] not in cursvc:
					cursvc[value[7]] = 1
				else:
					cursvc[value[7]] += 1
				
				if src+dst in key[:len(src)]+key[len(key)-len(dst):] and tcp_connections[key][4] - packet.time <=2:
					tcp_connections[uniq][8] += 1

					if value[2] > 2 and value[10] != 0:
						syncnt +=1

						# if tcp_connections[uniq][7] in value[7]:
						# 	synsvcnt +=1

					if value[7] not in cursvc:
						cursvc[value[7]] = 1
					else:
						cursvc[value[7]] += 1

			for key,value in cursvc.items():
				if tcp_connections[uniq][8] != 0:
					tcp_connections[uniq][9] += (value / tcp_connections[uniq][8])
			if tcp_connections[uniq][8] != 0:
				tcp_connections[uniq][11] = (syncnt / tcp_connections[uniq][8])
				tcp_connections[uniq][12] = synsvcnt / cursvc[tcp_connections[uniq][7]]
		  
		elif dup in tcp_connections:
			# Calculate the duration of the connection
			tcp_connections[dup][3] += packet.time - tcp_connections[dup][4]

			# 4 Destination Bytes
			features["Destination Bytes"] = len(packet)
			
			# 5 Duration
			features["Duration"] = tcp_connections[dup][3]
			
			# tcp_connections[dup][8] = -1
			tcp_connections[dup][9] = 0

			if tcp_connections[dup][10] <= 3 and tcp_connections[dup][10] >= 0 and packet[TCP].flags == 'SA':
				tcp_connections[dup][10] -= 1

			for key,value in tcp_connections.items():
				if dst+src in key[:len(dst)]+key[len(key)-len(src):] and tcp_connections[key][4] - packet.time <= 2:
					tcp_connections[dup][8] += 1

					if value[7] not in cursvc:
						cursvc[value[7]] = 1
					else:
						cursvc[value[7]] += 1

			for key,value in cursvc.items():
				if tcp_connections[dup][8] != 0:
					tcp_connections[dup][9] += (value / tcp_connections[dup][8])

# This function is used to check the type of service
# that the packet belongs to.  This is checked in the 
# svclist dictionary.  As time goes by, more data can be added
# to check and support which types of services are available
def check_service(packet):
	if TCP in packet:
		if packet[TCP].dport in svclist:
			return svclist[packet[TCP].dport]
		else:
			return "Other"
	
	elif UDP in packet:
		if packet[UDP].dport in svclist:
			return svclist[packet[UDP].dport]
		else:
			return "Other"


def basic_function():
	print("")

if len(sys.argv) == 1:
	print("Usage: python3 trafclas [Interface]")
	sys.exit()
else:
	iface = sys.argv[1]
	print("Interface: " + iface)

	try:
		global start_time
		start_time = time.mktime(datetime.datetime.today().timetuple())

		t1 = threading.Thread(target=basic_function)
		t1.start()

		sniff(prn=map_stats, iface=iface)

	except socket.error:
		print("No such device found.")
	except KeyboardInterrupt:
		print("\nTerminating Program...")