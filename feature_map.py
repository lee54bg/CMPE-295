from scapy.all import *
import sys
import json
import datetime
import hashlib
import collections
import threading

counter = 0

list = []

de = deque()
features = dict()


# Printing packet to console
def classify_traffic(packet):
	global counter
	
	# Reinitialize these variables everytime you get a packet
	# This will be used when calculating for features 8 - 13
	# in the Kyoto Dataset
	same_dst = 0
	same_dst_srv = 0

	# 11. Dst host same src port rate
	same_src_port_rate = 0.0

	# Service Types
	svclist = {
		7: 'echo',
		21: 'ftp',
		22: 'ssh',
		23: 'telnet',
		25: 'smtp',
		69: 'tftp',
		80: 'http',
	}

	# total = packet[IP].src + packet[IP].dst
	# hash_object = hashlib.md5(str(total).encode('utf-8'))
	# hash = hash_object.hexdigest()
	
	if IP in packet:
		de.append(packet[IP])
	
		# If the length of the Deque is greater than or equal to 100
		# then start calculating the features
		if len(de) >= 99:
			# print(de.count(packet[IP].dst))

			deq_count = 0

			# Iterate through 100 items of the deque and calculate 
			# the same destination for Kyoto Dataset
			for item in de:
				
				if packet[IP].dst == item.dst:
					same_dst += 1

					# Check for Dst host srv count:
					if TCP in item:
						if item[TCP].dport in svclist:
							same_dst_srv += 1

							# Check for number 11. Dst host same src port rate
							# of the Kyoto Dataset
							if packet[TCP].sport == item[TCP].sport:
								same_src_port_rate += 1

					elif UDP in item:
						if item[UDP].dport in svclist:
							same_dst_srv += 1

							# Check for number 11. Dst host same src port rate
							# of the Kyoto Dataset
							if packet[UDP].sport == item[UDP].sport:
								same_src_port_rate += 1
				if deq_count == 99:
					break
				
				deq_count += 1
			# At the end of the calculations, popped the left item of the deque
			# so that more items can be appended
			de.popleft()
		
		src_port_rate = same_src_port_rate / same_dst
		# Print statistics for 8 - 13
		print("{}, {}".format(same_dst, same_dst_srv))
			
	counter += 1

def basic_function():
	while True:
		input = raw_input("Enter something: ")
		print(input)

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

		sniff(prn=classify_traffic, iface=iface)
		
	except socket.error:
		print("No such device found.")