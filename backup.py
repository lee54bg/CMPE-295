from scapy.all import *
import sys
import json


def write_tcp_json(packet):

    src = packet[IP].src
    dst = packet[IP].dst
    sprt = packet[TCP].sport
    dprt = packet[TCP].dport

    #unique connection = sourceIP+SourcePort+DestinationIP
    uniq = src+':'+str(sprt)+':'+dst
    dup = dst+':'+str(dprt)+':'+src
    
    global temp
    global cursvc
    cursvc = {}
    oldkey=''
    cnt=0
    syncnt=0
    synsvcnt=0

    #Service Types
    svclist = {
    7: 'echo',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    69: 'tftp',
    80: 'http',
    }

    #TCP Flags
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
    
    #check for unique connections
    if uniq not in dic and dup not in dic:
        '''Dictionary with elemets:
        0 - source IP
        1 - dest IP
        2 - packet count
        3 - duration
        4 - last packet time
        5 - Source bytes
        6 - Dest bytes
        7 - service type
        8 - Count: the number of connections whose source IP address and destination IP address are the same 
            to those of the current connection in the past two seconds
        9 - Same srv rate: % of connections to the same service in Count feature
        10 - SYN Error Check
        11 - Serror rate: % of connections that have “SYN” errors in Count feature
        12 - Srv serror rate: % of connections that have “SYN” errors in Srv count(the
             number of connections whose service type is the same to that of the cur-
             rent connection in the past two seconds) feature    
        '''
       
        dic[uniq] = [src,dst,0,0,packet.time,len(packet),0,0,-1,0,3,0,0]

        if packet[TCP].flags == 'S':
            print('yes')
            dic[uniq][10] -= 1

        if dprt in svclist:
            dic[uniq][7] = svclist[dprt]
        
        for key,value in dic.items():
            
            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                dic[uniq][8] += 1 
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
    
        for key,value in cursvc.items():
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])*100
        
    elif uniq in dic:
        
        dic[uniq][2] += 1
        dic[uniq][3] += packet.time - dic[uniq][4]
        dic[uniq][4] = packet.time
        dic[uniq][5] += len(packet)
        dic[uniq][8] = -1
        dic[uniq][9] = 0

        if dic[uniq][2] == 2 and  packet[TCP].flags == 'A':
            dic[uniq][10] -= 1

        for key,value in dic.items():
            
            if value[7] not in cursvc:
                cursvc[value[7]] = 1
            else:
                cursvc[value[7]] += 1

            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                dic[uniq][8] += 1

                if value[2] > 2 and value[10] !=0:
                    syncnt +=1
                    if dic[uniq][7] in value[7]:
                        synsvcnt +=1

                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
                
        for key,value in cursvc.items():
            
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])*100

        if dic[uniq][8] != 0:
            dic[uniq][11] = (syncnt/dic[uniq][8])*100

            dic[uniq][12] = synsvcnt/cursvc[dic[uniq][7]]
      
    elif dup in dic:
    
        dic[dup][2] += 1
        dic[dup][3] += packet.time - dic[dup][4]
        dic[dup][4] = packet.time
        dic[dup][6] += len(packet)
        dic[dup][8] = -1
        dic[dup][9] = 0

        if dic[dup][10] <= 3 and dic[dup][10] >= 0 and packet[TCP].flags == 'SA':
            dic[dup][10] -= 1
        
        for key,value in dic.items():
            
            if dst+src in key[:len(dst)]+key[len(key)-len(src):] and dic[key][4]-packet.time<=2:
                dic[dup][8] += 1
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                
                else:
                    cursvc[value[7]] += 1
               
        for key,value in cursvc.items():
            if dic[dup][8] != 0:
                dic[dup][9] += (value/dic[dup][8])*100

    

#initiate variables
global dic
global act
global archive
global storetime
global cursvc
    
dic = {}
archive = {}
storetime ={}
count=0

packets = rdpcap('http_witp_jpegs.cap')
act = packets[0].time
for packet in packets:
    			
    if TCP in packet:
	    count +=1
	    print(count)
	    write_tcp_json(packet)

print('len',len(dic))
for key, value in dic.items():
        print(key,value)
        '''
for key, value in archive.items():
        print('new ',key,value)'''



from scapy.all import *
import sys
import json
import datetime

counter = 0

def write_icmp_json(packet):

	write_ip_json(packet)
	icmp = packet[ICMP]
	icmp_json = dict()
	
	icmp_fields = ["type","code","chksum","id","seq"]

	for key in icmp_fields:
		icmp_json[key] = getattr(icmp, key)
	
	with open('icmp.json', 'a') as fp:
		json.dump(icmp_json,fp,indent=2)


def write_ip_json(packet):
	#write_ether_json(packet)

	ip = packet[IP]
	ip_json = dict()
	
	ip_fields = ["version","ihl","tos","len","id","flags",
				"frag","ttl","proto","chksum","src","dst"]
				
	for key in ip_fields:
		ip_json[key] = getattr(ip, key)
	
	with open('ip.json', 'a') as fp:
		json.dump(ip_json, fp, indent=2)

def write_ether_json(packet):
	ether = packet[Ether]
	ether_json = dict()
	
	ether_fields = ["src","dst","type"]
				
	for key in ether_fields:
		ether_json[key] = getattr(ether, key)
	
	with open('ethernet.json', 'a') as fp:
		json.dump(ether_json,fp,indent=2)
	
def write_tcp_json(packet):

	#write_ip_json(packet)

	tcp_json = dict()
	tcp = packet[TCP]
	tcp_fields = ["sport","dport","seq","ack","dataofs","reserved",
				"flags","window","chksum","urgptr"]
	
	for key in tcp_fields:
		tcp_json[key] = getattr(tcp, key)

	with open('tcp.json', 'a') as fp:
		json.dump(tcp_json,fp,indent=2)

def write_udp_json(packet):
	
	#write_ip_json(packet)

	udp_json = dict()
	udp = packet[UDP]
	udp_fields = ["sport","dport","len","chksum"]
	
	for key in udp_fields:
		udp_json[key] = getattr(udp, key)

	with open('udp.json', 'a') as fp:
		json.dump(udp_json,fp,indent=2)

def write_arp_json(packet):
	#write_ether_json(packet)
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
	print(packet.time - start_time)

	# ## Check UDP
	# if UDP in packet:
	# 	write_udp_json(packet)
	# 	print("#" + str(counter) + " UDP")
		
	# ## Check TCP
	# elif TCP in packet:
	# 	write_tcp_json(packet)
	# 	print("#" + str(counter) + " TCP")

	# # Check ICMP	
	# elif ICMP in packet:
	# 	write_icmp_json(packet)
	# 	print("#" + str(counter) + " ICMP")

	# ## Check ARP
	# elif ARP in packet:
	# 	write_arp_json(packet)
	# 	print("#" + str(counter) + " ARP")
		
	counter += 1

if len(sys.argv) == 1:
	print("Usage: python3 trafclas [Interface]")
	sys.exit()
else:
	iface = sys.argv[1]
	print("Interface: " + iface)
try:
	global start_time
	start_time = time.mktime(datetime.datetime.today().timetuple())

	sniff(prn=classify_traffic, iface=iface)
except socket.error:
	print("No such device found.")