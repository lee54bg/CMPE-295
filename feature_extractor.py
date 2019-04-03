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
    if uniq not in connections and dup not in connections:
        
        connections[uniq] = [src,   # 1
            dst,            # 2
            0,              # 3
            0,              # 4
            packet.time,    # 5
            len(packet),    # 6
            0,              # 7
            0,              # 8
            -1,             # 9
            0,              # 10
            3,              # 11
            0,              # 12
            0               # 13
        ]          

        if packet[TCP].flags == 'S':
            print('yes')
            connections[uniq][10] -= 1

        if dprt in svclist:
            connections[uniq][7] = svclist[dprt]
        
        for key,value in connections.items():
            
            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and connections[key][4]-packet.time<=2:
                connections[uniq][8] += 1 
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
    
        for key,value in cursvc.items():
            if connections[uniq][8] != 0:
                connections[uniq][9] += (value/connections[uniq][8])*100
        
    elif uniq in connections:
        
        connections[uniq][2] += 1
        connections[uniq][3] += packet.time - connections[uniq][4]
        connections[uniq][4] = packet.time
        connections[uniq][5] += len(packet)
        connections[uniq][8] = -1
        connections[uniq][9] = 0

        if connections[uniq][2] == 2 and  packet[TCP].flags == 'A':
            connections[uniq][10] -= 1

        for key,value in connections.items():
            
            if value[7] not in cursvc:
                cursvc[value[7]] = 1
            else:
                cursvc[value[7]] += 1

            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and connections[key][4]-packet.time<=2:
                connections[uniq][8] += 1

                if value[2] > 2 and value[10] !=0:
                    syncnt +=1
                    if connections[uniq][7] in value[7]:
                        synsvcnt +=1

                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
                
        for key,value in cursvc.items():
            
            if connections[uniq][8] != 0:
                connections[uniq][9] += (value/connections[uniq][8])*100

        if connections[uniq][8] != 0:
            connections[uniq][11] = (syncnt/connections[uniq][8])*100

            connections[uniq][12] = synsvcnt/cursvc[connections[uniq][7]]
      
    elif dup in connections:
    
        connections[dup][2] += 1
        connections[dup][3] += packet.time - connections[dup][4]
        connections[dup][4] = packet.time
        connections[dup][6] += len(packet)
        connections[dup][8] = -1
        connections[dup][9] = 0

        if connections[dup][10] <= 3 and connections[dup][10] >= 0 and packet[TCP].flags == 'SA':
            connections[dup][10] -= 1
        
        for key,value in connections.items():
            
            if dst+src in key[:len(dst)]+key[len(key)-len(src):] and connections[key][4]-packet.time<=2:
                connections[dup][8] += 1
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                
                else:
                    cursvc[value[7]] += 1
               
        for key,value in cursvc.items():
            if connections[dup][8] != 0:
                connections[dup][9] += (value/connections[dup][8])*100


    

#initiate variables
global connections
global act
global archive
global storetime
global cursvc
    
connections = {}
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

print('len',len(connections))
for key, value in connections.items():
        print(key,value)
        
for key, value in archive.items():
        print('new ',key,value)