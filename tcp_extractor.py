from scapy.all import *
import sys
import json


def write_tcp_json(packet):
    if IP in packet and TCP in packet:

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
            11 - Serror rate: % of connections that have "SYN" errors in Count feature
            12 - Srv serror rate: % of connections that have "SYN" errors in Srv count(the
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
            
            print(dic[uniq])
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
                        
                        # if dic[uniq][7] in value[7]:
                        #     synsvcnt +=1

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


# packets = rdpcap('http_witp_jpegs.cap')
# act = packets[0].time
# for packet in packets:
    			
#     if TCP in packet:
# 	    count +=1
# 	    print(count)
# 	    write_tcp_json(packet)

# print('len',len(dic))
# for key, value in dic.items():
#         print(key,value)
#         '''
# for key, value in archive.items():
#         print('new ',key,value)'''

sniff(prn=write_tcp_json, iface="enp0s3")