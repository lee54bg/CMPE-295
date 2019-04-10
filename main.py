from scapy.all import *
import sys
import json
import csv
import os
import udp_module
import requests

try:
    import Queue as queue
except ImportError:
    import queue

data_to_send = queue.Queue()

def basic_function():
    print("Rest API Started")
    
    service = ['other', 'ssh', 'dns', 'rdp', 'smtp', 'snmp', 'http', 'smtp,ssl', 'ssl', 'sip']
    protocol = ["icmp", "tcp", "udp"]

    import numpy as np
  
    url = 'http://127.0.0.1:5000/api'

    while True:
        if data_to_send.empty():
            continue
        else:
            data = data_to_send.get()

            # print(len(data))
            # print(data)

            srv = data[1]
            prt = data[13]

            del data[1]
            del data[12]

            service_to_int = dict((c, i) for i, c in enumerate(service))
            protocols_to_int = dict((c, i) for i, c in enumerate(protocol))

            integer_encoded_service = service_to_int[srv]
            integer_encoded_protocol = protocols_to_int[prt]

            encoded_service = [0 for _ in range(len(service))]
            encoded_service[integer_encoded_service] = 1

            encoded_protocol = [0 for _ in range(len(protocol))]
            encoded_protocol[integer_encoded_protocol] = 1

            encoded_service.extend(encoded_protocol)
            data.extend(encoded_service)

            # print(len(data))
            # print(data)

            # Format the data into a list though the data is already in a list
            # data = np.array(data).tolist()
            r = requests.post(url,json={'exp':data})

            print(r.json())


def map_stats(writer):
    def packet_explore(packet):
        if IP in packet:            
            if TCP in packet:
                    write_tcp_json(packet,writer)
            elif UDP in packet:
                    udp_module.write_udp_json(packet,writer)

    return packet_explore


global svclist

svclist = {
    7: 'echo',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    69: 'tftp',
    80: 'http',
    # 443: 'https',
    53: 'dns'
}

def write_tcp_json(packet,writer):
    src = packet[IP].src
    dst = packet[IP].dst
    sprt = packet[TCP].sport
    dprt = packet[TCP].dport
    
    # unique connection = sourceIP+SourcePort+DestinationIP
    uniq = src+':'+str(sprt)+':'+dst
    dup = dst+':'+str(dprt)+':'+src
    
    global temp
    global cursvc
    cursvc = {}
    oldkey = ''
    cnt = 0
    syncnt = 0
    synsvcnt = 0
    srcport_count = 0
    syn_error_count = 0
    srv_syn_error_count = 0
    
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
        dic[uniq] = [src,dst,0,0,packet.time,len(packet),0,0,-1,0,3,0,0,0,0,0,0,0,'tcp']

        # SYN error calculation
        if packet[TCP].flags == 'S':
            dic[uniq][10] -= 1

        #identify service types
        if dprt in svclist:
            dic[uniq][7] = svclist[dprt]
        else:
            svclist[dprt] = 'other'
            dic[uniq][7] = 'other'
        
        # calculte offset and length of dic
        len_dic = len(dic)
        offset = len(dic) - 100


        #loop through unique conections
        for key,value in dic.items():
            
            #set offset to 0
            if offset > 0:
                offset -= 1
            #track first hundred connections 
            elif offset <= 0:   
                #check for src connections for top 100 connections
                if value[1] == dst:
                    #src connections for top 100 connections
                    if value[0] == src:
                        dic[uniq][13] += 1
                        #compare with the src port
                        start = key.find(':')+1
                        end = key[start:].find(':')+start
                        if sprt == int(key[start:end]):
                            srcport_count +=1
                        #calculate SYN error
                        if value[2] > 2 and value[10] !=0:
                            syn_error_count +=1

                    #svc connections for top 100 connections
                    if packet.dport in svclist:
                        if value[7] == svclist[packet.dport]:
                            dic[uniq][14] += 1
                            #SYN error for same service
                            if value[2] > 2 and value[10] !=0:
                                srv_syn_error_count +=1 

            #check for two second limit
            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                #Count feature
                dic[uniq][8] += 1 
                #Serror rate: calculte SYN error
                if value[2] > 2 and value[10] !=0:
                    syncnt +=1
                    if dic[uniq][7] in value[7]:
                        synsvcnt +=1
                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1

        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])
        #Serror rate: calculte SYN error
        if dic[uniq][8] != 0:
            dic[uniq][11] = (syncnt/dic[uniq][8])

        #Srv serror rate: Same service SYN error
        if cursvc[dic[uniq][7]] !=0:
            dic[uniq][12] = synsvcnt/cursvc[dic[uniq][7]]
        # Dst host same src port rate
        if dic[uniq][13]!=0:
            dic[uniq][15] = (srcport_count/dic[uniq][13])
            #SYN error calculation
            dic[uniq][16] = (syn_error_count/dic[uniq][13])
        
        #Dst host srv serror rate
        if dic[uniq][14]!=0:
            dic[uniq][17] = (srv_syn_error_count/dic[uniq][14])
        
        temp_list = [dic[uniq][3],dic[uniq][7],dic[uniq][5],dic[uniq][6],dic[uniq][8],dic[uniq][9],dic[uniq][11],
        dic[uniq][12],dic[uniq][13],dic[uniq][14],dic[uniq][15],dic[uniq][16],dic[uniq][17],dic[uniq][18]]

        writer.writerow(temp_list)


    elif uniq in dic:
        
        #packet count
        dic[uniq][2] += 1
        #duration
        dic[uniq][3] += packet.time - dic[uniq][4]
        #last packet time
        dic[uniq][4] = packet.time
        #Source bytes
        dic[uniq][5] += len(packet)
        #Count feature init
        dic[uniq][8] = -1
        #Same srv rate init
        dic[uniq][9] = 0

        dic[uniq][13] = 0
        dic[uniq][14] = 0

        # SYN error calculation
        if dic[uniq][2] == 2 and  packet[TCP].flags == 'A':
            dic[uniq][10] -= 1

        # calculte offset and length of dic
        len_dic = len(dic)
        offset = len(dic) - 100

        #loop through unique conections
        for key,value in dic.items():
            
            #set offset to 0
            if offset > 0:
                offset -= 1
            #track first hundred connections 
            elif offset <= 0:   
                #check for src connections for top 100 connections
                if value[1] == dst:
                    #src connections for top 100 connections
                    if value[0] == src:
                        dic[uniq][13] += 1
                        #compare with the src port
                        start = key.find(':')+1
                        end = key[start:].find(':')+start
                        if sprt == int(key[start:end]):
                            srcport_count +=1
                        #calculate SYN error
                        if value[2] > 2 and value[10] !=0:
                            syn_error_count +=1

                    #svc connections for top 100 connections
                    if packet.dport in svclist:
                        if value[7] in svclist[packet.dport]:
                            dic[uniq][14] += 1
                            #SYN error for same service
                            if value[2] > 2 and value[10] !=0:
                                srv_syn_error_count +=1 

            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                dic[uniq][8] += 1

                #Serror rate: calculte SYN error
                if value[2] > 2 and value[10] !=0:
                    syncnt +=1
                    if dic[uniq][7] in value[7]:
                        synsvcnt +=1

                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
        
        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])

        #Serror rate: calculte SYN error
        if dic[uniq][8] != 0:
            dic[uniq][11] = (syncnt/dic[uniq][8])

        #Srv serror rate: Same service SYN error
        if cursvc[dic[uniq][7]] !=0:
            dic[uniq][12] = synsvcnt/cursvc[dic[uniq][7]]
        
        # Dst host same src port rate
        if dic[uniq][13]!=0:
            dic[uniq][15] = (srcport_count/dic[uniq][13])
            #SYN error calculation
            dic[uniq][16] = (syn_error_count/dic[uniq][13])
        #Dst host srv serror rate
        if dic[uniq][14]!=0:
            dic[uniq][17] = (srv_syn_error_count/dic[uniq][14])
    
        temp_list = [dic[uniq][3],dic[uniq][7],dic[uniq][5],dic[uniq][6],dic[uniq][8],dic[uniq][9],dic[uniq][11],
        dic[uniq][12],dic[uniq][13],dic[uniq][14],dic[uniq][15],dic[uniq][16],dic[uniq][17],dic[uniq][18]]

        writer.writerow(temp_list)
      
    elif dup in dic:
        
        #packet count
        dic[dup][2] += 1
        #duration
        dic[dup][3] += packet.time - dic[dup][4]
        #last packet time
        dic[dup][4] = packet.time
        #Dest bytes
        dic[dup][6] += len(packet)
        #Count feature init
        dic[dup][8] = -1
        #Same srv rate init
        dic[dup][9] = 0
        dic[dup][13] = 0
        dic[dup][14] = 0

        # SYN error calculation
        if dic[dup][10] <= 3 and dic[dup][10] >= 0 and packet[TCP].flags == 'SA':
            dic[dup][10] -= 1
        
        # calculte offset and length of dic
        len_dic = len(dic)
        offset = len(dic) - 100
        
        #loop through unique conections
        for key,value in dic.items():

            #set offset to 0
            if offset > 0:
                offset -= 1
            #track first hundred connections 
            elif offset <= 0: 
                  
                #check for src connections for top 100 connections
                if value[0] == dst:
                    #src connections for top 100 connections
                     
                    if value[1] == src:
                        dic[dup][13] += 1
                        #compare with the src port
                        start = key.find(':')+1
                        end = key[start:].find(':')+start
                        if sprt == int(key[start:end]):
                            srcport_count +=1 
                        #calculate SYN error
                        if value[2] > 2 and value[10] !=0:
                            syn_error_count +=1
                    #svc connections for top 100 connections
                    if packet.sport in svclist:
                        if value[7] in svclist[packet.sport]:
                            dic[dup][14] += 1
                            #SYN error for same service
                            if value[2] > 2 and value[10] !=0:
                                srv_syn_error_count +=1 
                      
            
            if dst+src in key[:len(dst)]+key[len(key)-len(src):] and dic[key][4]-packet.time<=2:
                dic[dup][8] += 1

                #Serror rate: calculte SYN error
                if value[2] > 2 and value[10] !=0:
                    syncnt +=1
                    if dic[dup][7] in value[7]:
                        synsvcnt +=1
                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
        
        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[dup][8] != 0:
                dic[dup][9] += (value/dic[dup][8])
        #Serror rate: calculte SYN error
        if dic[dup][8] != 0:
            dic[dup][11] = (syncnt/dic[dup][8])

        #Srv serror rate: Same service SYN error
        if cursvc[dic[dup][7]] !=0:
            dic[dup][12] = synsvcnt/cursvc[dic[dup][7]]
        # Dst host same src port rate
        if dic[dup][13]!=0:
            dic[dup][15] = (srcport_count/dic[dup][13])
            #SYN error calculation
            dic[dup][16] = (syn_error_count/dic[dup][13])
        #Dst host srv serror rate
        if dic[dup][14]!=0:
            dic[dup][17] = (srv_syn_error_count/dic[dup][14])
        
        temp_list = [dic[dup][3],dic[dup][7],dic[dup][5],dic[dup][6],dic[dup][8],dic[dup][9],dic[dup][11],
        dic[dup][12],dic[dup][13],dic[dup][14],dic[dup][15],dic[dup][16],dic[dup][17],dic[dup][18]]

        # print(temp_list)
        data_to_send.put(temp_list)

        writer.writerow(temp_list)
    

#initiate variables
global dic
global cursvc

dic = {}
    
iface = sys.argv[1]
if len(sys.argv) == 1:
	print("Usage: python main [Interface]")
	sys.exit()
else:
    with open('kyoto_data.csv', mode='a') as csv_file:
        writer = csv.writer(csv_file)

        if os.stat("kyoto_data.csv").st_size == 0:
            writer.writerow(('Duration','Service','Source bytes','Destination bytes','Count','Same srv rate','Serror rate','Srv serror rate','Dst host count','Dst host srv count','Dst host same src port rate','Dst host serror rate','Dst host srv serror rate','Protocol'))
        try:
            import threading
  
            t1 = threading.Thread(target=basic_function)
            t1.start()

            sniff(prn=map_stats(writer), iface=iface)
        except socket.error:
            print("No such device found.")
        except KeyboardInterrupt:
		    print("\nTerminating Program...")