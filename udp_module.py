from scapy.all import *
import sys
import json
import os
import csv

try:
    import Queue as queue
except ImportError:
    import queue

#initiate variables
global dic
global cursvc
global svclist
    
dic = {}

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

def write_udp_json(packet,writer):
    src = packet[IP].src
    dst = packet[IP].dst
    sprt = packet[UDP].sport
    dprt = packet[UDP].dport

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
    srcport_count=0
    
    # check for unique connections
    if uniq not in dic and dup not in dic:
       
        dic[uniq] = [src,dst,0,0,packet.time,len(packet),0,0,-1,0,0,0,0,0,0,0,0,0,'udp']

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

                    #svc connections for top 100 connections
                    if packet.dport in svclist:
                        if value[7] == svclist[packet.dport]:
                            dic[uniq][14] += 1


            #check for two second limit
            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                #Count feature
                dic[uniq][8] += 1 
                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1

        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])
        # Dst host same src port rate
        if dic[uniq][13]!=0:
            dic[uniq][15] = (srcport_count/dic[uniq][13])
        
        temp_list = [dic[uniq][3],dic[uniq][7],dic[uniq][5],dic[uniq][6],dic[uniq][8],dic[uniq][9],0,0,dic[uniq][13],dic[uniq][14],dic[uniq][15],0,0,dic[uniq][18]]
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
                        
                    #svc connections for top 100 connections
                    if packet.dport in svclist:
                        if value[7] == svclist[packet.dport]:
                            dic[uniq][14] += 1
                       
            if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-packet.time<=2:
                dic[uniq][8] += 1
                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
        
        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[uniq][8] != 0:
                dic[uniq][9] += (value/dic[uniq][8])

        # Dst host same src port rate
        if dic[uniq][13]!=0:
            dic[uniq][15] = (srcport_count/dic[uniq][13])
        
        temp_list = [dic[uniq][3],dic[uniq][7],dic[uniq][5],dic[uniq][6],dic[uniq][8],dic[uniq][9],0,0,dic[uniq][13],dic[uniq][14],dic[uniq][15],0,0,dic[uniq][18]]
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
                        
                    #svc connections for top 100 connections
                    if packet.sport in svclist:
                        if value[7] == svclist[packet.sport]:
                            dic[dup][14] += 1
                        
            
            if dst+src in key[:len(dst)]+key[len(key)-len(src):] and dic[key][4]-packet.time<=2:
                dic[dup][8] += 1
                #Same srv rate calculate same service
                if value[7] not in cursvc:
                    cursvc[value[7]] = 1
                else:
                    cursvc[value[7]] += 1
        
        #same srv rate final calculation
        for key,value in cursvc.items():
            if dic[dup][8] != 0:
                dic[dup][9] += (value/dic[dup][8])
        # Dst host same src port rate
        if dic[dup][13]!=0:
            dic[dup][15] = (srcport_count/dic[dup][13])
        
        temp_list = [dic[dup][3],dic[dup][7],dic[dup][5],dic[dup][6],dic[dup][8],dic[dup][9],0,0,dic[dup][13],dic[dup][14],dic[dup][15],0,0,dic[dup][18]]
        writer.writerow(temp_list)