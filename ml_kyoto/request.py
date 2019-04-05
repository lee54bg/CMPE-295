from scapy.all import *
import sys
import json
import datetime
import hashlib
import collections
import requests



  
try:
    import Queue as queue
except ImportError:
    import queue

counter = 0

de = deque()
data_to_send = queue.Queue()

features = [
  0,  # 0 Duration
  "", # 1 Service 
  0,  # 2 Source Bytes
  0,  # 3 Destination Bytes
  0,  # 4 Count
  0,  # 5 Same srv rate
  0,  # 6 Serror rate
  0,  # 7 Srv serror rate
  0,  # 8 Dst host count 
  0,  # 9 Dst host srv count
  0,  # 10 Dst host same src port rate
  0,  # 11 Dst host serror rate
  0 # 12 Dst host srv serror rate
]

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
}

def map_stats(packet):
  global counter
  iter_counter = 0

  # Reinitialize these variables everytime you get a packet
  # This will be used when calculating for features of the Kyoto Dataset
  
  count = 0.0
  same_srv_count = 0.0
  same_srv_rate = 0.0

  # Features 9 - 13
  dst_host_count = 0.0
  dst_host_srv_count = 0.0
  dst_host_same_src_port_rate = 0.0
  dst_same_src_port = 0.0

  if IP in packet:
    # Add the packet to the list first before doing any processing
    de.append(packet[IP])

    # Check the type of service and then put it in Features
    # 2) Service
    features[1] = check_service(packet[IP])
    
    # Iterate through all of the items that are currently
    # in the list.
    for item in de:
      # Exit the loop after you encounter your own packet number
      if iter_counter == counter:
        break

      # Check all packets within a 2 second time frame
      if packet.time - item.time <= 2:
        if packet.src == item.src and packet.dst and item.dst:
          count += 1

          if packet.dport == item.dport and packet.dport in svclist:
            same_srv_count += 1
      
      extract_udp_feat(packet)

      if counter - iter_counter <= 100:
        # 9. Dst host count       
        if packet[IP].dst == item.dst:
          if packet[IP].src == item.src:
            dst_host_count += 1

            # Check for Dst host srv count:
            if TCP in packet and TCP in item:
              if packet[TCP].dport in svclist and packet[TCP].dport == item[TCP].dport:
                dst_host_srv_count += 1

              # Check for number 11. Dst host same src port rate
              # of the Kyoto Dataset
              if packet[TCP].sport == item[TCP].sport:
                dst_same_src_port += 1
              
            elif UDP in packet and UDP in item:
              if packet[UDP].dport in svclist and packet[UDP].dport == item[UDP].dport:
                dst_host_srv_count += 1

              # Check for number 11. Dst host same src port rate
              # of the Kyoto Dataset
              if packet[UDP].sport == item[UDP].sport:
                dst_same_src_port += 1

      iter_counter += 1

    if dst_host_count != 0:
      dst_host_same_src_port_rate = dst_same_src_port / dst_host_count

    if count != 0:
      same_srv_rate = same_srv_count / count
    
    # 5 Count
    features[4] = count
    # 6 Count Same Service Rate
    features[5] = same_srv_rate
    # 9 Dst host count
    features[8] = dst_host_count
    # 10 Destination Service Count
    features[9] = dst_host_srv_count
    # 11 Destination Same Source Port Rate
    features[10] = dst_host_same_src_port_rate


    # If the length of the Deque is greater than or equal to 100
    # then start calculating the features
    if len(de) >= 10000:
      # At the end of the calculations, popped the left item of the deque
      # so that more items can be appended
      de.popleft()
    
  # After all the operations are over, increment counter for the next packet
  print(features)
  data_to_send.put(features)

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
      features[2] = len(packet)
      # 7 SYN error rate
      features[6] = 0.0
      # 8 Service SYN error rate
      features[7] = 0.0
    elif dup in udp_connections:
      # 4 Destination Bytes
      features[3] = len(packet)
      # 7 SYN error rate
      features[6] = 0.0
      # 8 Service SYN error rate
      features[7] = 0.0
      
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

    # If this is a new TCP connection, log it in the connection dictionary
    if uniq not in tcp_connections and dup not in tcp_connections:
      # The start of a Unique TCP connection
      tcp_connections[uniq] = [
        src,      # 0 - source IP
        dst,      # 1 - dest IP
        0,        # 2 - packet count
        0,        # 3 - duration
        packet.time,  # 4 - last packet time
        len(packet),  # 5 - Source bytes
        0,        # 6 - Dest bytes
        0,        # 7 - Service Type
        -1,       # 8 - Count
        0,        # 9 - Same srv rate: % of tcp_connections to the same service in Count feature
        3,        # 10 - SYN Error Check
        0,        # 11 - Serror rate: % of tcp_connections that have "SYN" errors in Count feature
        0       # 12 -  Srv serror rate: % of tcp_connections that have "SYN" errors in Srv count(the
                  # number of tcp_connections whose service type is the same to that of the cur-
                  # rent connection in the past two seconds) feature    
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

      for key,value in cursvc.items():
        if tcp_connections[uniq][8] != 0:
          tcp_connections[uniq][9] += (value/tcp_connections[uniq][8])

      # 3 Source Bytes
      features[2] = len(packet)
      
    elif uniq in tcp_connections:
      # Calculate Duration
      tcp_connections[uniq][3] += packet.time - tcp_connections[uniq][4]
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
      
      # 1 Duration
      features[0] = tcp_connections[dup][3]
      # 3 Source Bytes
      features[2] = len(packet)
      
    elif dup in tcp_connections:
      # Calculate the duration of the connection
      tcp_connections[dup][3] += packet.time - tcp_connections[dup][4]

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

      # 1 Duration
      features[0] = tcp_connections[dup][3]
      # 4 Destination Bytes
      features[3] = len(packet)
      
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
    import numpy as np
  
    url = 'http://127.0.0.1:5000/api'

    while True:
        if data_to_send.empty():
            continue
    else:
        data = data_to_send.get()

        data = np.array(data).tolist()
        r = requests.post(url,json={'exp':data})

        print(r.json())

if len(sys.argv) == 1:
    print("Usage: python3 trafclas [Interface]")
    sys.exit()
else:
    # import csv

    # with open('Aggregated Data.csv', mode='w') as kyoto_dataset:
    #   kyoto_writer = csv.writer(kyoto_dataset, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    #   kyoto_writer.writerow(['John Smith', 'Accounting', 'November'])
    #   kyoto_writer.writerow(['Erica Meyers', 'IT', 'March'])

    iface = sys.argv[1]
    print("Interface: " + iface)

    try:
        global start_time
        start_time = time.mktime(datetime.datetime.today().timetuple())

        import threading
  
        t1 = threading.Thread(target=basic_function)
        t1.start()

        sniff(prn=map_stats, iface=iface)

    except socket.error:
        print("No such device found.")
    except KeyboardInterrupt:
        print("\nTerminating Program...")