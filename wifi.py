import sys
import os
from scapy.all import *
import numpy as np
import requests

try:
    import Queue as queue
except ImportError:
    import queue

data_to_send = queue.Queue()

def basic_function():
    print("Rest API Started")
    
    url = 'http://127.0.0.1:5000/api'

    while True:
        if data_to_send.empty():
            continue
        else:
            data = data_to_send.get()

            # Format the data into a list though the data is already in a list
            # data = np.array(data).tolist()
            r = requests.post(url,json={'exp':data})

            print(r.json())

def sniff_80211(packet):
    # Print statements are for debugging purposes
    # print(packet.summary())
    # packet.show()
    
    if Dot11 in packet:
        temp_list = [packet[Dot11].ID, len(packet[Dot11])]
        # print(temp_list)
        data_to_send.put(temp_list)
    elif Dot11FCS in packet:
        temp_list = [packet[Dot11FCS].ID, len(packet[Dot11FCS])]
        # print(temp_list)
        data_to_send.put(temp_list)

iface = sys.argv[1]

if len(sys.argv) == 1:
    print("Usage: python wifi.py {Interface}")
    sys.exit()
else:
    try:
        import threading

        t1 = threading.Thread(target=basic_function)
        t1.start()

        sniff(prn=sniff_80211, iface=iface)

    except KeyboardInterrupt:
        print("\nTerminating Program...")