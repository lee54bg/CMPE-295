import time
from scapy.all import *

start_time = time.time()

#while True:
    # if time.time() - start_time >= 2:
    # #if time.time() - start_time > 59:
    #     print("it's been a minute")
    #     break

def collect_stats(packet):
    print(packet.time)

try:
    sniff(prn=collect_stats, iface="enp0s3")
except AttributeError:
    print("No such device found.  Please try again\n")