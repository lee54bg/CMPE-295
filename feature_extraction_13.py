# Author: Brandon Lee Gaerlan
# CMPE 295B Master's Project
# Description:  Feature Extraction for packets

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
from random import randint
from random import seed
from kafka import KafkaProducer
import json
from json import dumps

import numpy as np
import requests

try:
    import Queue as queue
except ImportError:
    import queue

# Global variables declared
global dic
global cursvc
global svclist
global temp
global flags
global counter

dic = {}
udp_connections = {}

server_list = []

svclist = {
    7: 'echo',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    69: 'tftp',
    80: 'http',
    53: 'dns'
}

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

service = ['other', 'ssh', 'dns', 'rdp', 'smtp', 'snmp', 'http', 'smtp,ssl', 'ssl', 'sip']
protocol = ["icmp", "tcp", "udp"]

event_queue = queue.Queue()

class FeatureExtraction13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        
    def __init__(self, *args, **kwargs):
        super(FeatureExtraction13, self).__init__(*args, **kwargs)
        self.datapath = None
        self.datapaths = {}
        self.mac_to_port = {}
        self.counter = 0
        self.results = {}
        # Threads for extracting and processing packets, collecting
        # flow rule and port statistics, along with installing 
        # flow entries
        self.extract_thread = hub.spawn(self.process_packets)
        self.table_miss = hub.spawn(self.flow_table)
        self.producer = KafkaProducer(bootstrap_servers='130.65.159.69:9092',value_serializer=lambda v: json.dumps(v).encode('utf-8'))

    def flow_table(self):
        """
        Once the timeout has been triggered, ensure that the flow entries
        of the switch has been cleared
        """
        
        while True:
            hub.sleep(120)
            try:
                datapath = self.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                # Install table-miss flow entry
                match = parser.OFPMatch()
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath, 0, match, actions)
                print("Added Flow Entry")
            except AttributeError:
                print("Switch not instantiated")

    def extract_features(self, features, url):
        srv = features[1]
        prt = features[13]

        del features[1]
        del features[12]

        service_to_int = dict((c, i) for i, c in enumerate(service))
        protocols_to_int = dict((c, i) for i, c in enumerate(protocol))

        integer_encoded_service = service_to_int[srv]
        integer_encoded_protocol = protocols_to_int[prt]

        encoded_service = [0 for _ in range(len(service))]
        encoded_service[integer_encoded_service] = 1

        encoded_protocol = [0 for _ in range(len(protocol))]
        encoded_protocol[integer_encoded_protocol] = 1

        encoded_service.extend(encoded_protocol)
        features.extend(encoded_service)

        # Format the data into a list though the data is already in a list
        features = np.array(features).tolist()
        # print(features)
        # print(len(features))
        
        r = requests.post(url,json={'exp':features})
        # print(r.json())
        return r.json()

    def process_packets(self):
        while True:
            if event_queue.empty():
                hub.sleep(2)
                continue
            else:
                event_item = event_queue.get()
                msg = event_item.msg
                timestamp = event_item.timestamp
                
                features = None
                
                pkt = packet.Packet(msg.data)
                ip_packet = pkt.get_protocol(ipv4.ipv4)
                udp_seg = pkt.get_protocol(udp.udp)
                tcp_seg = pkt.get_protocol(tcp.tcp)

                if ip_packet:
                    src_ip = ip_packet.src
                    dst_ip = ip_packet.dst
                     
                    if udp_seg:
                        src_port = str(udp_seg.src_port)
                        dst_port = str(udp_seg.dst_port)
                        # Hit the node endpoint for UDP traffic
                        url = 'http://229c8b7b.ngrok.io/slave01/api'
                        features = self.extract_udp(ip_packet, udp_seg, timestamp)
                        print("UDP {}".format(len(features)))
                        
                        self.results['src_ip'] = src_ip
                        self.results['src_port'] = src_port
                        self.results['dst_ip'] = dst_ip
                        self.results['dst_port'] = dst_port
                        self.results['node'] = "slave01"
                        self.results['service'] = features[1]
                        self.results['result'] = self.extract_features(features, url)
                        # print("Done UDP") 
                        
                        producer.send('test', results).get(timeout=30)
                    elif tcp_seg:
                        src_port = str(tcp_seg.src_port)
                        dst_port = str(tcp_seg.dst_port)
                        # Hit the node endpoint for TCP traffic
                        url = 'http://229c8b7b.ngrok.io/slave02/api'
                        features = self.extract_tcp(ip_packet, tcp_seg, timestamp)
                        print("TCP {}".format(len(features)))
                        
                        self.results['src_ip'] = src_ip
                        self.results['src_port'] = src_port
                        self.results['dst_ip'] = dst_ip
                        self.results['dst_port'] = dst_port
                        self.results['node'] = "slave02"
                        self.results['service'] = features[1]
                        self.results['result'] = self.extract_features(features, url)
                        # print("Done UDP")
                        
                        producer.send('test', results).get(timeout=30)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Install table-miss flow entry
        
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        # Put the event into the event queue to ensure that packets are being processed
        event_queue.put(ev)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        ip_packet = pkt.get_protocol(ipv4.ipv4)
        
        match = None
        actions = []

        if ip_packet:
            match = parser.OFPMatch(eth_type=0x0800,
                in_port=in_port,
                ipv4_src=ip_packet.src,
                ipv4_dst=ip_packet.dst
        )

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def extract_tcp(self, packet, tcp_seg, timestamp):
        src = packet.src
        dst = packet.dst
        src_port = str(tcp_seg.src_port)
        dst_port = str(tcp_seg.dst_port)
        
        # unique connection = sourceIP+SourcePort+DestinationIP
        uniq = src+':'+src_port+':'+dst
        dup = dst+':'+dst_port+':'+src
        
        cursvc = {}
        oldkey = ''
        cnt = 0
        syncnt = 0
        synsvcnt = 0
        srcport_count = 0
        syn_error_count = 0
        srv_syn_error_count = 0
        
        # check for unique connections
        if uniq not in dic and dup not in dic:
            dic[uniq] = [src,dst,0,0,timestamp,packet.total_length,0,0,-1,0,3,0,0,0,0,0,0,0,'tcp']

            # SYN error calculation
            if tcp_seg.has_flags(tcp.TCP_SYN):
                dic[uniq][10] -= 1

            #identify service types
            if dst_port in svclist:
                dic[uniq][7] = svclist[dst_port]
            else:
                svclist[dst_port] = 'other'
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
                            if src_port == int(key[start:end]):
                                srcport_count +=1
                            #calculate SYN error
                            if value[2] > 2 and value[10] !=0:
                                syn_error_count +=1

                        #svc connections for top 100 connections
                        if dst_port in svclist:
                            if value[7] == svclist[dst_port]:
                                dic[uniq][14] += 1
                                #SYN error for same service
                                if value[2] > 2 and value[10] !=0:
                                    srv_syn_error_count +=1 

                #check for two second limit
                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-timestamp<=2:
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

            return temp_list

        elif uniq in dic:
            
            # packet count
            dic[uniq][2] += 1
            # duration
            dic[uniq][3] += timestamp - dic[uniq][4]
            # last packet time
            dic[uniq][4] = timestamp
            # Source bytes
            dic[uniq][5] += packet.total_length
            # Count feature init
            dic[uniq][8] = -1
            # Same srv rate init
            dic[uniq][9] = 0

            dic[uniq][13] = 0
            dic[uniq][14] = 0

            #   >>> pkt = tcp.tcp(bits=(tcp.TCP_SYN | tcp.TCP_ACK))
            #   >>> pkt.has_flags(tcp.TCP_SYN, )
        
            if dic[uniq][2] == 2 and tcp_seg.has_flags(tcp.TCP_ACK):
                dic[uniq][10] -= 1

            # calculte offset and length of dic
            len_dic = len(dic)
            offset = len(dic) - 100

            # loop through unique conections
            for key,value in dic.items():
                
                # set offset to 0
                if offset > 0:
                    offset -= 1
                # track first hundred connections 
                elif offset <= 0:   
                    # check for src connections for top 100 connections
                    if value[1] == dst:
                        # src connections for top 100 connections
                        if value[0] == src:
                            dic[uniq][13] += 1
                            #compare with the src port
                            start = key.find(':')+1
                            end = key[start:].find(':')+start
                            if src_port == int(key[start:end]):
                                srcport_count +=1
                            #calculate SYN error
                            if value[2] > 2 and value[10] !=0:
                                syn_error_count +=1

                        #svc connections for top 100 connections
                        if dst_port in svclist:
                            if value[7] in svclist[dst_port]:
                                dic[uniq][14] += 1
                                #SYN error for same service
                                if value[2] > 2 and value[10] !=0:
                                    srv_syn_error_count +=1 

                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-timestamp<=2:
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

            return temp_list
            
        elif dup in dic:
            
            #packet count
            dic[dup][2] += 1
            #duration
            dic[dup][3] += timestamp - dic[dup][4]
            #last packet time
            dic[dup][4] = timestamp
            #Dest bytes
            dic[dup][6] += packet.total_length
            #Count feature init
            dic[dup][8] = -1
            #Same srv rate init
            dic[dup][9] = 0
            dic[dup][13] = 0
            dic[dup][14] = 0

            # SYN error calculation
            if dic[dup][10] <= 3 and dic[dup][10] >= 0 and tcp_seg.has_flags(tcp.TCP_ACK, tcp.TCP_SYN):
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
                      
                    # check for src connections for top 100 connections
                    if value[0] == dst:
                        # src connections for top 100 connections
                         
                        if value[1] == src:
                            dic[dup][13] += 1
                            #compare with the src port
                            start = key.find(':')+1
                            end = key[start:].find(':')+start
                            if src_port == int(key[start:end]):
                                srcport_count +=1 
                            #calculate SYN error
                            if value[2] > 2 and value[10] !=0:
                                syn_error_count +=1
                        #svc connections for top 100 connections
                        if src_port in svclist:
                            if value[7] in svclist[src_port]:
                                dic[dup][14] += 1
                                #SYN error for same service
                                if value[2] > 2 and value[10] !=0:
                                    srv_syn_error_count +=1 
                          
                
                if dst+src in key[:len(dst)]+key[len(key)-len(src):] and dic[key][4]-timestamp<=2:
                    dic[dup][8] += 1

                    #Serror rate: calculte SYN error
                    if value[2] > 2 and value[10] !=0:
                        syncnt +=1
                        if dic[dup][7] in value[7]:
                            synsvcnt +=1
                    
                    # Same srv rate calculate same service
                    if value[7] not in cursvc:
                        cursvc[value[7]] = 1
                    else:
                        cursvc[value[7]] += 1
            
            #same srv rate final calculation
            for key,value in cursvc.items():
                if dic[dup][8] != 0:
                    dic[dup][9] += (value/dic[dup][8])
            # Serror rate: calculte SYN error
            if dic[dup][8] != 0:
                dic[dup][11] = (syncnt/dic[dup][8])

            # Srv serror rate: Same service SYN error
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

            return temp_list

    def extract_udp(self, packet, udp_seg, timestamp):
        src = packet.src
        dst = packet.dst
        src_port = str(udp_seg.src_port)
        dst_port = str(udp_seg.dst_port)
        
        #unique connection = sourceIP+SourcePort+DestinationIP
        uniq = src+':'+str(src_port)+':'+dst
        dup = dst+':'+str(dst_port)+':'+src
        
        global temp
        global cursvc
        cursvc = {}
        oldkey=''
        cnt=0
        syncnt=0
        synsvcnt=0
        srcport_count=0
        
        # check for unique connections
        if uniq not in udp_connections and dup not in udp_connections:
           
            udp_connections[uniq] = [src,dst,0,0,timestamp,packet.total_length,0,0,-1,0,0,0,0,0,0,0,0,0,'udp']

            #identify service types
            if dst_port in svclist:
                udp_connections[uniq][7] = svclist[dst_port]
            else:
                svclist[dst_port] = 'other'
                udp_connections[uniq][7] = 'other'
            # calculte offset and length of udp_connections
            len_dic = len(udp_connections)
            offset = len(udp_connections) - 100

            #loop through unique conections
            for key,value in udp_connections.items():
                
                #set offset to 0
                if offset > 0:
                    offset -= 1
                #track first hundred connections 
                elif offset <= 0:   
                    #check for src connections for top 100 connections
                    if value[1] == dst:
                        #src connections for top 100 connections
                        if value[0] == src:
                            udp_connections[uniq][13] += 1
                            #compare with the src port
                            start = key.find(':')+1
                            end = key[start:].find(':')+start
                            if src_port == int(key[start:end]):
                                srcport_count +=1

                        #svc connections for top 100 connections
                        if dst_port in svclist:
                            if value[7] == svclist[dst_port]:
                                udp_connections[uniq][14] += 1

                #check for two second limit
                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and udp_connections[key][4]-timestamp<=2:
                    #Count feature
                    udp_connections[uniq][8] += 1 
                    #Same srv rate calculate same service
                    if value[7] not in cursvc:
                        cursvc[value[7]] = 1
                    else:
                        cursvc[value[7]] += 1

            #same srv rate final calculation
            for key,value in cursvc.items():
                if udp_connections[uniq][8] != 0:
                    udp_connections[uniq][9] += (value/udp_connections[uniq][8])
            # Dst host same src port rate
            if udp_connections[uniq][13]!=0:
                udp_connections[uniq][15] = (srcport_count/udp_connections[uniq][13])
            
            temp_list = [udp_connections[uniq][3],udp_connections[uniq][7],udp_connections[uniq][5],udp_connections[uniq][6],udp_connections[uniq][8],udp_connections[uniq][9],0,0,udp_connections[uniq][13],udp_connections[uniq][14],udp_connections[uniq][15],0,0,udp_connections[uniq][18]]
            return temp_list
            # writer.writerow(temp_list)
        elif uniq in udp_connections:
            
            #packet count
            udp_connections[uniq][2] += 1
            #duration
            udp_connections[uniq][3] += timestamp - udp_connections[uniq][4]
            #last packet time
            udp_connections[uniq][4] = timestamp
            #Source bytes
            udp_connections[uniq][5] += packet.total_length
            #Count feature init
            udp_connections[uniq][8] = -1
            #Same srv rate init
            udp_connections[uniq][9] = 0

            udp_connections[uniq][13] = 0
            udp_connections[uniq][14] = 0

            # calculte offset and length of udp_connections
            len_dic = len(udp_connections)
            offset = len(udp_connections) - 100

            #loop through unique conections
            for key,value in udp_connections.items():
                
                #set offset to 0
                if offset > 0:
                    offset -= 1
                #track first hundred connections 
                elif offset <= 0:   
                    #check for src connections for top 100 connections
                    if value[1] == dst:
                        #src connections for top 100 connections
                        if value[0] == src:
                            udp_connections[uniq][13] += 1
                            #compare with the src port
                            start = key.find(':')+1
                            end = key[start:].find(':')+start
                            if src_port == int(key[start:end]):
                                srcport_count +=1
                            
                        #svc connections for top 100 connections
                        if dst_port in svclist:
                            if value[7] == svclist[dst_port]:
                                udp_connections[uniq][14] += 1
                           
                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and udp_connections[key][4]-timestamp<=2:
                    udp_connections[uniq][8] += 1
                    #Same srv rate calculate same service
                    if value[7] not in cursvc:
                        cursvc[value[7]] = 1
                    else:
                        cursvc[value[7]] += 1
            
            #same srv rate final calculation
            for key,value in cursvc.items():
                if udp_connections[uniq][8] != 0:
                    udp_connections[uniq][9] += (value/udp_connections[uniq][8])

            # Dst host same src port rate
            if udp_connections[uniq][13]!=0:
                udp_connections[uniq][15] = (srcport_count/udp_connections[uniq][13])
            
            temp_list = [udp_connections[uniq][3],udp_connections[uniq][7],udp_connections[uniq][5],udp_connections[uniq][6],udp_connections[uniq][8],udp_connections[uniq][9],0,0,udp_connections[uniq][13],udp_connections[uniq][14],udp_connections[uniq][15],0,0,udp_connections[uniq][18]]
            return temp_list
            # writer.writerow(temp_list)
          
        elif dup in udp_connections:
            #packet count
            udp_connections[dup][2] += 1
            #duration
            udp_connections[dup][3] += timestamp - udp_connections[dup][4]
            #last packet time
            udp_connections[dup][4] = timestamp
            #Dest bytes
            udp_connections[dup][6] += packet.total_length
            #Count feature init
            udp_connections[dup][8] = -1
            #Same srv rate init
            udp_connections[dup][9] = 0
            udp_connections[dup][13] = 0
            udp_connections[dup][14] = 0

            # calculte offset and length of udp_connections
            len_dic = len(udp_connections)
            offset = len(udp_connections) - 100
            
            #loop through unique conections
            for key,value in udp_connections.items():

                #set offset to 0
                if offset > 0:
                    offset -= 1
                #track first hundred connections 
                elif offset <= 0: 
                      
                    #check for src connections for top 100 connections
                    if value[0] == dst:
                        #src connections for top 100 connections
                         
                        if value[1] == src:
                            udp_connections[dup][13] += 1
                            #compare with the src port
                            start = key.find(':')+1
                            end = key[start:].find(':')+start
                            if src_port == int(key[start:end]):
                                srcport_count +=1 
                            
                        #svc connections for top 100 connections
                        if src_port in svclist:
                            if value[7] == svclist[src_port]:
                                udp_connections[dup][14] += 1
                            
                
                if dst+src in key[:len(dst)]+key[len(key)-len(src):] and udp_connections[key][4]-timestamp<=2:
                    udp_connections[dup][8] += 1
                    #Same srv rate calculate same service
                    if value[7] not in cursvc:
                        cursvc[value[7]] = 1
                    else:
                        cursvc[value[7]] += 1
            
            #same srv rate final calculation
            for key,value in cursvc.items():
                if udp_connections[dup][8] != 0:
                    udp_connections[dup][9] += (value/udp_connections[dup][8])
            # Dst host same src port rate
            if udp_connections[dup][13]!=0:
                udp_connections[dup][15] = (srcport_count/udp_connections[dup][13])
            
            temp_list = [udp_connections[dup][3],udp_connections[dup][7],udp_connections[dup][5],udp_connections[dup][6],udp_connections[dup][8],udp_connections[dup][9],0,0,udp_connections[dup][13],udp_connections[dup][14],udp_connections[dup][15],0,0,udp_connections[dup][18]]
            return temp_list
            # writer.writerow(temp_list)
