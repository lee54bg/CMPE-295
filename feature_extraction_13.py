# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import event
from ryu.topology import event as e2

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
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
udp = {}
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


data_to_send = queue.Queue()

class TimeoutEvent(event.EventBase):
    """
    A class that inherits the EventBase.  This will be used to generate the various timeouts
    for clearing the flow entries of the switches.
    """
    def __init__(self, message):
        super(TimeoutEvent, self).__init__()
        self.msg = message

class FeatureExtraction13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [TimeoutEvent]

    def start(self):
        """
        Start a new thread for a timer.
        """
            
        super(FeatureExtraction13, self).start()
        # self.threads.append(hub.spawn(self.gen_timer))
        self.threads.append(hub.spawn(self.basic_function))
        

    def __init__(self, *args, **kwargs):
        super(FeatureExtraction13, self).__init__(*args, **kwargs)
        self.datapath = None
        self.mac_to_port = {}
        self.counter = 0
        
    def gen_timer(self):
        """
        Generate a random timeout from 15 to 30 seconds
        to clear flow entries
        """
        while 1:
            rand_num = randint(15, 30)
            hub.sleep(rand_num)
            print("Cleared the timer after " + str(rand_num) + " seconds")
            self.send_event_to_observers(TimeoutEvent("Table-miss"))

    def basic_function(self):
        service = ['other', 'ssh', 'dns', 'rdp', 'smtp', 'snmp', 'http', 'smtp,ssl', 'ssl', 'sip']
        protocol = ["icmp", "tcp", "udp"]
      
        url = ""

        while True:
            if data_to_send.empty():
                hub.sleep(1)
                continue
            else:
                item = data_to_send.get()
                
                data = item[0]
                timestamp = item[1]

                features = None

                ip_packet = data.get_protocol(ipv4.ipv4)
                
                try:
                    if ip_packet:
                        src_ip = ip_packet.src
                        dst_ip = ip_packet.dst
                        
                        # udp_seg = data.get_protocol(udp.udp)
                        tcp_seg = data.get_protocol(tcp.tcp)

                        if tcp_seg:
                            tcp_send(tcp_seg, src_ip, dst_ip)
                            print("TCP")
                        # elif udp_seg:
                        #     udp_send(udp_seg, src_ip, dst_ip)
                        #     print("UDP")
                except:
                    print("Not working")
                
    def tcp_send(tcp_seg, src_ip, dst_ip):
        url = "https://229c8b7b.ngrok.io/slave01/api"
        src_port = tcp_seg.src_port
        dst_port = tcp_seg.dst_port
        features = self.extract_tcp(ip_packet, tcp_seg, timestamp)
        
        srv = None
        try:
            srv = features[1]
        except:
            print(features)
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
        r = requests.post(url,json={'exp':features})
        
        print("TCP {}".format(r.json()))

        return jsonify(r)
    
    def udp_send(udp_seg, src_ip, dst_ip):
        if udp_seg:
            url = "https://229c8b7b.ngrok.io/slave02/api"
            src_port = udp_seg.src_port
            dst_port = udp_seg.dst_port
            features = self.extract_udp(ip_packet, udp_seg, timestamp)
            
            srv = None
            try:
                srv = features[1]
            except:
                print(features)
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
            r = requests.post(url,json={'exp':features})
            
            # print(features)
            print("UDP {}".format(r.json()))

            return jsonify(r)
    
    @set_ev_cls(TimeoutEvent)
    def flow_table(self, ev):
        """
        Once the timeout has been triggered, ensure that the flow entries
        of the switch has been cleared
        """
        
        try:
            datapath = self.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Install table-miss flow entry
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)
        except AttributeError:
            print("Switch not instantiated")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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

    @set_ev_cls(e2.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        print(switch)
        print(switch.id)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        timestamp = ev.timestamp
        

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_packet = pkt.get_protocol(ipv4.ipv4)
        
        src_ip = 0
        dst_ip = 0
        src_port = 0
        dst_port = 0

        match = None
        actions = []

        item = [pkt, timestamp]
        data_to_send.put(item)
        
        if ip_packet:
            match = parser.OFPMatch(eth_type=0x0800,
                in_port=in_port,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
        )
            
            # self.basic_function()
            # print("{} {} {}".format(timestamp, src_ip, dst_ip))

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
                      
                    #check for src connections for top 100 connections
                    if value[0] == dst:
                        #src connections for top 100 connections
                         
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

            return temp_list

    def extract_udp(self, packet, udp_seg, timestamp):
        src = packet.src
        dst = packet.dst
        src_port = str(udp_seg.src_port)
        dst_port = str(udp_seg.dst_port)

        # Unique connection = sourceIP+SourcePort+DestinationIP
        uniq = src+':'+src_port+':'+dst
        dup = dst+':'+dst_port+':'+src
        
        cursvc = {}
        oldkey = ''
        cnt = 0
        syncnt = 0
        synsvcnt = 0
        srcport_count = 0
        
        # check for unique connections
        if uniq not in dic and dup not in dic:
           
            dic[uniq] = [src,dst,0,0,timestamp,packet.total_length,0,0,-1,0,0,0,0,0,0,0,0,0,'udp']

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

                        #svc connections for top 100 connections
                        if svclist[dst_port] is not None:
                            if value[7] == svclist[dst_port]:
                                dic[uniq][14] += 1


                #check for two second limit
                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-timestamp<=2:
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
            
            return temp_list
            
        elif uniq in dic:
            #packet count
            dic[uniq][2] += 1
            #duration
            dic[uniq][3] += timestamp - dic[uniq][4]
            #last packet time
            dic[uniq][4] = timestamp
            #Source bytes
            dic[uniq][5] += packet.total_length
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
                            if src_port == int(key[start:end]):
                                srcport_count +=1
                            
                        #svc connections for top 100 connections
                        if svclist[dst_port] is not None:
                            if value[7] == svclist[dst_port]:
                                dic[uniq][14] += 1
                           
                if src+dst in key[:len(src)]+key[len(key)-len(dst):] and dic[key][4]-timestamp<=2:
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
                            if src_port == int(key[start:end]):
                                srcport_count +=1 
                            
                        #svc connections for top 100 connections
                        if svclist[src_port] is not None:
                            if value[7] == svclist[src_port]:
                                dic[dup][14] += 1
                            
                
                if dst+src in key[:len(dst)]+key[len(key)-len(src):] and dic[key][4]-timestamp<=2:
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

            return temp_list
