# Author: Brandon Lee Gaerlan
# CMPE 295B Master's Project
# Description:  Stat collection for Ryu SDN

from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
# from kafka import KafkaProducer

class StatsMonitor13(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(StatsMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.statistics = {}
        # self.producer = KafkaProducer(bootstrap_servers='130.65.159.69:9092',value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.get_stats(dp)
            hub.sleep(10)

    def get_stats(self, datapath):
        self.logger.debug('sending stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            self.statistics['port_no'] = stat.port_no
            self.statistics['rx_packets'] = stat.rx_packets
            self.statistics['rx_bytes'] = stat.rx_bytes
            self.statistics['rx_errors'] = stat.rx_errors
            self.statistics['tx_packets'] = stat.tx_packets
            self.statistics['tx_bytes'] = stat.tx_bytes
            self.statistics['tx_errors'] = stat.tx_errors

            # self.producer.send('test', self.statistics).get(timeout=30)
            
            for key,value in statistics.items():
                print(key, value)