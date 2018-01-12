



from operator import attrgetter
from ryu.base import app_manager
from ryu.lib.pack_utils import msg_pack_into
from ryu import utils
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib import hub
from ryu.topology import event
from ryu.lib.packet import packet, ethernet, arp, icmp, ipv4, ipv6
from ryu.lib.packet import ether_types
from ryu.topology.switches import LLDPPacket
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib import dpid as dpid_lib

import os
import time




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # variables to maintain the execution sequence of different EVENTS
        self.ResetFlow = 0
        self.PingFlow = False
        self.FlowDel = False
                        
        # time to hold both the old rule and the new rule (2 sec). It is set once 
        self.present_time = 2*1000        

 	# Set time in sec to start the main rule insertion/deletion function execution 
        self.monitor_thread = hub.spawn_after(1, self._monitor)                                    


#....................................................... switch_in_handler ...................................................
                                                  # pro-active rules in Switches

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

# 	send all flows: Switch --> Controller 
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.debug( "pro-active rules for cellular network" )
        if datapath.id == 1:       
            self.group_mod01(datapath)
            actions = [parser.OFPActionSetField(ip_dscp = 1), parser.OFPActionGroup(group_id = 1)]
            priority = 100
            match = parser.OFPMatch(in_port= 1, eth_type=0x0800, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', ip_proto=17, udp_dst=5555 )
            self.add_flow(datapath, priority , match, actions)  

            match = parser.OFPMatch(in_port= 2, eth_type=0x0800)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority, match, actions)
            match = parser.OFPMatch(in_port= 4, eth_type=0x0800)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority, match, actions)
        if datapath.id == 3:       
            priority = 100
            match = parser.OFPMatch(in_port= 2, eth_type=0x0800, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', ip_dscp = 1, ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority, match, actions)

            match = parser.OFPMatch(in_port= 1, eth_type=0x0800)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, priority, match, actions)
        if datapath.id == 4:
            priority = 100
            match = parser.OFPMatch(in_port= 2, eth_type=0x0800, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', ip_dscp = 1, ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority, match, actions)
            match = parser.OFPMatch(in_port= 4, eth_type=0x0800, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', ip_dscp = 1, ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 22, match, actions)

            self.group_mod02(datapath)
            actions = [parser.OFPActionGroup(group_id = 1)]
            priority = 100
            match = parser.OFPMatch(in_port= 1, eth_type=0x0800)
            self.add_flow(datapath, priority , match, actions)  
        if datapath.id == 5:       
            priority = 100
            match = parser.OFPMatch(in_port= 1, eth_type=0x0800, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', ip_dscp = 1, ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, priority, match, actions)

            match = parser.OFPMatch(in_port= 2, eth_type=0x0800)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority, match, actions)

#.............................................................................................................................

#...........................................................add_flow..........................................................
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
#.............................................................................................................................

#....................................................... send_group_mod .....................................................
    # applicable in Swicth-1 (shared switch/AP) 
    def group_mod01(self, datapath):                                                                                                      
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        group_id = 1
        action01 = [parser.OFPActionOutput(2)]   # output port 2 of switch 1 for switch 3

        action02 = [parser.OFPActionOutput(4)]   # output port 4 for switch 1 for switch 5
        weight01 = 50                           # % of the total data packets of a flow         
        weight02 = 50                             # % of the total data packets of a flow
        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL        
        buckets = [parser.OFPBucket(weight01, watch_port, watch_group, action01), parser.OFPBucket(weight02, watch_port, watch_group, action02)]
        req = parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD, ofproto.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)


    def group_mod02(self, datapath):                                                                                                      
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        group_id = 2
        action01 = [parser.OFPActionOutput(2)]   # output port 2 of switch 1 for switch 3
        action02 = [parser.OFPActionOutput(4)]   # output port 4 for switch 1 for switch 5
        weight01 = 50                           # % of the total data packets of a flow         
        weight02 = 50                             # % of the total data packets of a flow
        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL        
        buckets = [parser.OFPBucket(weight01, watch_port, watch_group, action01), parser.OFPBucket(weight02, watch_port, watch_group, action02)]
        req = parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD, ofproto.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)

#.............................................................................................................................

#....................................................... packet_in_handler ...................................................
                                                    # reactive rules in Switches

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if self.ResetFlow == 0 and arp_pkt != None:
            self.logger.debug("ARP processing in WiFi network")
            if dpid == 1:   
                self.group_mod01(datapath)
                action = [parser.OFPActionGroup(group_id = 1)]
	        match = parser.OFPMatch(in_port= 1, eth_type=0x0806)
                self.add_flow(datapath, 1, match, action)

	        match = parser.OFPMatch(in_port= 2, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)
	        match = parser.OFPMatch(in_port= 4, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)

            if dpid == 3:   
	        match = parser.OFPMatch(in_port= 1, eth_type=0x0806)
	        action = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 1, match, action)
	        match = parser.OFPMatch(in_port= 2, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)
            if dpid == 4:   
	        match = parser.OFPMatch(in_port= 4, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)
	        match = parser.OFPMatch(in_port= 2, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)

                self.group_mod02(datapath)
                action = [parser.OFPActionGroup(group_id = 2)]
	        match = parser.OFPMatch(in_port= 1, eth_type=0x0806)
                self.add_flow(datapath, 1, match, action)                  
            if dpid == 5:   
	        match = parser.OFPMatch(in_port= 1, eth_type=0x0806)
	        action = [parser.OFPActionOutput(2)]
                self.add_flow(datapath, 1, match, action)
	        match = parser.OFPMatch(in_port= 2, eth_type=0x0806)
	        action = [parser.OFPActionOutput(1)]
                self.add_flow(datapath, 1, match, action)




#.............................................................................................................................


#....................................................... Flow status request/response ........................................
    def request_stats(self, datapath):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if self.ResetFlow == 1 and dpid == 4:
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow = []
	print "\n\n"
        self.logger.debug('datapath         IP-DSCP '
                         ' IP4-src            IP4-dst           '
                         'out-port packets  bytes    priority   duration(s)        duration(ns)')
        self.logger.debug('----------------  -------- '
                         '----------------- ----------------- '
                         '-------- -------- --------  --------  -----------------  ----------------- ')
        for stat in sorted([flow for flow in body if flow.priority == 11], key=lambda flow: (flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_dscp'])):
            self.logger.debug('%016x %8x %17s %17s %8x %8d %8d %8d %17d %17d',
                             ev.msg.datapath.id, stat.match['ip_dscp'],
                             stat.match['ipv4_src'], stat.match['ipv4_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count, stat.priority, stat.duration_sec, stat.duration_nsec)
            if (stat.packet_count > 0) :
                self.PingFlow = True
                self.logger.info("number of pkt: %s   PingFlow: %s ", stat.packet_count, self.PingFlow)
                
	print "\n"
        self.logger.info('datapath         IP-DSCP '
                         ' IP4-src            IP4-dst           '
                         'out-port packets  bytes    priority   duration(s)        duration(ns)')
        self.logger.info('----------------  -------- '
                         '----------------- ----------------- '
                         '-------- -------- --------  --------  -----------------  ----------------- ')
        for stat in sorted([flow for flow in body if flow.priority == 22], key=lambda flow: (flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_dscp'])):
            self.logger.info('%016x %8x %17s %17s %8x %8d %8d %8d %17d %17d',
                             ev.msg.datapath.id, stat.match['ip_dscp'],
                             stat.match['ipv4_src'], stat.match['ipv4_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count, stat.priority, stat.duration_sec, stat.duration_nsec)
            if (stat.packet_count > 0) :
                self.PingFlow = False
                self.FlowDel = True
                self.logger.info("number of pkt: %s ResetFlow: %s PingFlow: %s ", stat.packet_count, self.ResetFlow, self.PingFlow)


                             
#.....................................................................................................................................

#....................................................... Cycelic Network Control .....................................................

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
	datapath = ev.datapath
	if ev.state == MAIN_DISPATCHER:
	    if not datapath.id in self.datapaths:
		self.logger.debug('register datapath: %016x', datapath.id)
		self.datapaths[datapath.id] = datapath
	elif ev.state == DEAD_DISPATCHER:
	    if datapath.id in self.datapaths:
		self.logger.debug('deregister datapath: %016x', datapath.id)
		del self.datapaths[datapath.id]

    def _monitor(self):
        while True:  
            for datapath in self.datapaths.values():
                self.request_stats(datapath)
                hub.sleep(2)
            if self.ResetFlow == 0:
                pres_time = ( time.time() * 1000 )
                self.logger.debug( "Data pkt flow through Cellular network" )
                self.logger.debug("present time: %s  millisec", pres_time)
#                self.logger.info("Do you want to change the network? [y/n]")
#                Result1 = raw_input(": ")
#                if (Result1 == 'y'):                    
#	    	    self.ResetFlow = 1  
#                    pres_time = ( time.time() * 1000 )
#                    self.logger.info( "Trigger time: %s  millisec", pres_time )
#                else:
#                    print "Skip..............."	    	                        

            elif self.ResetFlow == 1:
                pres_time = ( time.time() * 1000 )
                self.logger.debug( "Action Start: Data pkt flow through WiFi network" )
                self.logger.debug("present time: %s  millisec", pres_time)
                                   
                                    
#.............................................................................................................................



















        
