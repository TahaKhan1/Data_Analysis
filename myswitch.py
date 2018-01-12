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
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu import utils
from ryu.lib.packet import ipv6
from ryu.lib import mac
from ryu.topology import event,switches
from ryu.topology.api import get_switch, get_link
import copy

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {} ## 
        self.access_ports = {}  ## dpid -> port_num
        self.access_table = {}  ## {(sw,port): [host1_ip]}
        self.link_to_port = {}   ## (src_dpid, dst_dpid)-> (src_port, dest_port)
        self.interior_ports = {}  ## dpid -> port_num
        self.switch_port_table = {} ## dpid-> port_num
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	msg=ev.msg
		

	#self.logger.info("Packet data: {}".format(msg))
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
	#self.logger.info("Switch: {}".format(datapath.id)
		
   
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
        msg = ev.msg
	datapath = msg.datapath
	#self.logger.info('Datapath: {}'.format(datapath.id))
	ofproto = datapath.ofproto	

	parser = datapath.ofproto_parser
	#self.logger.info('Parser: {}'.format(parser))


	if msg.reason == ofproto.OFPR_NO_MATCH:
		reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
                reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
                reason = 'INVALID TTL'
	#self.logger.info('OFPPacketIn received: buffer_id=%x total_len=%d reason=%s table_id=%d cookie=%d match=%s', msg.buffer_id, msg.total_len, reason, msg.table_id, msg.cookie, msg.match)
        in_port = msg.match['in_port']

	#open flow headers are parsed already	

	pkt = packet.Packet(msg.data)
	#self.logger.info('Packet information {}'.format(pkt))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:  # ignore lldp packet
		#self.logger.info("LLDP packet in %s %s %s %s", dpid, src, dst, in_port)
		return           
        	
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
	
	if dst[:5] == "33:33":  # ignore IPV6 multicast packet
 		match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
		actions=[]
		self.add_flow(datapath, 1 , match, actions)
		return
	
	if  dst==mac.BROADCAST_STR: # Handle ARP broadcast 	
		self.logger.info('This is ARP broadcast received at port {} of switch {}'.format(in_port, datapath.id) )	
		#self.send_arpproxy()

	return
	
	###------------------------- Topology Discovery ------------------####
	
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
	self.logger.info("****************THIS EVENT IS TRIGGERRED***********")
	# The Function get_switch(self, None) outputs the list of switches.
	self.topo_raw_switches = copy.copy(get_switch(self, None))
	# The Function get_link(self, None) outputs the list of links.
	self.topo_raw_links = copy.copy(get_link(self, None))

	print(" \t" + "Current Links:")
	for l in self.topo_raw_links:
		print (" \t\t" + str(l))

	print(" \t" + "Current Switches:")
	for s in self.topo_raw_switches:
		print (" \t\t" + str(s))     
	return 
    
    @set_ev_cls(event.EventLinkDelete)
    def link_down_handler(self, ev):
	self.logger.info("A link has gone down")
	self.logger.info('Switch Down {}, {}'.format(ev.link.src.dpid, ev.link.dst))		
	

    @set_ev_cls(event.EventLinkAdd)
    def link_down_handler(self, ev):
    
	self.logger.info("A link has restored")
	self.logger.info('Switch Up {}, {}'.format(ev.link.src.dpid, ev.link.dst))
	
	
	
	
	






     

    

	
		 
   
	

   

