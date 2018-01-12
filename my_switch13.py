# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# conding=utf-8
import logging
import struct
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.app import network_awareness

CONF = cfg.CONF

class MySimpleSwitch13(app_manager.RyuApp):
    """
        ShortestForwarding is a Ryu app for forwarding packets in shortest
        path.
        The shortest path computation is done by module network awareness,
        network monitor and network delay detector.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_awareness": network_awareness.NetworkAwareness,
        }
    
    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = 'shortest_forwarding'
        self.awareness = kwargs["network_awareness"]
        self.monitor = kwargs["network_monitor"]
        self.delay_detector = kwargs["network_delay_detector"]
        self.datapaths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

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

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=15, hard_timeout=60)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                             src_dpid, dst_dpid))
            return None

    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.awareness.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)


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
		
   
    ###---------------Packet_In_Handler--------------------####	

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
			msg = ev.msg
			datapath = msg.datapath
			#self.logger.info('Datapath: {}'.format(datapath.id)
			ofproto = datapath.ofproto	

			parser = datapath.ofproto_parser
			#self.logger.info('Parser: {}'.format(parser))


	if msg.reason == ofproto.OFPR_NO_MATCH:
		reason = 'NO MATCH'
    elif msg.reason == ofproto.OFPR_ACTION:
        reason = 'ACTION'
    elif msg.reason == ofproto.OFPR_INVALID_TTL:
        reason = 'INVALID TTL'
	
    in_port = msg.match['in_port']

	#open flow headers are parsed already	

	pkt = packet.Packet(msg.data)
	#self.logger.info('Packet information {}'.format(pkt))
    eth = pkt.get_protocols(ethernet.ethernet)[0]
	dst = eth.dst
    src = eth.src
    dpid = datapath.id
	arp_pkt=pkt.get_protocol(arp.arp)

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
    if isinstance(arp_pkt,arp.arp):
		self.logger.debug("Arp Processing")
		self.arp_forwarding(msg,arp_pkt.src_ip,arp_pkt.dst_ip)

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
	
	
	
	
	






     

    

	
		 
   
	

   

