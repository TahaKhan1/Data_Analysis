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
import copy
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
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import setting


CONF = cfg.CONF

class NetworkAwareness(app_manager.RyuApp):
    """
        NetworkAwareness is a Ryu app for discover topology information.
        This App can provide many data services for other App, such as
        link_to_port, access_table, switch_port_table,access_ports,
        interior_ports.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "awareness"
        self.link_to_port = {}       # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.access_table = {}       # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # dpip->port_num
        self.access_ports = {}       # dpid->port_num
        self.interior_ports = {}     # dpid->port_num


	###--------------------------switch_features_handler--------------###

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Initial operation, send miss-table flow entry to datapaths.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

	###-----------------------------add_flow-------------------------###
	def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
		dp.send_msg(mod)
	

    #####---------------------get_host_location-------------------#####

    def get_host_location(self, host_ip):
    """
        Get host location info:(datapath, port) according to host ip.
    """
    for key in self.access_table.keys():
        if self.access_table[key][0] == host_ip:
            return key
    self.logger.info("%s location is not found." % host_ip)
    return None
    ###------------------------get_switches-----------------------###
    def get_switches(self):
        return self.switches
    ###----------------------- get_links------------------------####
    def get_links(self):
		return self.link_to_port

	###-----------------------create_port_map-------------------------###

    def create_port_map(self, switch_list):
    """
        Create interior_port table and access_port table. 
    """
    for sw in switch_list:
        dpid = sw.dp.id
        self.switch_port_table.setdefault(dpid, set())
        self.interior_ports.setdefault(dpid, set())
        self.access_ports.setdefault(dpid, set())

        for p in sw.ports:
			self.switch_port_table[dpid].add(p.port_no)


	
