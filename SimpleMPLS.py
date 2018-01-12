# Copyright 2016 Greg M. Bernstein
"""
A program to set up simple label switched paths (LSPs) between two IP based
hosts in a users network.  We will set up bidirectional paths with
forwarding equivalence classes based on the destination and source IP
addresses. The first switch connected to a host along a path will act as the
ingress LSR and perform MPLS push operation, last switch will do the MPLS
pop operation. This program requires OpenFlow 1.3 support by the switches. I've
also found that Mininet/OVS needs to be running on a more recent Linux kernel
for the MPLS functionality to work. Also recomment OpenVswitch 2.5 or higher.

This application will only work with Mininet networks whose topologies are known
in advanced and available in a JSON file. Substitute your network file for my
ExNetweithLoops1A.json file.

To launch the application just use:
    python SimpleMPLS.py --netfile=MPLS-topo.json
If you don't want to use the telnet/python backdoor:
    python SimpleMPLS.py --netfile=ExNetwithLoops1A.json --notelnet

To launch mininet using a custom topology and remote controller based on this
code use:

sudo python NetRunnerNS.py -f MPLS-topo.json -ip 127.0.0.1

To bring up our 'backdoor' python interface on the machine you are running this
program (windows or Linux) type:
telnet localhost 3000

Getting a reference to the Outline application in the 'backdoor' python shell
and setting up and tearing down a path:
```python
from ryu.base.app_manager import AppManager
am = AppManager.get_instance()
myapp = am.applications["SimpleMPLS"]
myapp.make_lsp("H1-S1-S2-S4-H6")
myapp.make_lsp("H1-S1-S2-S3-S5-H2")
myapp.show_all_lsps()
myapp.make_lsp("H2-S1-S2-H5")
myapp.show_all_lsps()
myapp.remove_lsp("H1-S1-S2-S4-H6")
myapp.remove_lsp("H3-S1-S2-S4-S5-H9")
myapp.show_all_lsps()
myapp.remove_lsp("H2-S1-S2-H5")
```
"""

import random
from collections import defaultdict, OrderedDict
import json
import networkx as nx
from networkx.readwrite import json_graph
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.cmd import manager # For directly starting Ryu
import sys  # For getting command line arguments and passing to Ryu
import eventlet
from eventlet import backdoor  # For telnet python access
from ryu.ofproto import ofproto_v1_3  # This code is OpenFlow 1.0 specific
from ryu.lib.packet.packet import Packet # For packet parsing
import ryu.lib.packet.ipv4
import ryu.lib.packet.mpls
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller import ofp_event
from ryu.topology import switches

if __name__ == "__main__":  # Stuff to set additional command line options
    from ryu import cfg

    CONF = cfg.CONF
    CONF.register_cli_opts([
        cfg.StrOpt('netfile', default=None, help='network json file'),
        cfg.BoolOpt('notelnet', default=False,
                    help='Telnet based debugger.')
    ])


class SimpleMPLS(app_manager.RyuApp):
    """ This app can be used to setup and tear down MPLS LSPs.
        The topology of the network must be given via a JSON file.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    last_shortest_path = "E"

    def __init__(self, *args, **kwargs):
        """ Define member variables here.  For example I keep the network
            topology graph, a dictionary of switch information (for later
            sending commands to the switches), a structure to keep track of all
            labels currently assigned to links (to avoid label collisions).
        """
        super(SimpleMPLS, self).__init__(*args, **kwargs)
        self.netfile = self.CONF.netfile
        self.switches = {}
        # Reads in the topology file and creates a NetworkX graph
        self.g = json_graph.node_link_graph(
            in_adjust_ports(json.load(open(self.netfile))))
        # Will store link labels in a dictionary index by a tuple containing
        # node names such as ("S1", "S2"). We keep track of labels for each link
        # direction, i.e., ("S1", "S2") and ("S2", "S1").
        self.link_labels = defaultdict(list)  # Default to empty list of labels
        self.lsps = {} # Keep track of all the LSPs created
        if not self.CONF.notelnet:
            eventlet.spawn(backdoor.backdoor_server,
                           eventlet.listen(('localhost', 3000)))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures)
    def switch_features(self, event):
        """ This method gets called when a switch connects to the controller.
            We keep switch information in a dictionary indexed by its name.
        """
        msg = event.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Assumes that datapath ID represents an ascii name
        switchName = dpid_to_name(dp.id)
        self.logger.info("Switch {} came up".format(switchName))
        self.switches[switchName] = dp  # Save switch information
        #self.add_flow(dp, 0, match, actions) #"           **************ADDED*****************"
        if len(self.switches) == 5:
             self.make_lsp("H1-S1-S2-S3-S5-H2")
#####################################################################################################
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_ADD,
                                       cookie=0,
                                    priority=ofproto.OFP_DEFAULT_PRIORITY,flags=ofproto.OFPFF_SEND_FLOW_REM, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD,
                                       cookie=0,
                                    priority=ofproto.OFP_DEFAULT_PRIORITY,flags=ofproto.OFPFF_SEND_FLOW_REM, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)


    def make_shortest_path(self):
        """This methode compute the shorest path from H1 to H2
        """
        # Read in a JSON formatted graph file
        g = json_graph.node_link_graph(json.load(open("MPLS-topo.json")))
        
        # Compute the shortest paths from host H1 to all other nodes
        paths = nx.shortest_path(g, "H1", weight="weight")
        for dest in paths.keys():  # Nicely output all those paths
          if dest == "H2":
            print "Shortest Path from H1 to {} is:".format(dest)
            #print "{}".format(paths[dest])
            path = [s.encode('utf-8') for s in paths[dest]]
            y = "-".join(path)
            print y
            return y
      
#######################################################################################################################
    def make_lsp(self, pathString):
        """ Use this to create two uni-directional LSPs (forward and reverse)
        between two hosts systems along a specified path.
        :param pathString: A string of text with node names separated by dashes,
        the first and last nodes must be hosts, and all other nodes switches.
        Example: "H2-S1-S2-H5".
        """
        self.logger.info("make_path called with path {}".format(pathString))
        node_list = pathString.split("-")
        
        if not path_valid(self.g, node_list):
            self.logger.info("Invalid path, cannot create!")
            return
        if len(node_list) < 4:
            self.logger.info("No hop and single hops paths not supported")
            return;
        src = node_list[0]
        dst = node_list[-1]
        fwd_path, fwd_labels = self._get_path_am(node_list)
        node_list.reverse()
        rev_path, rev_labels = self._get_path_am(node_list)
        self._setup_path(fwd_path)
        self._setup_path(rev_path)
        self.logger.info("Forward flows: {}".format(fwd_path))
        self.logger.info("Reverse flows: {}".format(rev_path))
        # Need to keep enough information about messages sent to switch to
        # create LSP so that we can remove the flow entries latter if asked.
        self.lsps[pathString] = {"fwd": fwd_path, "rev": rev_path,
                                 "fwd_labels": fwd_labels,
                                 "rev_labels": rev_labels}

    def show_all_lsps(self):
        """Displays a list of current LSPs in the network."""
        self.logger.info("Currently {} bidirectional LSPs".format(len(self.lsps)))
        for pathString in self.lsps.keys():
            self.logger.info("\t {}".format(pathString))

    def _setup_path(self, ma_path):
        """ Sends flow mod messages to each switch along a unidirectional path.
            Given a dictionary of matches and action for each switch. """
        for switch, flow in ma_path.iteritems():
            datapath = self.switches[switch]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            # construct flow_mod message and send it.
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 flow["actions"])]
            match = parser.OFPMatch(**flow["match_fields"])
            mod = parser.OFPFlowMod(datapath=datapath, priority=20,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)  # Sends the actual message (finally!)

    def remove_lsp(self, pathString):
        """ Removes forward and reverse LSP for a previously setup path."""
        if pathString not in self.lsps.keys():
            self.logger.info("The path {} does not exist.".format(pathString))
            return
        lsp = self.lsps[pathString]
        self._remove_path(lsp["fwd"])  # Remove flow table entries forward
        self._remove_path(lsp["rev"])  # Remove flow table entries reverse
        #  Remove link labels from our internal network state
        for link, label in lsp["fwd_labels"].iteritems():
            self.link_labels[link].remove(label)
        for link, label in lsp["rev_labels"].iteritems():
            self.link_labels[link].remove(label)
        del self.lsps[pathString]

    def _remove_path(self, ma_path):
        """Creates and send messages to remove flow table entries along a path.
            Given matches and actions for each switch (ma_path)"""
        self.logger.info("Remove path: {}".format(ma_path))
        for switch, flow in ma_path.iteritems():
            datapath = self.switches[switch]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            # construct flow_mod message and send it.
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 flow["actions"])]
            match = parser.OFPMatch(**flow["match_fields"])
            mod = parser.OFPFlowMod(datapath=datapath,
                                    command=ofproto.OFPFC_DELETE,
                                    table_id=ofproto.OFPTT_ALL,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY,
                                    priority=20, match=match, instructions=inst)
            self.logger.info("sending fwd del to switch {} match {} inst {}".format(switch, match, inst))
            datapath.send_msg(mod)

    def _get_path_am(self, node_list):
        """ Figures out the OpenFlow actions and matches needed for each MPLS
            switch along the path including label push, swap, and pop. This
            applies to a valid unidirectional path where the first and last
            nodes in the node_list are hosts, and all other nodes are switches.

            Returns structure (python dictionary) of the matches and actions
            needed for each flow mod message to be sent to each switch along the
            path. Also returns the labels used on each link along the path.
            """
        src = node_list[0]
        dst = node_list[-1]
        labels_used = {}
        switch_flows = OrderedDict()
        g = self.g
        # Prepare first switch here
        datapath = self.switches[node_list[1]]
        ofproto = datapath.ofproto  # Gets the OpenFlow constants
        parser = datapath.ofproto_parser  # Gets the OpenFlow data structures
        # Get the list of labels used on the first MPLS link
        label_list = self.link_labels[(node_list[1], node_list[2])]
        plabel = assign_label(label_list)
        labels_used[(node_list[1], node_list[2])] = plabel
        # Sets up the MPLS forwarding equivalence class for the LSP
        match_fields = {"in_port": get_in_port(g, node_list[0], node_list[1]),
                        "eth_type": 0x800,
                        "ipv4_src": g.node[src]['ip'],
                        "ipv4_dst": g.node[dst]['ip']}
        # The first action is only for debugging purposes and sends the matched
        # packet received to the controller for inspection.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), # Debugging
                   parser.OFPActionPushMpls(),
                   parser.OFPActionSetField(mpls_label=plabel),
                   parser.OFPActionOutput(
                       get_out_port(g, node_list[1], node_list[2]))
                   ]
        switch_flows[node_list[1]] = {"match_fields": match_fields,
                                      "actions": actions}
        # Now the rest of the switches
        for i in range(2, len(node_list) - 1):
            datapath = self.switches[node_list[i]]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match_fields = {
                "in_port": get_in_port(g, node_list[i - 1], node_list[i]),
                "eth_type": 0x8847,
                "mpls_label": plabel
            }
            if i < len(node_list) - 2:
                label_list = self.link_labels[(node_list[i], node_list[i + 1])]
                olabel = assign_label(label_list)
                labels_used[(node_list[i], node_list[i+1])] = olabel
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), # for debugging
                           parser.OFPActionDecMplsTtl(),
                           parser.OFPActionSetField(mpls_label=olabel),
                           parser.OFPActionOutput(get_out_port(g, node_list[i],
                                                               node_list[
                                                                   i + 1]))]
                plabel = olabel # output label becomes the next input label
            else:  # Last switch, we need to pop
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), # for debugging
                           parser.OFPActionPopMpls(),
                           parser.OFPActionOutput(get_out_port(g, node_list[i],
                                                               node_list[
                                                                   i + 1]))]
            switch_flows[node_list[i]] = {"match_fields": match_fields,
                                          "actions": actions}
        return switch_flows, labels_used

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        """ Handles packets sent to the controller.
            Used for debugging."""
        msg = event.msg
        dp = msg.datapath
        # Assumes that datapath ID represents an ascii name
        switchName = dpid_to_name(dp.id)
        packet = Packet(msg.data)
        # self.logger.info("packet: {}".format(msg))
        ether = packet.get_protocol(ryu.lib.packet.ethernet.ethernet)
        
        ethertype = ether.ethertype
        self.logger.info(" Switch {} received packet with ethertype: {}".format(switchName, hex(ethertype)))
        if ethertype == 0x8847:
            mpls = packet.get_protocol(ryu.lib.packet.mpls.mpls)
            self.logger.info("Label: {}, TTL: {}".format(mpls.label, mpls.ttl))
        ipv4 = packet.get_protocol(ryu.lib.packet.ipv4.ipv4)
        if ipv4:
            self.logger.info("IPv4 src: {} dst: {}".format(ipv4.src, ipv4.dst))
        src = ether.src
        if src == '00:00:00:00:00:01': #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
             #print src
             y = self.make_shortest_path()
             #print "last shortest path is **********", self.last_shortest_path
             #if self.last_shortest_path == "H1-S1-S2-S3-S5-H2":
              #  print "before return"
               # return
             #else:
             self.last_shortest_path = y
             #print "last shortest path is **********", self.last_shortest_path
             #self.make_lsp(y)

             #print "return after building the path"

###########################################################################################
    @set_ev_cls(ofp_event.EventOFPPortStatus)
    def port_change(self, event):
        """Gather up some information about the event to print"""
        msg = event.msg
        reason = msg.reason
        dp = msg.datapath
        switch = dp.id
        port_status = msg.desc
        port = port_status.port_no
        name = port_status.name
        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port)
        elif reason == ofproto.OFPPR_DELETE :
            self.logger.info("port deleted %s", port)
            
        elif reason == ofproto.OFPPR_MODIFY and len(self.switches) == 5: #and (port_status.state & 1 != 0):
            self.logger.info("port modified %s", port)
            if port_status.state & 1 == 0:
                  state = "Up"
            else:
                  state = "Down"
                  self.logger.info("Port {} is {}".format(name, state))
                  self.remove_lsp(self.last_shortest_path)
                  #y = self.make_shortest_path()
                  self.last_shortest_path = "H1-S1-S2-S4-S5-H2"
                  #self.make_lsp(self.last_shortest_path)
        else:
            self.logger.info("Illeagal port state %s %s", port, reason)
        self.logger.info("I heard a port status change from switch {} port {} ".format(switch, port))
        # self.logger.info("msg: {}".format(str(msg)))
        
        if port_status.state & 1 == 0:
            state = "Up"
        else:
            state = "Down"
        self.logger.info("Port {} is {}".format(name, state))
        #self.port_events.appendleft(port_status)

    """@set_ev_cls(EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
            link = ev.link
            self.logger.info('link.src.port_no = %d added', link.src.port_no)
            # e.g.)
            # link.src.port_no = 2
    @set_ev_cls(EventLinkDelete, MAIN_DISPATCHER)
    def _link_del_handler(self, ev):
            link = ev.link
            self.logger.info('link.src.port_no = %d deleted', link.src.port_no)
    """
#########################################################################################################################33
def assign_label(label_list):
    """Given the current label list finds a value not in the list,
        adds the value to the list and returns it."""
    # very simplistic algorithm, not good when lots of labels.
    if not label_list:
        new_label = random.randint(1, 1000)
    else:
        new_label = random.randint(1, 1000)
        while new_label in label_list:
            new_label = random.randint(1, 1000)
    label_list.append(new_label)
    return new_label


def path_valid(g, p):
    """ Checks whether the list nodes p is a valid path in g."""
    plen = len(p)
    for i in range(plen - 1):
        if not g.has_edge(p[i], p[i + 1]):  # nice NetworkX graph feature.
            return False
    return True


def get_out_port(g, n1, n2):
    """ Get the output port for n1 to send to n2
        assuming n1 and n2 are connected and ports are assigned to links."""
    # Uses nifty NetworkX graph representation.
    return g[n1][n2]["ports"][n1]


def get_in_port(g, n1, n2):
    """ Get the output port for n2 to receive from n1
        assuming n1 and n2 are connected and ports are assigned to links."""
    # Uses nifty NetworkX graph representation.
    return g[n1][n2]["ports"][n2]


# Takes a int or long and turns it into a hex string without the leading
# 0x or the sometimes trailing L.
def hex_strip(n):
    hexString = hex(n)
    plainString = hexString.split("0x")[
        1]  # Gets rid of the Ox of the hex string
    return plainString.split("L")[0]  # Gets rid of the trailing L if any


def dpid_to_name(dpid):
    tempString = hex_strip(dpid)
    return tempString.decode('hex')


# A small adjustment in port representation from the JSON needed prior
# to converting to NetworkX's internal format.
def in_adjust_ports(gnl_dict):
    """ Converts from ports {"srcPort": num1, "trgPort": num2} format to
        ports {"SrcNodeId": num1, "TrgNodeId": num2} format.
    """
    for link in gnl_dict["links"]:
        if "ports" in link:
            ports = link["ports"]
            new_ports = {
                gnl_dict['nodes'][link["source"]]['id']: ports["srcPort"],
                gnl_dict['nodes'][link["target"]]['id']: ports["trgPort"]}
            link["ports"] = new_ports
    return gnl_dict


if __name__ == "__main__":
    manager.main(args=sys.argv)


