# Ryu API imports
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.controller import Datapath
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib.packet import udp
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

# Python std_lib imports
from collections import defaultdict
from logging import info, debug, exception
from time import sleep

# Local Imports
from union_find import find, make_set, union
from helpers import show_dpid
import file_parsing as fp
import config as cfg

class RoutingGatewayController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoutingGatewayController, self).__init__(*args, **kwargs)

        self.topology_api_app = self

        # Ryu refers to an OpenFlow switch as a 'Datapath'. 
        # As a result of the fact that OpenFlow communication channels are stateful
        # every OpenFlow message must be created and sent via its corresponding 
        # datapath object.
        # datapaths :: switch_dpid -> datapath_object
        self.datapaths = {}

        # Ryu will interpret LLDP's sent by switches, allowing for the discovery
        # of the nw topology in a convenient manner. 
        # adj_mat :: switch_dpid -> switch_dpid -> switch_port_no
        self.adj_mat = defaultdict(dict)

        # Explicitly keeping track of the links as a collection of (DPID x DPID)
        # in order to facilitate spanning tree computation.
        # link_list :: [(dpid_i, dpid_j)]
        self.link_list = []

        # The following structures keep track of the state of ports on a per
        # switch basis. 
        #
        # active_ports : Ports that currently compose the MST.
        # available_ports : All ports on the switch
        # link_ports : ports that connect the switch to other switches in the core
         
        # active_ports :: switch_dpid -> [active_ports]
        self.active_ports = defaultdict(list)

        # available_ports :: switch_dpid -> [available_ports]
        self.available_ports = defaultdict(list)

        # link_ports :: switch_dpid -> [link_ports]
        self.link_ports = defaultdict(list)

        # mac_to_port :: switch_dpid -> mac_addr -> output_port
        self.mac_to_port = defaultdict(dict)

        # Assign a known port number for the test traffic.
        # TEST_TRAFFIC_DEST_PORT :: Int
        self.TEST_TRAFFIC_DEST_PORT = 50000

        # CONTROLLER_SW_PORT :: Int
        self.CONTROLLER_SW_PORT = 4294967294

    # The set_ev_cls decorator takes two parameters, the event type to register
    # for and the connection state that the channel must be in for the event 
    # to be raised. 
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dp = ev.switch.dp
        info('Discovered switch with DPID: %s' % dp.id)
        if dp.id not in self.datapaths.iterkeys():
            self.datapaths[dp.id] = dp
        self.available_ports[dp.id] = map(lambda of_port : of_port.port_no, dp.ports.values())
        predicate = lambda p_num : not p_num == self.CONTROLLER_SW_PORT
        self.available_ports[dp.id] = filter(predicate, self.available_ports[dp.id])
        self.install_default_flowmod(dp)

    def install_default_flowmod(self, sw):
        parser = sw.ofproto_parser
        proto = sw.ofproto
        of_act_list = [parser.OFPActionOutput(proto.OFPP_CONTROLLER, proto.OFPCML_NO_BUFFER)]
        of_match = parser.OFPMatch()
        self.install_flow(sw, of_match, of_act_list)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        dp = ev.switch.dp
        info('Switch with DPID: %s has left the network.' % dp.id)
        try: 
            del self.datapaths[dp.id]
        except KeyError:
            pass

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src_sw = ev.link.src
        dst_sw = ev.link.dst
        info('Discovered link between %s:%d and %s:%d' % (show_dpid(src_sw.dpid), src_sw.port_no, show_dpid(dst_sw.dpid), dst_sw.port_no))
        self.update_link_state(src_sw, dst_sw)
        host_ports = self.compute_host_ports()
        mst = self.compute_mst()
        self.active_ports = self.compute_active_ports(mst, host_ports)
        info('Active ports: ')
        info(self.active_ports)

    def update_link_state(self, src_sw, dst_sw):
        self.adj_mat[src_sw.dpid][dst_sw.dpid] = src_sw.port_no
        self.adj_mat[dst_sw.dpid][src_sw.dpid] = dst_sw.port_no
        self.link_list.append((src_sw.dpid, dst_sw.dpid))
        self.link_ports[src_sw.dpid].append(src_sw.port_no)
        self.link_ports[dst_sw.dpid].append(dst_sw.port_no)

    def compute_host_ports(self):
        available_ports = self.available_ports
        link_ports = self.link_ports
        datapaths = self.datapaths
        host_ports = { dpid : set(available_ports[dpid]) - set(link_ports[dpid]) for dpid in datapaths.iterkeys() }
        return host_ports

    def compute_active_ports(self, mst, host_ports): 
        active_ports = defaultdict(list)
        for n1, n2 in mst:
            try: 
                active_ports[n1].append(self.adj_mat[n1][n2])
                active_ports[n2].append(self.adj_mat[n2][n1])
            except KeyError as key_ex:
                exception(key_ex)

        active_ports = { dpid : set(active_ports[dpid]).union(host_ports[dpid]) for dpid in self.datapaths.iterkeys() }
        return active_ports

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        src_sw = ev.link.src
        dst_sw = ev.link.dst
        info('Removed link between %s and %s' % (src_sw.dpid, dst_sw.dpid))
        try:
            del self.adj_mat[src_sw.dpid][dst_sw.dpid]
            del self.adj_mat[dst_sw.dpid][src_sw.dpid]
        except KeyError:
            pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        of_msg = ev.msg
        src_sw = of_msg.datapath
        ofp_parser = src_sw.ofproto_parser
        
        in_pkt = packet.Packet(of_msg.data)
        eth_frame = in_pkt.get_protocol(ethernet.ethernet)

        # As a result of Ryu's link detection, all LLDP packets are forwarded
        # to the controller.
        if eth_frame.ethertype == ether_types.ETH_TYPE_LLDP:
            return 

        # For now, only route ipv4 traffic
        if eth_frame.ethertype == ether_types.ETH_TYPE_IPV6:
            ipv6_match = ofp_parser.OFPMatch(eth_type=eth_frame.ethertype)
            self.install_flow(src_sw, ipv6_match)
            return

        ip_pkt = in_pkt.get_protocol(ipv4.ipv4)
        udp_pkt = in_pkt.get_protocol(udp.udp)

        if ip_pkt:
            info('Received IP Packet. Src: %s, Dst: %s.' % (ip_pkt.src,
                ip_pkt.dst))
        
        # The changes will need to occur in this branch, since routes
        # will be statically installed, we can assume that any traffic
        # that reaches this switch with udp_dst ==
        # self.TEST_TRAFFIC_PORT must be destined for the locally
        # connected host
        # if ip_pkt and udp_pkt and udp_pkt.dst_port == self.TEST_TRAFFIC_DEST_PORT and int(ip_pkt.src.split('.')[-1]) == src_sw.id:
        #     info('Switch %d received test traffic on port: %d' % (src_sw.id, of_msg.match['in_port']))
        #     (out_port, dst_sw_dpid) = self.route_test_traffic(src_sw, of_msg, ip_pkt, udp_pkt)
        #     dst_sw = self.datapaths[dst_sw_dpid]
        #     of_act = [dst_sw.ofproto_parser.OFPActionOutput(dst_sw.ofproto.OFPP_NORMAL)]
        #     self.inject_packet(dst_sw, of_msg, of_act)
        #     return

        # No longer need the condition that checks the last quartet of
        # the L3 addr since we assume precomputed and installed routes
        # for test traffic.
        # if udp_pkt and udp_pkt.dst_port == self.TEST_TRAFFIC_DEST_PORT:
        #    info('switch %d received test traffic on sw_port: %d' %
        #            (src_sw.id, of_msg.match['in_port']))

        #    # Craft an ARP request for the dst L3 address of the packet. 
        #    arp_req = arp.arp(src_mac=src_sw.id, src_ip=ip_pkt.src_ip,
        #            dst_ip=ip_pkt.dst_ip)
        #    self.broadcast_frame(src_sw, arp_req)

         


        self.switch_l2_packet(src_sw, of_msg, eth_frame)

    def route_test_traffic(self, src_sw, of_msg, ip_pkt, udp_pkt):
        dst_ip = ip_pkt.dst
        dst_dpid = int(dst_ip.split('.')[-1])
        shortest_paths = self.k_shortest_paths(src_sw.id, dst_dpid, 3)
        for ds_val, path in enumerate(shortest_paths, 0):
            while len(path) > 1:
                current = path[0]
                next_hop = path[1]
                output_port = self.adj_mat[current][next_hop]
                current_sw = self.datapaths[current]
                parser = current_sw.ofproto_parser
                of_act = [parser.OFPActionOutput(output_port)]
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_dscp=ds_val + 1
                )
                self.install_flow(current_sw, match, of_act, priority=50)
                path = [n_i for i, n_i in enumerate(path) if i > 0]

        ds_val = ip_pkt.tos >> 2
        next_hop = src_sw.id
        if len(shortest_paths) < ds_val:
            next_hop = shortest_paths[0][1]
        else:
            next_hop = shortest_paths[ds_val - 1][1]
        return (self.adj_mat[src_sw.id][next_hop], dst_dpid)

    def k_shortest_paths(self, src_dpid, dst_dpid, k):
        paths = []
        count = defaultdict(int)
        h = []
        h.append(([src_dpid], 0))
        while len(h) > 0:
            (p_u, cost) = min(h, key = lambda (_, cost) : cost)
            h.remove((p_u, cost))
            count[p_u[-1]] = count[p_u[-1]] + 1
            if p_u[-1] == dst_dpid:
                paths.append(p_u)
            if count[p_u[-1]] <= k:
                for adj_node in self.adj_mat[p_u[-1]].iterkeys():
                    if adj_node not in p_u:
                        p_v = p_u + [adj_node]
                        h.append((p_v, cost + 1))
        return paths
        
    def switch_l2_packet(self, src_sw, of_msg, eth_frame):
        in_port = of_msg.match['in_port']
        self.mac_to_port[src_sw.id][eth_frame.src] = in_port
        if eth_frame.dst not in self.mac_to_port[src_sw.id].iterkeys():
            self.broadcast_frame(src_sw, of_msg)
        else:
            ofp_parser = src_sw.ofproto_parser
            of_act_list = [ofp_parser.OFPActionOutput(self.mac_to_port[src_sw.id][eth_frame.dst])]
            of_match = ofp_parser.OFPMatch(
                eth_src=eth_frame.src,
                eth_dst=eth_frame.dst
            )
            self.inject_packet(src_sw, of_msg, of_act_list)
            self.install_flow(src_sw, of_match, of_act_list, 5, idle_timeout=120)

    def broadcast_frame(self, sw, of_msg):
        parser = sw.ofproto_parser
        port_list = self.active_ports[sw.id]
        in_port = of_msg.match['in_port']
        ofp_act_list = [
            parser.OFPActionOutput(port_no) 
            for port_no in port_list if port_no is not in_port
            ]
        self.inject_packet(sw, of_msg, ofp_act_list)
    
    def inject_packet(self, sw, of_msg, action_list):
        data = None
        ofproto = sw.ofproto
        if of_msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = of_msg.data
        inject_pkt = sw.ofproto_parser.OFPPacketOut(
            datapath=sw, buffer_id=of_msg.buffer_id, 
            in_port=of_msg.match['in_port'], actions=action_list,
            data=data
        )
        sw.send_msg(inject_pkt)

    def compute_mst(self):
        node_set = [make_set(i) for i in self.datapaths.iterkeys()]
        mst = []
        match_node = lambda ln : next(n for n in node_set if n.id == ln)
        link_set = [
            (match_node(ln1), match_node(ln2))
            for (ln1, ln2) in self.link_list
        ]
        for n1, n2 in link_set:
            if find(n1) is not find(n2):
                mst.append((n1, n2))
                union(n1, n2)
        pretty_mst = [(n1.id, n2.id) for (n1, n2) in mst]
        return pretty_mst

    def install_flow(self, switch, match, actions=[], priority=1, buffer_id=None, idle_timeout=0):
        info('Adding flow to switch with DPID: %s' % switch.id)
        of_proto = switch.ofproto
        ofp_parser = switch.ofproto_parser

        instrs = [ofp_parser.OFPInstructionActions(of_proto.OFPIT_APPLY_ACTIONS,
                    actions)]
        if buffer_id:
            flow_mod = ofp_parser.OFPFlowMod(datapath=switch, buffer_id = buffer_id,
                                             priority=priority, match=match,
                                             instructions=instrs, 
                                             idle_timeout=idle_timeout,
                                             table_id=100)
        else:
            flow_mod = ofp_parser.OFPFlowMod(datapath=switch, priority=priority,
                                             match=match, instructions=instrs, 
                                             idle_timeout=idle_timeout,
                                             table_id=100)
        switch.send_msg(flow_mod)
