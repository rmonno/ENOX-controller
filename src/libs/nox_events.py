# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Events declaration for NOX application """

from nox.lib.core import pyevent


class Pck_setFlowEntryEvent(pyevent):
    NAME = 'pck_set_flow_entry_event'

    def __init__(self, ip_src, ip_dst):
        self.ip_src = ip_src
        self.ip_dst = ip_dst

    def describe(self):
        return pyevent(Pck_setFlowEntryEvent.NAME, self)


class Pckt_flowEntryEvent(pyevent):
    NAME = 'pckt_flow_entry_event'

    def __init__(self, dp_in, port_in, dp_out, port_out,
                 ip_src=None, ip_dst=None, tcp_dport=0xffff, tcp_sport=0xffff,
                 ip_tos=None, ip_proto=None,
                 vprio=None, vid=None, etype=None, esrc=None, edst=None,
                 table=None, action=None, idle=None, hard=None, prio=None,
                 cookie=None, src_wild=None, dst_wild=None):
        self.datapath_in = dp_in
        self.dataport_in = port_in
        self.datapath_out = dp_out
        self.dataport_out = port_out
        self.ether_source = esrc
        self.ether_dst = edst
        self.ether_type = etype
        self.vlan_id = vid
        self.vlan_priority = vprio
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_proto = ip_proto
        self.ip_tos_bits = ip_tos
        self.tcp_udp_src_port = tcp_sport if tcp_sport != 0xffff else None
        self.tcp_udp_dst_port = tcp_dport if tcp_dport != 0xffff else None
        self.table_id = table
        self.action = action
        self.idle_timeout = idle
        self.hard_timeout = hard
        self.priority = prio
        self.cookie = cookie
        self.ip_src_wild = src_wild
        self.ip_dst_wild = dst_wild

    def describe(self):
        return pyevent(Pckt_flowEntryEvent.NAME, self)

    def __str__(self):
        msg = "dp_in=%s,dport_in=%s,dp_out=%s,dport_out=%s,eth_src=%s,"
        msg += "eth_dst=%s,etype=%s,vid=%s,vprio=%s,ip_src=%s,ip_dst=%s,"
        msg += "ip_proto=%s,ip_tos=%s,l4_port_src=%s,l4_port_dst=%s,table=%s,"
        msg += "action=%s,idle=%s,hard=%s,prio=%s,cookie=%s,"
        msg += "src_wild=%s,dst_wild=%s"
        val = (self.datapath_in, self.dataport_in, self.datapath_out,
               self.dataport_out, self.ether_source, self.ether_dst,
               self.ether_type, self.vlan_id, self.vlan_priority, self.ip_src,
               self.ip_dst, self.ip_proto, self.ip_tos_bits,
               self.tcp_udp_src_port, self.tcp_udp_dst_port, self.table_id,
               self.action, self.idle_timeout, self.hard_timeout,
               self.priority, self.cookie, self.ip_src_wild, self.ip_dst_wild)

        return msg % val


class Pckt_delFlowEntryEvent(pyevent):
    NAME = 'pckt_delete_flow_entry_event'

    def __init__(self, dp_in, port_in, dp_out, port_out,
                 ip_src=None, ip_dst=None, tcp_dport=0xffff, tcp_sport=0xffff,
                 ip_proto=0xffff, vid=None):
        self.datapath_in = dp_in
        self.dataport_in = port_in
        self.datapath_out = dp_out
        self.dataport_out = port_out
        self.vlan_id = vid
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_proto = ip_proto if ip_proto != 0xffff else None
        self.tcp_udp_src_port = tcp_sport if tcp_sport != 0xffff else None
        self.tcp_udp_dst_port = tcp_dport if tcp_dport != 0xffff else None
        self.ether_source = None
        self.ether_dst = None
        self.ether_type = None
        self.vlan_priority = None

    def describe(self):
        return pyevent(Pckt_delFlowEntryEvent.NAME, self)

    def __str__(self):
        msg = "dp_in=%s,dport_in=%s,dp_out=%s,dport_out=%s,vid=%s,"
        msg += "ip_src=%s,ip_dst=%s,ip_proto=%s,l4_port_src=%s,l4_port_dst=%s"
        val = (self.datapath_in, self.dataport_in, self.datapath_out,
               self.dataport_out, self.vlan_id, self.ip_src, self.ip_dst,
               self.ip_proto, self.tcp_udp_src_port, self.tcp_udp_dst_port)

        return msg % val


class Circuit_flowEntryEvent(pyevent):
    NAME = 'circuit_flow_entry_event'

    def __init__(self, flow_id, dpid, port_in, port_out, hard, bandwidth,
                 command, wild=None):
        self.flow_id = flow_id
        self.dpid = dpid
        self.port_in = port_in
        self.port_out = port_out
        self.hard_timeout = hard
        self.bandwidth = bandwidth
        self.command = command
        self.wild = wild

    def describe(self):
        return pyevent(Circuit_flowEntryEvent.NAME, self)

    def __str__(self):
        msg = "flow_id=%s,dpid=%s,port_in=%s,port_out=%s,hard_timeout=%s,"
        msg += "bandwidth=%s,command=%s,wildcards=%s"
        val = (self.flow_id, self.dpid, self.port_in, self.port_out,
               self.hard_timeout, self.bandwidth, self.command, self.wild)

        return msg % val
