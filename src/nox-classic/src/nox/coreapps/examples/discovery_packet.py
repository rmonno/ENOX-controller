# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of NOX.
#
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------
""" Discovey Packet NOX application """

from nox.lib.core                                     import *
from nox.lib.packet.ethernet                          import ethernet
from nox.netapps.discovery.pylinkevent                import Link_event
from nox.lib.util                                     import extract_flow
from nox.lib.packet.ipv4                              import ipv4
from nox.netapps.authenticator.pyauth                 import Host_auth_event, \
                                                             Host_bind_event
from nox.netapps.bindings_storage.pybindings_storage  import pybindings_storage
from nox.coreapps.pyrt.pycomponent                    import CONTINUE
from nox.lib.netinet.netinet                          import *

import nox.lib.openflow                 as     openflow
import nox.lib.packet.packet_utils      as     pkt_utils

import sys
import os
import json
import requests
import logging
from   time import time

# update sys python path
KEY = 'nox-classic'
BASEPATH  = os.path.dirname(os.path.abspath(sys.argv[0]))
NOX_INDEX = BASEPATH.find(KEY)

LIBS_PATH = BASEPATH[0:NOX_INDEX-1]
sys.path.insert(0, LIBS_PATH)

IDL_FIND_PATH = BASEPATH[0:NOX_INDEX] + KEY + '/build/src'
for (root, dirs, names) in os.walk(IDL_FIND_PATH):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')

import libs as nxw_utils

LOG = nxw_utils.ColorLog(logging.getLogger('discovery_packet'))


class DiscoveryPacket(Component):
    """ Discovery Packet Class """
    FCONFIG = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.auth_hosts = []
        self.hosts      = {}
        self.links      = {}
        self.switches   = {}
        self.__reasons = {0: "AUTHENTICATION_EVENT",
                          1: "AUTO_AUTHENTICATION",
                          2: "NWADDR_AUTO_ADD",
                          3: "DEAUTHENTICATION_EVENT",
                          4: "NWADDR_AUTO_REMOVE",
                          5: "INTERNAL_LOCATION",
                          6: "BINDING_CHANGE",
                          7: "HARD_TIMEOUT",
                          8: "IDLE_TIMEOUT",
                          9: "SWITCH_LEAVE",
                          10: "LOCATION_LEAVE",
                          11: "HOST_DELETE",
                         }

        self.w_srv = nxw_utils.WebServConfigParser(DiscoveryPacket.FCONFIG)
        self.url   = "http://%s:%s/" % (str(self.w_srv.host),
                                        str(self.w_srv.port))
        self.hs    = {'content-type': 'application/json'}

        discovery_ = nxw_utils.DiscoveryConfigParser(DiscoveryPacket.FCONFIG)
        self.region = discovery_.packet_region
        self.allow_ping = discovery_.allow_ping

    def configure(self, configuration):
        self.register_python_event(nxw_utils.Pckt_flowEntryEvent.NAME)
        self.register_python_event(nxw_utils.Pckt_delFlowEntryEvent.NAME)

    def packet_in_handler(self, dpid, inport, reason, length, bufid, packet):
        """ Handler for packet_in event """
        assert length is not None
        assert packet is not None
        # checks packet consistency
        if not packet.parsed:
            LOG.warning("Ignoring incomplete packet")
            return CONTINUE

        if packet.type == ethernet.LLDP_TYPE:
            return CONTINUE

        dpid_ = str(datapathid.from_host(long(str(dpid))))
        LOG.debug("dpid=%s, inport=%s, reason=%s, len=%s, bufid=%s, p=%s",
                  dpid_, inport, reason, length, str(bufid), str(packet))

        # Handle ARP packets
        if packet.type == ethernet.ARP_TYPE or\
           (packet.type == ethernet.VLAN_TYPE and\
            packet.find('vlan').eth_type == ethernet.ARP_TYPE):
            LOG.debug("Received ARP packet " + str(packet.find('arp')))
            if not dpid_ in self.switches:
                LOG.debug("Registering new switch %s" % dpid_)
                self.switches[dpid_] = {}

            self.__do_l2_learning(dpid_, inport, packet)
            self.__forward_l2_packet(dpid_, inport, packet, packet.arr, bufid)

        # switch over ethernet type
        if packet.type == ethernet.IP_TYPE or\
           (packet.type == ethernet.VLAN_TYPE and\
            packet.find('vlan').eth_type == ethernet.IP_TYPE):
            ip_addr = packet.find('ipv4')
            LOG.info("IPv4 packet: " + str(ip_addr))
            #  XXX FIXME: Remove the following check in order to be generic...
            if ip_addr.protocol == ipv4.ICMP_PROTOCOL:
                flow = extract_flow(packet)
                LOG.debug("Sending path request for flow: %s" % str(flow))
                payload = {"dst_port": flow[core.TP_DST],
                           "src_port": flow[core.TP_SRC],
                           "ip_dst"  : pkt_utils.ip_to_str(ip_addr.dstip),
                           "ip_src"  : pkt_utils.ip_to_str(ip_addr.srcip),
                           "ip_proto": flow[core.NW_PROTO],
                           "vlan_id" : flow[core.DL_VLAN]}

                LOG.debug("Payload=%s" % str(payload))
                if self.allow_ping == 'True':
                    req = requests.post(url=self.url + "pckt_host_path",
                                        headers=self.hs, data=json.dumps(payload))
                    LOG.debug("URL=%s, response=%s", req.url, req.text)

        return CONTINUE

    def __do_l2_learning(self, dpid, inport, packet):
        """ Layer 2 addresses learning """
        assert(dpid   is not None)
        assert(inport is not None)
        assert(packet is not None)
        # learn MAC on incoming port
        srcaddr = packet.src.tostring()
        if ord(srcaddr[0]) & 1:
            return
        if srcaddr in self.switches[dpid]:
            dst = self.switches[dpid][srcaddr]
            if dst[0] != inport:
                LOG.debug("MAC has moved from '%s' to '%s' " % (str(dst),
                                                                str(inport)))
            else:
                return
        else:
            LOG.debug("Learned MAC '%s' on %s %d " % \
                        (pkt_utils.mac_to_str(packet.src),
                         dpid, inport))

        # learn or update timestamp of entry
        self.switches[dpid][srcaddr] = (inport, time(), packet)

    def __forward_l2_packet(self, dpid, inport, packet, buf, bufid):
        """ Layer 2 forwarding """
        dstaddr = packet.dst.tostring()
        if not ord(dstaddr[0]) & 1 and dstaddr in self.switches[dpid]:
            prt = self.switches[dpid][dstaddr]
            if prt[0] == inport:
                LOG.err("**WARNING** Learned port = inport")
                self.send_openflow(long(str(dpid), 16), bufid, buf,
                                   openflow.OFPP_FLOOD,
                                   inport)
            else:
                # We know the outport, set up a flow
                LOG.debug("Installing flow for %s" % str(packet))
                flow = extract_flow(packet)
                actions = [[openflow.OFPAT_OUTPUT, [0, prt[0]]]]
                self.install_datapath_flow(long(str(dpid), 16), flow, 5,
                                           openflow.OFP_FLOW_PERMANENT,
                                           actions, bufid,
                                           openflow.OFP_DEFAULT_PRIORITY,
                                           inport, buf)
                LOG.info("New installed flow entry for dpid '%s': %s" % \
                          (dpid, str(flow)))
        else:
            # haven't learned destination MAC. Flood
            self.send_openflow(long(str(dpid), 16), bufid, buf,
                               openflow.OFPP_FLOOD, inport)
            LOG.debug("Flooding received packet...")

    def datapath_join_handler(self, dpid, stats):
        """ Handler for datapath_join event """
        assert (dpid  is not None)
        assert (stats is not None)

        dpid_ = str(datapathid.from_host(long(str(dpid))))
        LOG.debug("Received datapath_join event for DPID '%s'" % dpid_)

        try:
            ports = []
            for p_info in stats['ports']:
                port = {}
                port['port_no'] = p_info['port_no']
                port['hw_addr'] = pkt_utils.mac_to_str(p_info['hw_addr'])
                port['name'] = p_info['name']
                port['config'] = p_info['config']
                port['state'] = p_info['state']
                port['curr'] = p_info['curr']
                port['advertised'] = p_info['advertised']
                port['supported'] = p_info['supported']
                port['peer'] = p_info['peer']
                ports.append(port)

            payload = {"dpid": dpid_,
                       "region": "packet_" + self.region,
                       "ofp_capabilities": stats['caps'],
                       "ofp_actions": stats['actions'],
                       "buffers": stats['n_bufs'],
                       "tables": stats['n_tables'],
                       "ports": ports}
            req = requests.post(url=self.url + "pckt_dpid", headers=self.hs,
                                data=json.dumps(payload))
            LOG.debug("URL=%s, response(code=%d, content=%s)",
                      req.url, req.status_code, str(req.content))

        except Exception, err:
            LOG.error("Got error in datapath_join handler (%s)" % str(err))

        return CONTINUE

    def datapath_leave_handler(self, dpid):
        """ Handler for datapath_leave event """
        assert (dpid is not None)

        dpid_ = str(datapathid.from_host(long(str(dpid))))
        LOG.debug("Received datapath_leave ev for DPID '%s'" % dpid_)

        try:
            req = requests.delete(url=self.url + "pckt_dpid/%s" % dpid_)
            LOG.debug("URL=%s, response(code=%d, content=%s)",
                      req.url, req.status_code, str(req.content))

        except Exception, err:
            LOG.error("Got error in datapath_leave handler (%s)" % str(err))

        return CONTINUE

    def link_key_build(self, from_node, to_node):
        """ Build key for a link """
        assert(from_node is not None)
        assert(to_node is not None)
        return str(from_node) + "TO" + str(to_node)

    def link_add(self, data):
        """ Add a detected link """
        assert(data is not None)
        dpsrc_ = str(datapathid.from_host(long(str(data['dpsrc']))))
        dpdst_ = str(datapathid.from_host(long(str(data['dpdst']))))

        link_key = self.link_key_build(dpsrc_, dpdst_)
        if link_key in self.links:
            LOG.debug("Link '%s' will be updated with received info", link_key)
            # XXX FIXME: Insert code to update link information

        else:
            LOG.info("Adding new detected link '%s'..." % link_key)
            self.links[link_key] = nxw_utils.Link(link_key, dpsrc_, dpdst_)

        self.links[link_key].adjacency_add(data['sport'], data['dport'])
        LOG.info("Added a new adjacency for link '%s'" % link_key)

        # post inter-switch link
        payload = {"src_dpid"  : dpsrc_,
                   "src_portno": data['sport'],
                   "dst_dpid"  : dpdst_,
                   "dst_portno": data['dport']}
        req = requests.post(url=self.url + "pckt_intersw_link",
                            headers=self.hs, data=json.dumps(payload))
        LOG.debug("URL=%s, response(code=%d, content=%s)",
                  req.url, req.status_code, str(req.content))

    def link_del(self, data):
        """ Delete links """
        assert(data is not None)
        dpsrc_ = str(datapathid.from_host(long(str(data['dpsrc']))))
        dpdst_ = str(datapathid.from_host(long(str(data['dpdst']))))

        link_key = self.link_key_build(dpsrc_, dpdst_)
        if link_key in self.links:
            LOG.debug("Link %s will be updated removing adjancency" % link_key)
        else:
            LOG.error("Cannot find any link with id '%s'" % link_key)

        self.links[link_key].adjacency_del(data['sport'], data['dport'])
        LOG.info("Removed an existing adjacency for link '%s'" % link_key)

        payload = {"src_dpid"  : dpsrc_,
                   "src_portno": data['sport'],
                   "dst_dpid"  : dpdst_,
                   "dst_portno": data['dport']}
        req = requests.delete(url=self.url + "pckt_intersw_link",
                             headers=self.hs, data=json.dumps(payload))
        LOG.debug("URL=%s, response(code=%d, content=%s)",
                  req.url, req.status_code, str(req.content))

    def link_event_handler(self, ingress):
        """ Handler for link_event """
        assert (ingress is not None)
        try:
            link_data = ingress.__dict__
            LOG.debug("Received link event with the following data: %s" % \
                       str(link_data))
            if link_data['action'] == "add":
                LOG.debug("Adding new detected link...")
                self.link_add(link_data)

            elif link_data['action'] == "remove":
                LOG.debug("Removing link...")
                self.link_del(link_data)

            else:
                LOG.error("Cannot handle the following action: '%s'" % \
                           str(link_data['action']))

        except Exception, err:
            LOG.error("Got errors in link_event handler ('%s')" % str(err))

        return CONTINUE

    def host_auth_handler(self, data):
        """ Handler for host_auth_event """
        assert(data is not None)
        try:
            auth_data = data.__dict__
            LOG.info("Received host_auth_ev with the following data: %s" %
                      str(auth_data))
            dladdr      = pkt_utils.mac_to_str(auth_data['dladdr'])
            host_ipaddr = nxw_utils.convert_ipv4_to_str(auth_data['nwaddr'])

            if dladdr in self.hosts:
                LOG.debug("Ignoring auth_event (more notifications for" + \
                          " multiple inter-switch links)")
                return CONTINUE

            r_ = str(datapathid.from_host(long(str(auth_data['datapath_id']))))

            self.hosts[dladdr]          = nxw_utils.Host(dladdr)
            self.hosts[dladdr].rem_dpid = r_
            self.hosts[dladdr].rem_port = auth_data['port']

            if auth_data['nwaddr'] == 0:
                LOG.debug("Received auth_event without IP address...")

            else:
                LOG.debug("Received auth_event with IP address info...")
                self.hosts[dladdr].ip_addr = host_ipaddr
                # post host
                payload = {"ip_addr"     : host_ipaddr,
                           "mac"         : dladdr,
                           "peer_dpid"   : r_,
                           "peer_portno" : auth_data['port']}
                req = requests.post(url=self.url + "pckt_host",
                                    headers=self.hs, data=json.dumps(payload))
                LOG.debug("URL=%s, response(code=%d, content=%s)",
                          req.url, req.status_code, str(req.content))

        except Exception, err:
            LOG.error("Got errors in host_auth_ev handler ('%s')" % str(err))

        return CONTINUE

    def host_bind_handler(self, data):
        """ Handler for host_bind_event """
        assert(data is not None)
        try:
            bind_data   = data.__dict__
            dladdr      = pkt_utils.mac_to_str(bind_data['dladdr'])
            host_ipaddr = nxw_utils.convert_ipv4_to_str(bind_data['nwaddr'])

            # Check reason value
            reason     = int(bind_data['reason'])
            if not reason in self.__reasons:
                LOG.error("Got host_leave event with unsupported reason value")
                return CONTINUE
            reason_str = self.__reasons[reason]
            LOG.info("Received host_bind_ev with reason '%s'" % reason_str)

            # XXX FIXME: Insert mapping for values <--> reason
            if reason > 7:
                if dladdr not in self.hosts:
                    LOG.debug("Ignoring Received host_leave_ev for an host" + \
                              " not present in DB")
                    return CONTINUE
                else:
                    ret = self.__host_leave(dladdr)
                    if not ret:
                        return CONTINUE

            elif (reason < 3 or reason == 5) and (bind_data['nwaddr'] == 0):
                LOG.debug("Ignoring host_bind_ev without IPaddr info")
                return CONTINUE
            elif (reason > 2) and (reason != 5):
                LOG.error("Unsupported reason for host_bind_ev: '%s'" % \
                           reason_str)
                return CONTINUE

            LOG.info("Received host_bind_ev with the following data: %s" % \
                      str(bind_data))

            # Check for presence of the host in stored (internal) hosts
            if dladdr in self.hosts:
                if self.hosts[dladdr].ip_addr is None:
                    LOG.debug("Got host_bind_ev for an host not posted yet")
                    # Post host
                    payload = {"ip_addr"    : host_ipaddr,
                               "mac"        : dladdr,
                               "peer_dpid"  : self.hosts[dladdr].rem_dpid,
                               "peer_portno": self.hosts[dladdr].rem_port}
                    req = requests.post(url=self.url + "pckt_host",
                                        headers=self.hs,
                                        data=json.dumps(payload))
                    LOG.debug("URL=%s, response(code=%d, content=%s)",
                              req.url, req.status_code, str(req.content))
                else:
                    LOG.debug("Got host_bind_ev for an host already posted")

            else:
                LOG.debug("Got host_bind_ev for an host not authenticated yet")

        except Exception, err:
            LOG.error("Got error in host_bind_handler (%s)" % str(err))

        return CONTINUE

    def flow_mod_handler(self, ingress):
        """ Handler for Flow_mod event """
        assert(ingress is not None)
        try:
            data = ingress.__dict__
            LOG.debug("Received flow_mod_ev with the following data: %s" % \
                       str(data))
            return CONTINUE

        except Exception, err:
            LOG.error("Got error in flow_mod_handler (%s)" % str(err))
            return CONTINUE

    def flow_removed_handler(self, ingress):
        """ Handler for Flow_removed event """
        assert(ingress is not None)
        try:
            data = ingress.__dict__
            LOG.debug("Received flow_rem_ev with the following data: %s" % \
                       str(data))
            return CONTINUE

        except Exception, err:
            LOG.error("Got error in flow_removed_handler (%s)" % str(err))
            return CONTINUE

    def __host_leave(self, dladdr):
        """ Handler for host_leave event """
        LOG.debug("Received host_leave_ev for host with MAC %s" % str(dladdr))
        try:
            # XXX FIXME: Add proper check to avoid to send requests for OF
            #            switch
            if not dladdr in self.hosts:
                LOG.warn("Received host_leave_ev for an host already deleted")
                return True

            # Delete host
            payload = { "mac": str(dladdr)}
            req = requests.delete(url=self.url + "pckt_host",
                                  headers=self.hs, data=json.dumps(payload))
            LOG.debug("URL=%s" % str(req.url))
            LOG.debug("Response(code=%d, content=%s)" % (req.status_code,
                                                         str(req.content)))
            if req.status_code == 204:
                LOG.info("Successfully delete host '%s'" % str(dladdr))
                del self.hosts[dladdr]
                return True
            else:
                LOG.error("Cannot delete host with mac address %s" % \
                           str(dladdr))
                return False

        except Exception, err:
            LOG.error(str(err))
            return False

    def flow_entry_handler(self, event):
        """ Handler for flow_entry event """
        LOG.info("Received flow_entry event: %s" % str(event.pyevent))

        if event.pyevent.datapath_in != event.pyevent.datapath_out:
            LOG.debug("Received request for flow_mod with different dpids")
            return CONTINUE

        try:
            attrs = self.__extract_flow_info(event.pyevent)
            actions = [[event.pyevent.action,
                        [0, event.pyevent.dataport_out]]]

            self.install_datapath_flow(long(str(event.pyevent.datapath_in), 16),
                                       attrs,
                                       event.pyevent.idle_timeout,
                                       event.pyevent.hard_timeout,
                                       actions,
                                       None, # buffer
                                       event.pyevent.priority,
                                       event.pyevent.dataport_in,
                                       None) # pkt

            LOG.info("Sent FLOW_MOD to dpid %s: Entry=%s, actions=%s",
                     event.pyevent.datapath_in, str(attrs), str(actions))

        except Exception, err:
            LOG.error("Got error sent FLOW_MOD: %s" % str(err))

        return CONTINUE

    def delete_flow_entry_handler(self, event):
        """ Handler for delete_flow_entry event """
        LOG.info("Received delete_flow_entry event: %s" % str(event.pyevent))

        if event.pyevent.datapath_in != event.pyevent.datapath_out:
            LOG.debug("Received delete-request for flow with different dpids")
            return CONTINUE

        try:
            attrs = self.__extract_flow_info(event.pyevent)
            self.delete_datapath_flow(long(str(event.pyevent.datapath_in), 16),
                                      attrs)

        except Exception, err:
            LOG.error("Got error sent DEL_FLOW_MOD: %s" % str(err))

        return CONTINUE

    def __extract_flow_info(self, flowevent):
        """ Returns flow attributes from the pckt_flowentry_event """
        attrs = {}

        attrs[IN_PORT] = flowevent.dataport_in
        attrs[NW_SRC] = str(flowevent.ip_src)
        attrs[NW_DST] = str(flowevent.ip_dst)

        if flowevent.ether_source:
            attrs[core.DL_SRC] = flowevent.ether_source

        if flowevent.ether_dst:
            attrs[core.DL_DST] = flowevent.ether_dst

        if flowevent.ether_type:
            attrs[core.DL_TYPE] = flowevent.ether_type

        attrs[core.DL_VLAN] = 0xffff # XXX should be written OFP_VLAN_NONE
        attrs[core.DL_VLAN_PCP] = 0

        if flowevent.vlan_id:
            attrs[core.DL_VLAN] = flowevent.vlan_id

        if flowevent.vlan_priority:
            attrs[core.DL_VLAN_PCP] = flowevent.vlan_priority

        attrs[core.NW_SRC] = 0
        attrs[core.NW_DST] = 0
        attrs[core.NW_PROTO] = 0
        attrs[core.TP_SRC] = 0
        attrs[core.TP_DST] = 0

        if flowevent.ip_src:
            attrs[core.NW_SRC] = str(flowevent.ip_src)

        if flowevent.ip_dst:
            attrs[core.NW_DST] = str(flowevent.ip_dst)

        if flowevent.ip_proto:
            attrs[core.NW_PROTO] = flowevent.ip_proto

        if flowevent.tcp_udp_src_port:
            attrs[core.TP_SRC] = flowevent.tcp_udp_src_port

        if flowevent.tcp_udp_dst_port:
            attrs[core.TP_DST] = flowevent.tcp_udp_dst_port

        return attrs

    def install(self):
        """ Install """
        self.register_for_datapath_join(self.datapath_join_handler)
        self.register_for_datapath_leave(self.datapath_leave_handler)
        self.register_for_packet_in(self.packet_in_handler)
        self.register_for_flow_mod(self.flow_mod_handler)
        self.register_for_flow_removed(self.flow_removed_handler)
        self.register_handler(Link_event.static_get_name(),
                              self.link_event_handler)
        self.register_handler(Host_auth_event.static_get_name(),
                              self.host_auth_handler)
        self.register_handler(Host_bind_event.static_get_name(),
                              self.host_bind_handler)
        self.register_handler(nxw_utils.Pckt_flowEntryEvent.NAME,
                              self.flow_entry_handler)
        self.register_handler(nxw_utils.Pckt_delFlowEntryEvent.NAME,
                              self.delete_flow_entry_handler)

        self.bindings = self.resolve(pybindings_storage)
        LOG.debug("%s started..." % str(self.__class__.__name__))

    def getInterface(self):
        """ Get interface """
        return str(DiscoveryPacket)


def getFactory():
    """ Get factory """
    class Factory:
        """ Class Factory """
        def instance(self, ctxt):
            """ Return Topology Manager object """
            return DiscoveryPacket(ctxt)

    return Factory()
