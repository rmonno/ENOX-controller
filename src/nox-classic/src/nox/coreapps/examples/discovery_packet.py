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
from nox.lib.util                                     import extract_flow
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

# XXX FIXME: Insert proper params (in conf file) to change the following values
DEFAULT_TABLE_POLL_TIME = 10
DEFAULT_PORT_POLL_TIME  = 10
DEFAULT_STATS_POLL_TIME = 10

class DiscoveryPacket(Component):
    """ Discovery Packet Class """
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.auth_hosts = []
        self.hosts      = {}
        self.links      = {}
        self.switches   = {}
        self.db_conn    = None
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

        self.w_srv = nxw_utils.WebServConfigParser(DiscoveryPacket.CONFIG_FILE)
        self.url   = "http://%s:%s/" % (str(self.w_srv.host),
                                        str(self.w_srv.port))
        self.hs    = {'content-type': 'application/json'}

    def configure(self, configuration):
        self.register_python_event(nxw_utils.Pck_setFlowEntryEvent.NAME)

        self.register_handler(nxw_utils.Pck_setFlowEntryEvent.NAME,
                              self.pck_setFlowEntry)

    def pck_setFlowEntry(self, event):
        LOG.info("SRC=%s, DST=%s", event.pyevent.ip_src, event.pyevent.ip_dst)
        return CONTINUE

    def packet_in_handler(self, dpid, inport, reason, length, bufid, packet):
        """ Handler for packet_in event """
        assert length is not None
        assert packet is not None
        # checks packet consistency
        if not packet.parsed:
            LOG.warning("Ignoring incomplete packet")
            return CONTINUE

        if packet.type == ethernet.LLDP_TYPE:
            LOG.debug("Ignoring received LLDP packet...")
            return CONTINUE

        # Handle ARP packets
        if packet.type == ethernet.ARP_TYPE:
            LOG.debug("Received ARP packet " + str(packet.find('arp')))
            if not dpid in self.switches:
                LOG.debug("Registering new switch %s" % str(dpid))
                self.switches[dpid] = {}

            self.__do_l2_learning(dpid, inport, packet)
            self.__forward_l2_packet(dpid, inport, packet, packet.arr, bufid)

        LOG.debug("dpid=%s, inport=%s, reason=%s, len=%s, bufid=%s, p=%s",
                  str(dpid), str(inport), str(reason), str(len),
                  str(bufid), str(packet))

        # switch over ethernet type
        if packet.type == ethernet.IP_TYPE:
            ip_addr = packet.find('ipv4')
            LOG.info("IPv4 packet: " + str(ip_addr))
            #  XXX FIXME: Remove the following check in order to be generic...
            if ip_addr.protocol == ipv4.ICMP_PROTOCOL:
                flow    = extract_flow(packet)
                LOG.debug("Sending path request for the following flow: %s" % \
                           str(flow))
                payload = { "dst_port": flow[core.TP_DST],
                            "ip_dst"  : pkt_utils.ip_to_str(ip_addr.dstip),
                            "ip_src"  : pkt_utils.ip_to_str(ip_addr.srcip),
                            "vlan_id" : flow[core.DL_VLAN],
                          }
                req = requests.post(url=self.url + "pckt_host_path",
                                    headers=self.hs, data=json.dumps(payload))
                LOG.debug("URL=%s" % req.url)
                LOG.debug("Response=%s" % req.text)

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
            LOG.debug("Learned MAC '%s' on %d %d " % \
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
                self.send_openflow(dpid, bufid, buf,
                                   openflow.OFPP_FLOOD,
                                   inport)
            else:
                # We know the outport, set up a flow
                LOG.debug("Installing flow for %s" % str(packet))
                flow = extract_flow(packet)
                actions = [[openflow.OFPAT_OUTPUT, [0, prt[0]]]]
                self.install_datapath_flow(dpid, flow, 5,
                                           openflow.OFP_FLOW_PERMANENT,
                                           actions, bufid,
                                           openflow.OFP_DEFAULT_PRIORITY,
                                           inport, buf)
                LOG.info("New installed flow entry for dpid '%s': %s" % \
                          (str(dpid), str(flow)))
        else:
            # haven't learned destination MAC. Flood
            self.send_openflow(dpid, bufid, buf, openflow.OFPP_FLOOD, inport)
            LOG.debug("Flooding received packet...")

    def datapath_join_handler(self, dpid, stats):
        """ Handler for datapath_join event """
        assert (dpid  is not None)
        assert (stats is not None)
        try:
            LOG.debug("Received datapath_join event for DPID '%s'" % str(dpid))

            ports = [ ]
            for p_info in stats['ports']:
                port = { }
                port['port_no']    = p_info['port_no']
                port['hw_addr']    = pkt_utils.mac_to_str(p_info['hw_addr'])
                port['name']       = p_info['name']
                port['config']     = p_info['config']
                port['state']      = p_info['state']
                port['curr']       = p_info['curr']
                port['advertised'] = p_info['advertised']
                port['supported']  = p_info['supported']
                port['peer']       = p_info['peer']
                ports.append(port)

            payload = { "dpid": dpid,
                        "ofp_capabilities": stats['caps'],
                        "ofp_actions": stats['actions'],
                        "buffers": stats['n_bufs'],
                        "tables": stats['n_tables'],
                        "ports": ports,
                      }

            req = requests.post(url=self.url + "pckt_dpid", headers=self.hs,
                                data=json.dumps(payload))
            LOG.debug("URL=%s" % req.url)
            LOG.debug("Response=%s" % req.text)

            return CONTINUE

        except Exception, err:
            LOG.error("Got error in datapath_join handler (%s)" % str(err))
            return CONTINUE

    def datapath_leave_handler(self, dpid):
        """ Handler for datapath_leave event """
        assert (dpid is not None)
        try:
            LOG.debug("Received datapath_leave event for DPID '%s'" % str(dpid))

            req = requests.delete(url=self.url + "pckt_dpid/%s" % str(dpid))
            LOG.debug("URL=%s" % req.url)
            LOG.debug("Response=%s" % req.text)

            return CONTINUE

        except Exception, err:
            LOG.error("Got error in datapath_leave handler (%s)" % str(err))
            return CONTINUE

    def link_key_build(self, from_node, to_node):
        """ Build key for a link """
        assert(from_node is not None)
        assert(to_node is not None)
        key = None
        key = str(from_node) + "TO" + str(to_node)
        return key

    def link_add(self, data):
        """ Add a detected link """
        assert(data is not None)
        link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
        if link_key in self.links:
            LOG.debug("Link '%s' will be updated with received info" % \
                       str(link_key))
            # XXX FIXME: Insert code to update link information

        else:
            LOG.debug("Adding new detected link '%s'..." % str(link_key))
            self.links[link_key] = nxw_utils.Link(link_key,
                                                  data['dpsrc'],
                                                  data['dpdst'])

        self.links[link_key].adjacency_add(int(data['sport']),
                                           int(data['dport']))
        LOG.info("Added a new adjacency for link '%s'" % str(link_key))

        # post inter-switch link
        payload = { "src_dpid"  : data['dpsrc'],
                    "src_portno": data['sport'],
                    "dst_dpid"  : data['dpdst'],
                    "dst_portno": data['dport'],
                  }
        req = requests.post(url=self.url + "pckt_intersw_link",
                            headers=self.hs,
                            data=json.dumps(payload))
        LOG.debug("URL=%s" % req.url)
        LOG.debug("Response=%s" % req.text)

    def link_del(self, data):
        """ Delete links """
        link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
        if link_key in self.links:
            LOG.debug("Link %s will be updated by removing adjancency" % \
                       str(link_key))
        else:
            LOG.error("Cannot find any link with id '%s'" % str(link_key))

        self.links[link_key].adjacency_del(data['sport'],
                                           data['dport'])
        LOG.info("Removed an existing adjacency for link '%s'" % str(link_key))

        payload = { "src_dpid"  : data['dpsrc'],
                    "src_portno": data['sport'],
                    "dst_dpid"  : data['dpdst'],
                    "dst_portno": data['dport'],
                  }

        req = requests.delete(url=self.url + "pckt_intersw_link",
                             headers=self.hs, data=json.dumps(payload))
        LOG.debug("URL=%s" % req.url)
        LOG.debug("Response=%s" % req.text)

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

            return CONTINUE

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

            if auth_data['nwaddr'] == 0:
                LOG.debug("Received auth_event without IP address...")
                # Since Datapath_join event for an OF switch with
                # dladdr could be caught later, we need to store info
                self.hosts[dladdr]          = nxw_utils.Host(dladdr)
                self.hosts[dladdr].rem_dpid = auth_data['datapath_id']
                self.hosts[dladdr].rem_port = auth_data['port']
                return CONTINUE

            if dladdr in self.auth_hosts:
                LOG.debug("Ignoring auth_event (more notifications for" + \
                          " multiple inter-switch links)")
                return CONTINUE
            self.auth_hosts.append(dladdr)

            try:
                # get host (for check if it is already present)
                req = requests.get(url=self.url + "pckt_host/%s" % str(dladdr))
                LOG.debug("URL=%s" % req.url)
                LOG.debug("Response=%s" % req.text)
                if req.text == "204":
                    LOG.debug("Found entry for an host with mac_addr '%s'" %
                               str(dladdr))
                    # XXX FIXME: Add proper checks for host info updating
                    #LOG.debug("Updated host '%s'" % str(dladdr))
                else:
                    LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

            except Exception, err:
                LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

            if auth_data['nwaddr'] != 0:
                # post host
                payload = { "ip_addr"     : host_ipaddr,
                            "mac"         : dladdr,
                            "peer_dpid"   : auth_data['datapath_id'],
                            "peer_portno" : auth_data['port'],
                          }
                req = requests.post(url=self.url + "pckt_host",
                                    headers=self.hs, data=json.dumps(payload))
                LOG.debug("URL=%s" % req.url)
                LOG.debug("Response=%s" % req.text)

            return CONTINUE

        except Exception, err:
            LOG.error("Got errors in host_auth_ev handler ('%s')" % str(err))
            return CONTINUE

    def host_bind_handler(self, data):
        """ Handler for host_binf_event """
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

            try:
                # get host (for check if it is already present)
                req = requests.get(url=self.url + "pckt_host/%s" % str(dladdr))
                LOG.debug("URL=%s" % req.url)
                LOG.debug("Response=%s" % req.text)
                if req.text == "204":
                    LOG.debug("Found entry for an host with mac_addr '%s'" %
                               str(dladdr))
                    # XXX FIXME: Add proper checks for host info updating
                    #LOG.debug("Updated host '%s'" % str(dladdr))
                    return CONTINUE
                else:
                    LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

            except Exception, err:
                LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

            if dladdr in self.hosts:
                LOG.debug("Got host_bind_ev for an host not present in DB yet")

                #post host
                payload = { "ip_addr"     : host_ipaddr,
                            "mac"         : dladdr,
                            "peer_dpid"   : self.hosts[dladdr].rem_dpid,
                            "peer_portno" : self.hosts[dladdr].rem_port,
                          }
                req = requests.post(url=self.url + "pckt_host",
                                    headers=self.hs, data=json.dumps(payload))
                LOG.debug("URL=%s" % req.url)
                LOG.debug("Response=%s" % req.text)
                self.hosts.pop(dladdr)
                if dladdr in self.auth_hosts:
                    self.auth_hosts.remove(dladdr)

            else:
                LOG.debug("Got host_bind_ev for an host already " + \
                          "present in DB")
                LOG.debug("Updating host...")
                # XXX FIXME: Insert code for host update
                LOG.info("Host info updated successfully")

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
            #mac_addresses = self.db_conn.port_get_macs()
            #if dladdr in mac_addresses:
            #    LOG.debug("Ignoring received leave_ev for OF switch...")
            #    self.db_conn.close()
            #    return False

            # Delete host
            payload = { "mac": str(dladdr),
                      }
            req = requests.delete(url=self.url + "pckt_host",
                                  headers=self.hs, data=json.dumps(payload))
            LOG.debug("URL=%s" % str(req.url))
            LOG.debug("Response=%s" % str(req.text))
            LOG.info("Successfully delete host '%s'" % str(dladdr))
            return True

        except Exception, err:
            LOG.error(str(err))
            return False

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
