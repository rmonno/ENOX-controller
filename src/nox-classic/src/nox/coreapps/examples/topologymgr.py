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
""" Topology Manager NOX application """

from nox.lib.core                                     import Component, \
                                                             IN_PORT, \
                                                             NW_SRC, \
                                                             NW_DST
from nox.lib.packet.ethernet                          import ethernet
from nox.lib.packet.ipv4                              import ipv4
from nox.lib.util                                     import extract_flow
from nox.netapps.discovery.pylinkevent                import Link_event
from nox.netapps.authenticator.pyauth                 import Host_auth_event, \
                                                             Host_bind_event
from nox.netapps.bindings_storage.pybindings_storage  import pybindings_storage
from nox.coreapps.pyrt.pycomponent                    import CONTINUE
from nox.lib.netinet.netinet                          import *

import nox.lib.openflow                 as     openflow
import nox.lib.packet.packet_utils      as     pkt_utils

import sys
import os
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

LOG = nxw_utils.ColorLog(logging.getLogger('topologymgr'))


class TopologyMgr(Component):
    """ Topology Manager Class """
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.auth_hosts = []
        self.hosts      = {}
        self.links      = {}
        self.switches   = {}
        self.db_conn    = None
        self.fpce       = nxw_utils.FPCE()
        self.ior        = None
        self.ior_topo   = False
        self.ior_rout   = False
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

        conf = nxw_utils.NoxConfigParser(TopologyMgr.CONFIG_FILE)
        self.pce_client = nxw_utils.PCEClient(conf.address,
                                              conf.port,
                                              int(conf.size))
        self.pce_client.create()

    def ior_del(self):
        """ Delete stored IOR """
        if self.ior is None:
            LOG.error("Cannot delete IOR (no stored IOR)")
        else:
            self.ior = None

    def mysql_enable(self,
                     host    = "localhost",
                     user    = "topology_user",
                     pwd     = "topology_pwd",
                     db_name = "topology_ofc_db"):
        """ Enable MYSQL Database """
        self.db_conn = nxw_utils.TopologyOFCManager(host,
                                                    user,
                                                    pwd,
                                                    db_name,
                                                    LOG)
        LOG.debug("Enabled connection with Topology DB (%s, %s, %s)",
                  host, user, db_name)

    def pce_topology_enable(self):
        """ Enable PCE-topology """
        LOG.debug("Retrieving IOR for topology requests")
        try:
            resp = self.pce_client.send_msg("topology")
            if resp is None:
                self.ior_topo = False
            else:
                LOG.debug("Received the following response: %s", str(resp))
                parsed_resp = self.pce_client.decode_requests(resp)
                if not parsed_resp:
                    LOG.error("Got an error in response parsing...")
                    self.ior_topo = False
                else:
                    LOG.info("Received the following IOR: '%s'",
                             str(parsed_resp))
                    self.fpce.ior_topology_add(parsed_resp)
                    self.ior_topo = True

        except Exception as err:
            LOG.error("Pce Topology Failure: %s", str(err))
            self.ior_topo = False

        return self.ior_topo

    def pce_routing_enable(self):
        """ Enable F-PCE routing """
        LOG.debug("Retrieving IOR for routing requests")
        try:
            resp = self.pce_client.send_msg("routing")
            if resp is None:
                self.ior_rout = False
            else:
                LOG.debug("Received the following response: %s", str(resp))
                parsed_resp = self.pce_client.decode_requests(resp)
                if not parsed_resp:
                    LOG.error("Got an error in response parsing...")
                    self.ior_rout = False
                else:
                    LOG.info("Received the following IOR: '%s'",
                             str(parsed_resp))
                    self.fpce.ior_routing_add(parsed_resp)
                    self.ior_rout = True

        except Exception as err:
            LOG.error("Pce Routing Failure: %s", str(err))
            self.ior_rout = False

        return self.ior_rout

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
            # XXX FIXME: Remove the following check in order to be generic...
            if ip_addr.protocol == ipv4.ICMP_PROTOCOL:
                self.__resolve_path(pkt_utils.ip_to_str(ip_addr.srcip),
                                    pkt_utils.ip_to_str(ip_addr.dstip),
                                    packet)

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

        # insert values into topology-db
        try:
            # connect and open transaction
            self.db_conn.open_transaction()

            # datapath_insert
            self.db_conn.datapath_insert(d_id=dpid,
                                         d_name="ofswitch-" + str(dpid),
                                         caps=stats['caps'],
                                         actions=stats['actions'],
                                         buffers=stats['n_bufs'],
                                         tables=stats['n_tables'])
            # port_insert
            for p_info in stats['ports']:
                mac = pkt_utils.mac_to_str(p_info['hw_addr'])
                self.db_conn.port_insert(d_id=dpid,
                                         port_no=p_info['port_no'],
                                         hw_addr=mac,
                                         name=p_info['name'],
                                         config=p_info['config'],
                                         state=p_info['state'],
                                         curr=p_info['curr'],
                                         advertised=p_info['advertised'],
                                         supported=p_info['supported'],
                                         peer=p_info['peer'])
            # commit transaction
            self.db_conn.commit()
            LOG.debug("Successfull committed information!")

        except nxw_utils.DBException as err:
            LOG.error(str(err))
            # rollback transaction
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

        # check ior-dispatcher on pce node
        if not self.ior_topo and not self.pce_topology_enable():
            LOG.error("Unable to contact ior-dispatcher on PCE node!")
            return CONTINUE

        # get datapath and ports index from topology-db
        nodes = []
        try:
            for p_info in stats['ports']:
                node = self.node_get_frompidport(dpid, p_info['port_no'])
                nodes.append(node)

        except nxw_utils.DBException as err:
            LOG.error(str(err))

        except Exception, err:
            LOG.error(str(err))

        # update flow-pce topology (nodes)
        LOG.debug("Nodes=%s", nodes)
        for node in nodes:
            self.fpce.add_node_from_string(node)

        # update flow-pce topology (links)
        for node in nodes:
            others = [n for n in nodes if n != node]

            for oth in others:
                self.fpce.add_link_from_strings(node, oth)

        return CONTINUE

    def datapath_leave_handler(self, dpid):
        """ Handler for datapath_leave event """
        assert (dpid is not None)

        # check ior-dispatcher on pce node
        if not self.ior_topo and not self.pce_topology_enable():
            LOG.error("Unable to contact ior-dispatcher on PCE node!")
        else:
            # get nodes and links from topology-db
            (nodes, links, hosts) = self.__datapath_leave_db_actions(dpid)

            # update flow-pce topology (delete links)
            LOG.info("DataPath_leave nodes=%s", nodes)
            for node in nodes:
                others = [n for n in nodes if n != node]

                for oth in others:
                    self.fpce.del_link_from_strings(node, oth)

            # update flow-pce topology (delete interswitch links)
            LOG.info("DataPath_leave links=%s", links)
            for src, dst in links:
                self.fpce.del_link_from_strings(src, dst)
                self.fpce.del_link_from_strings(dst, src)

            # update flow-pce topology (delete nodes)
            for node in nodes:
                self.fpce.del_node_from_string(node)

            # update flow-pce topology (delete nodes)
            LOG.info("DataPath_leave hosts=%s", hosts)
            for host in hosts:
                self.fpce.del_node_from_string(host)

        # delete values into topology-db
        try:
            self.db_conn.open_transaction()

            # datapath_delete
            # (automatically delete all ports and hosts associated with it)
            self.db_conn.datapath_delete(d_id=dpid)

            self.db_conn.commit()
            LOG.debug("Successfull committed information!")

        except nxw_utils.DBException as err:
            LOG.error(str(err))
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

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
        try:
            link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
            if link_key in self.links:
                LOG.debug("Link '%s' will be updated with received info" % \
                           str(link_key))
            else:
                LOG.debug("Adding new detected link '%s'..." % str(link_key))
                self.links[link_key] = nxw_utils.Link(link_key,
                                                      data['dpsrc'],
                                                      data['dpdst'])

            self.links[link_key].adjacency_add(int(data['sport']),
                                               int(data['dport']))
            LOG.info("Added a new adjacency for link '%s'" % str(link_key))

            # check ior-dispatcher on pce node
            if not self.ior_topo and not self.pce_topology_enable():
                LOG.error("Unable to contact ior-dispatcher on PCE node!")
                return CONTINUE

            nodes = []
            try:
                src_node = self.node_get_frompidport(data['dpsrc'],
                                                     data['sport'])
                nodes.append(src_node)

                dst_node = self.node_get_frompidport(data['dpdst'],
                                                     data['dport'])
                nodes.append(dst_node)

            except nxw_utils.DBException as err:
                LOG.error(str(err))

            except Exception, err:
                LOG.error(str(err))

            for node in nodes:
                others = [n for n in nodes if n != node]

                for oth in others:
                    self.fpce.add_link_from_strings(node, oth)

        except Exception, err:
            LOG.error("Cannot add link ('%s')" % str(err))

        # update inter-switch value into topology-db
        try:
            # connect and open transaction
            self.db_conn.open_transaction()

            # links insert
            self.db_conn.link_insert(src_dpid=data['dpsrc'],
                                     src_pno=data['sport'],
                                     dst_dpid=data['dpdst'],
                                     dst_pno=data['dport'])
            # commit transaction
            self.db_conn.commit()

        except nxw_utils.DBException as err:
            LOG.error(str(err))
            # rollback transaction
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

    def link_del(self, data):
        """ Delete links """
        assert(data is not None)
        try:
            link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
            if link_key in self.links:
                LOG.debug("Link %s will be updated by removing adjancency" % \
                           str(link_key))
            else:
                LOG.error("Cannot find any link with id '%s'" % str(link_key))

            self.links[link_key].adjacency_del(data['sport'],
                                               data['dport'])
            LOG.info("Removed an existing adjacency for link '%s'" % \
                      str(link_key))

        except Exception, err:
            LOG.error("Cannot remove info for link ('%s')" % str(err))

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

        LOG.debug("Link_event handled successfully...")
        link_key = self.link_key_build(link_data['dpsrc'], link_data['dpdst'])
        LOG.debug(str(self.links[link_key]))
        return CONTINUE

    def __host_insert_db(self, mac_addr, dpid, port, ip_addr = None):
        """ Insert host DB entries """
        try:
            # Host_insert
            self.db_conn.host_insert(mac_addr, dpid, port, ip_addr)

            # commit transaction
            self.db_conn.commit()
            LOG.debug("Successfully committed information!")

        except nxw_utils.DBException:
            self.db_conn.rollback()
            raise

    def __host_update_db(self, mac_addr, ip_addr):
        """ Update host DB entries """
        try:
            # connect and open transaction
            self.db_conn.open_transaction()
            # Host_insert
            self.db_conn.host_update(mac_addr, ip_addr)
            # commit transaction
            self.db_conn.commit()
            LOG.debug("Successfully committed information!")
        except nxw_utils.DBException:
            self.db_conn.rollback()
        finally:
            self.db_conn.close()

    def __host_leave(self, dladdr):
        """ Handler for host_leave event """
        LOG.debug("Received host_leave_ev for host with MAC %s" % str(dladdr))
        try:
            self.db_conn.open_transaction()
            try:
                mac_addresses = self.db_conn.port_get_macs()
                if dladdr in mac_addresses:
                    LOG.debug("Ignoring received leave_ev for OF switch...")
                    self.db_conn.close()
                    return False
            except Exception:
                LOG.debug("Received leave_ev for a MAC not present in DB")
                return False

            host  = self.db_conn.host_get_ipaddr(dladdr)
            nodes = [host]
            dpid  = self.db_conn.host_get_dpid(dladdr)
            port  = self.db_conn.host_get_inport(dladdr)
            didx  = self.db_conn.datapath_get_index(dpid)
            pidx  = self.db_conn.port_get_index(dpid, port)
            node  = nxw_utils.createNodeIPv4(didx, pidx)
            nodes.append(node)

            # update flow-pce topology (remove links)
            for node in nodes:
                others = [n for n in nodes if n != node]
                for oth in others:
                    self.fpce.del_link_from_strings(node, oth)

            self.fpce.del_node_from_string(host)

            # Delete hosts from DB
            host_idx = self.db_conn.host_get_index(dladdr)
            self.db_conn.host_delete(host_idx)
            self.db_conn.commit()
            LOG.debug("Successfully delete host '%s' from DB!" % str(dladdr))

        except nxw_utils.DBException as err:
            self.db_conn.rollback()
            return False
        except Exception, err:
            LOG.error(str(err))
            return False
        finally:
            self.db_conn.close()

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
                try:
                    host_idx = None
                    host_idx = self.db_conn.host_get_index(dladdr)
                    LOG.debug("Host with mac_addr '%s' has index '%s'" % \
                               (str(dladdr), str(host_idx)))
                except Exception, err:
                    LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

                if dladdr in self.hosts:
                    LOG.debug("Got host_bind_ev for an host not present " + \
                              "in DB yet")

                    # Insert Host info into DB
                    self.__host_insert_db(dladdr,
                                          self.hosts[dladdr].rem_dpid,
                                          self.hosts[dladdr].rem_port,
                                          host_ipaddr)
                    LOG.info("Added host '%s' into DB" % str(dladdr))
                    self.hosts.pop(dladdr)
                    # XXX FIXME Remove auth_hosts (maintain only self.hosts)
                    self.auth_hosts.pop(self.auth_hosts.index(dladdr))

                else:
                    LOG.debug("Got host_bind_ev for an host already " + \
                              "present in DB")
                    self.db_conn.open_transaction()
                    LOG.debug("Updating host info in DB...")
                    self.db_conn.host_update(dladdr, host_ipaddr)
                    self.db_conn.commit()
                    LOG.info("Host info updated successfully")
            except nxw_utils.DBException:
                self.db_conn.rollback()
            finally:
                self.db_conn.close()


            # check ior-dispatcher on pce node
            if not self.ior_topo and not self.pce_topology_enable():
                LOG.error("Unable to contact ior-dispatcher on PCE node!")
                return CONTINUE

            nodes = [host_ipaddr]
            # Update flow-pce topology (hosts)
            LOG.debug("Hosts=%s", nodes)
            self.fpce.add_node_from_string(host_ipaddr)
            # update flow-pce topology (links between DPID and host)
            try:
                # connect and open transaction
                self.db_conn.open_transaction()
                # Host_insert
                dpid    = self.db_conn.host_get_dpid(dladdr)
                in_port = self.db_conn.host_get_inport(dladdr)
            except nxw_utils.DBException as err:
                self.db_conn.rollback()
            finally:
                self.db_conn.close()

            try:
                node = self.node_get_frompidport(dpid, in_port)
                nodes.append(node)
            except nxw_utils.DBException as err:
                LOG.error(str(err))
            except Exception, err:
                LOG.error(str(err))

            # update flow-pce topology (links)
            for node in nodes:
                others = [n for n in nodes if n != node]
                for oth in others:
                    self.fpce.add_link_from_strings(node, oth)

            return CONTINUE

        except Exception, err:
            LOG.error("Got error in host_bind_event handler ('%s')" % str(err))

    def host_auth_handler(self, data):
        """ Handler for host_auth_event """
        assert(data is not None)
        try:
            auth_data = data.__dict__
            LOG.info("Received host_auth_ev with the following data: %s" %
                      str(auth_data))
            dladdr      = pkt_utils.mac_to_str(auth_data['dladdr'])
            host_ipaddr = nxw_utils.convert_ipv4_to_str(auth_data['nwaddr'])
            try:
                # connect and open transaction
                self.db_conn.open_transaction()
                if auth_data['nwaddr'] == 0:
                    LOG.debug("Received auth_event without IP address...")
                    mac_addresses = self.db_conn.port_get_macs()
                    if dladdr in mac_addresses:
                        LOG.debug("Ignoring received auth_ev for OF switch...")
                        return CONTINUE

                    else:
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

                host_idx = None
                try:
                    host_idx = self.db_conn.host_get_index(dladdr)
                except Exception, err:
                    LOG.debug("Any host with mac='%s' in DB" % str(dladdr))

                if host_idx is None:
                    LOG.debug("Adding new host with MAC addr '%s'" % \
                              str(dladdr))
                    try:
                        # Insert Host info into DB
                        self.__host_insert_db(dladdr,
                                              auth_data['datapath_id'],
                                              auth_data['port'],
                                              host_ipaddr)
                        LOG.info("Added host '%s' into DB" % str(dladdr))
                        self.auth_hosts.pop(self.auth_hosts.index(dladdr))
                    except nxw_utils.DBException as err:
                        LOG.error(str(err))
                    except Exception, err:
                        LOG.error("Cannot insert host info into DB ('%s')")
                else:
                    LOG.debug("Found entry for an host with mac_addr '%s'" %
                               str(dladdr))
                    try:
                        # XXX FIXME: Add proper checks for host info updating
                        self.__host_update_db(dladdr, host_ipaddr)
                        LOG.debug("Updated host '%s'" % str(dladdr))
                    except nxw_utils.DBException as err:
                        LOG.error(str(err))
                    except Exception:
                        LOG.error("Cannot insert host info into DB ('%s')")

            except nxw_utils.DBException:
                self.db_conn.rollback()
                return CONTINUE
            finally:
                self.db_conn.close()

            if auth_data['nwaddr'] != 0:
                # check ior-dispatcher on pce node
                if not self.ior_topo and not self.pce_topology_enable():
                    LOG.error("Unable to contact ior-dispatcher on PCE node!")
                    return CONTINUE

                nodes = [host_ipaddr]

                # Update flow-pce topology (hosts)
                LOG.debug("Hosts=%s", nodes)
                self.fpce.add_node_from_string(host_ipaddr)

                # update flow-pce topology (links between DPID and host)
                try:
                    # connect and open transaction
                    self.db_conn.open_transaction()
                    # Host_insert
                    dpid    = self.db_conn.host_get_dpid(dladdr)
                    in_port = self.db_conn.host_get_inport(dladdr)
                    # commit transaction
                    self.db_conn.commit()
                    LOG.debug("Successfully committed information!")
                except nxw_utils.DBException:
                    self.db_conn.rollback()
                finally:
                    self.db_conn.close()

                try:
                    node = self.node_get_frompidport(dpid, in_port)
                    nodes.append(node)
                except nxw_utils.DBException as err:
                    LOG.error(str(err))
                except Exception, err:
                    LOG.error(str(err))

                # update flow-pce topology (links)
                for node in nodes:
                    others = [n for n in nodes if n != node]

                    for oth in others:
                        self.fpce.add_link_from_strings(node, oth)

            return CONTINUE

        except Exception, err:
            LOG.error("Got errors in host_auth_ev handler ('%s')" % str(err))
            return CONTINUE

    def node_get_frompidport(self, dpid, port):
        """ Get node from dpid and port """
        try:
            # connect and open transaction
            self.db_conn.open_transaction()

            didx = self.db_conn.datapath_get_index(dpid)
            pidx = self.db_conn.port_get_index(dpid, port)
            return nxw_utils.createNodeIPv4(didx, pidx)

        finally:
            self.db_conn.close()

    def install(self):
        """ Install """
        self.register_for_datapath_join(self.datapath_join_handler)
        self.register_for_datapath_leave(self.datapath_leave_handler)
        self.register_for_packet_in(self.packet_in_handler)
        self.register_handler(Link_event.static_get_name(),
                              self.link_event_handler)
        self.register_handler(Host_auth_event.static_get_name(),
                              self.host_auth_handler)
        self.register_handler(Host_bind_event.static_get_name(),
                              self.host_bind_handler)


        self.mysql_enable()
        self.pce_topology_enable()
        self.pce_routing_enable()
        self.bindings = self.resolve(pybindings_storage)
        LOG.debug("%s started..." % str(self.__class__.__name__))

    def getInterface(self):
        """ Get interface """
        return str(TopologyMgr)

    # private methods
    def __resolve_path(self, ingress, egress, packet):
        """ Resolve path """
        LOG.debug("Ingress=%s, Egress=%s", ingress, egress)

        # check ior-dispatcher on pce node
        if not self.ior_rout and not self.pce_routing_enable():
            LOG.error("Unable to contact ior-dispatcher on PCE node!")
        else:
            (wor, pro) = self.fpce.connection_route_from_hosts(ingress, egress)
            if not wor:
                return

            LOG.info("Wlen=%d, WorkingEro=%s", len(wor), str(wor))
            LOG.debug("Plen=%d, ProtEro=%s", len(pro), str(pro))

            flows = []
            for idx_x, idx_y in zip(wor, wor[1:]):
                (din_idx, pin_idx)   = self.fpce.decode_ero_item(idx_x)
                (dout_idx, pout_idx) = self.fpce.decode_ero_item(idx_y)

                flows.append((din_idx, pin_idx, dout_idx, pout_idx))

            cflows = self.__convert_flows_from_index(flows)
            for d_in, p_in, d_out, p_out in cflows:
                LOG.info("d_in=%s, p_in=%s, d_out=%s, p_out=%s",
                         str(d_in), str(p_in), str(d_out), str(p_out))

                self.__manage_flow_mod(ingress, egress,
                                       d_in, p_in, d_out, p_out,
                                       packet)

    def __convert_flows_from_index(self, flows):
        """ Convert flows from index """
        LOG.debug("Flows=%s", str(flows))
        try:
            self.db_conn.open_transaction()

            res = []
            for din, pin, dout, pout in flows:
                try:
                    (d_in, p_in)   = self.db_conn.port_get_did_pno(pin)
                    (d_out, p_out) = self.db_conn.port_get_did_pno(pout)

                    res.append((d_in, p_in, d_out, p_out))

                except nxw_utils.DBException as err:
                    LOG.error(str(err))

            return res

        except nxw_utils.DBException as err:
            LOG.error(str(err))
            return []

        finally:
            self.db_conn.close()

    def __manage_flow_mod(self, flow_ip_in, flow_ip_out,
                          dpid_in, port_in, dpid_out, port_out,
                          packet):
        """ Handle flow_mod """
        try:
            LOG.debug("Got requests for flow_mod sending...")
            if dpid_in != dpid_out:
                LOG.debug("Nothing to do (received request for flow_mod" + \
                          "sending with different dpids)")
                return
            else:
                dpid = dpid_in
            # Build flow entry
            LOG.debug("Building flow entry for OF switch '%s'" % str(dpid))
            attrs = self.__flow_entry_build(flow_ip_in,
                                            flow_ip_out,
                                            port_in,
                                            packet)
            LOG.debug("Built the following flow entry for dpid '%s': %s" % \
                       (str(dpid), str(attrs)))
            actions = [[openflow.OFPAT_OUTPUT, [0, port_out]]]

            # Send flow_mod message
            LOG.debug("Sending FLOW_MOD message to dpid '%s'" % str(dpid))
            # XXX FIXME: Remove the following stubs
            idle_timeout = 5
            buffer_id    = None
            pkt          = None

            self.install_datapath_flow(dpid_in,
                                       attrs,
                                       idle_timeout,
                                       openflow.OFP_FLOW_PERMANENT,
                                       actions,
                                       buffer_id,
                                       openflow.OFP_DEFAULT_PRIORITY,
                                       port_in,
                                       pkt)
            LOG.info("Sent FLOW_MOD to dpid %s: Flowentry=%s, actions=%s" % \
                      (str(dpid), str(attrs), str(actions)))

        except Exception, err:
            LOG.error("Got error in manage_flow_mod ('%s')" % str(err))

    def __flow_entry_build(self, src_ip, dst_ip, in_port, packet):
        """ Build OpenFlow entries """
        assert(src_ip  is not None)
        assert(dst_ip  is not None)
        assert(in_port is not None)
        assert(packet  is not None)
        try:
            attributes = extract_flow(packet)

            attributes[IN_PORT]  = in_port
            attributes[NW_SRC]   = src_ip
            attributes[NW_DST]   = dst_ip
            return attributes

        except Exception:
            raise

    def __datapath_leave_db_actions(self, dpid):
        """ Actions related to datapath_leave event """
        nodes = []
        links = []
        hosts = []
        try:
            self.db_conn.open_transaction()

            d_idx  = self.db_conn.datapath_get_index(d_id=dpid)
            p_idxs = self.db_conn.port_get_indexes(d_id=dpid)
            for p_idx in p_idxs:
                nodes.append(nxw_utils.createNodeIPv4(d_idx, p_idx))

            try: # optional
                h_idxs = self.db_conn.host_get_indexes(d_id=dpid)
                for in_port, ip_addr in h_idxs:
                    port = self.db_conn.port_get_index(d_id=dpid,
                                                       port_no=in_port)
                    node = nxw_utils.createNodeIPv4(d_idx, port)

                    links.append((ip_addr, node))
                    hosts.append(ip_addr)

            except nxw_utils.DBException as err:
                LOG.error("host_get_indexes: " + str(err))

            try: # optional
                l_idxs = self.db_conn.link_get_indexes(src_dpid=dpid)
                for src_pno, dst_dpid, dst_pno in l_idxs:
                    src_port = self.db_conn.port_get_index(d_id=dpid,
                                                           port_no=src_pno)
                    src_node = nxw_utils.createNodeIPv4(d_idx, src_port)

                    dst_id = self.db_conn.datapath_get_index(d_id=dst_dpid)
                    dst_port = self.db_conn.port_get_index(d_id=dst_dpid,
                                                           port_no=dst_pno)
                    dst_node = nxw_utils.createNodeIPv4(dst_id, dst_port)

                    links.append((src_node, dst_node))

            except nxw_utils.DBException as err:
                LOG.error("link_get_indexes: " + str(err))

        except nxw_utils.DBException as err:
            LOG.error("dp_leave_db_actions: " + str(err))

        finally:
            self.db_conn.close()

        return (nodes, links, hosts)


def getFactory():
    """ Get factory """
    class Factory:
        """ Class Factory """
        def instance(self, ctxt):
            """ Return Topology Manager object """
            return TopologyMgr(ctxt)

    return Factory()
