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

from nox.lib.core                                     import *
from nox.lib.packet.ethernet                          import ethernet
from nox.lib.packet.ipv4                              import ipv4
from nox.netapps.discovery.pylinkevent                import Link_event
from nox.netapps.bindings_storage.pybindings_storage  import pybindings_storage
from nox.netapps.authenticator.pyauth                 import Host_auth_event, Host_bind_event
from nox.lib.netinet.netinet                          import *

import nox.lib.packet.packet_utils                    as     pkt_utils

import sys, os
from time import time

# update sys python path
key = 'nox-classic'
basepath = os.path.dirname(os.path.abspath(sys.argv[0]))
nox_index = basepath.find(key)

libs_path = basepath[0:nox_index-1]
sys.path.insert(0, libs_path)

idl_find_path = basepath[0:nox_index] + key + '/build/src'
for (root, dirs, names) in os.walk(idl_find_path):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')

import libs as nxw_utils

log = nxw_utils.ColorLog(logging.getLogger('topologymgr'))


class TopologyMgr(Component):
    CONFIG_FILE = libs_path + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.auth_hosts = [ ]
        self.links      = { }
        self.st         = { }
        self.db_conn    = None
        self.fpce       = nxw_utils.FPCE()
        self.ior_topo   = False
        self.ior_rout   = False

        conf = nxw_utils.NoxConfigParser(TopologyMgr.CONFIG_FILE)
        self.pce_client = nxw_utils.PCE_Client(conf.address,
                                               conf.port,
                                               int(conf.size))
        self.pce_client.create()

    def ior_del(self):
        if self.ior is None:
            log.error("Cannot delete IOR (no stored IOR)")
        else:
            self.ior = None

    def mysql_enable(self,
                     host    = "localhost",
                     user    = "topology_user",
                     pwd     = "topology_pwd",
                     db_name = "topology_ofc_db"):
        self.db_conn = nxw_utils.TopologyOFCManager(host,
                                                    user,
                                                    pwd,
                                                    db_name,
                                                    log)
        log.debug("Enabled connection with Topology DB (%s, %s, %s)",
                  host, user, db_name)

    def pce_topology_enable(self):
        log.debug("Retrieving IOR for topology requests")
        try:
            resp = self.pce_client.send_msg("topology")
            if resp is None:
                self.ior_topo = False
            else:
                log.debug("Received the following response: %s", str(resp))
                parsed_resp = self.pce_client.decode_requests(resp)
                if not parsed_resp:
                    log.error("Got an error in response parsing...")
                    self.ior_topo = False
                else:
                    log.info("Received the following IOR: '%s'",
                             str(parsed_resp))
                    self.fpce.ior_topology_add(parsed_resp)
                    self.ior_topo = True

        except Exception as e:
            log.error("Pce Topology Failure: %s", str(e))
            self.ior_topo = False

        return self.ior_topo

    def pce_routing_enable(self):
        log.debug("Retrieving IOR for routing requests")
        try:
            resp = self.pce_client.send_msg("routing")
            if resp is None:
                self.ior_rout = False
            else:
                log.debug("Received the following response: %s", str(resp))
                parsed_resp = self.pce_client.decode_requests(resp)
                if not parsed_resp:
                    log.error("Got an error in response parsing...")
                    self.ior_rout = False
                else:
                    log.info("Received the following IOR: '%s'",
                             str(parsed_resp))
                    self.fpce.ior_routing_add(parsed_resp)
                    self.ior_rout = True

        except Exception as e:
            log.error("Pce Routing Failure: %s", str(e))
            self.ior_rout = False

        return self.ior_rout

    def packet_in_handler(self, dpid, inport, reason, len, bufid, packet):
        assert packet is not None
        # checks packet consistency
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return CONTINUE

        if packet.type == ethernet.LLDP_TYPE:
            log.debug("Ignoring received LLDP packet...")
            return CONTINUE

        # Handle ARP packets
        if packet.type == ethernet.ARP_TYPE:
            log.debug("Received ARP packet " + str(packet.find('arp')))
            if not self.st.has_key(dpid):
                log.debug("Registering new switch %s" % str(dpid))
                self.st[dpid] = { }

            self.__do_l2_learning(dpid, inport, packet)
            self.__forward_l2_packet(dpid, inport, packet, packet.arr, bufid)

        log.debug("dpid=%s, inport=%s, reason=%s, len=%s, bufid=%s, p=%s",
                  str(dpid), str(inport), str(reason), str(len),
                  str(bufid), str(packet))

        # switch over ethernet type
        if packet.type == ethernet.IP_TYPE:
            ip = packet.find('ipv4')
            log.info("IPv4 packet: " + str(ip))
            # XXXX FIXME: Remove the following check in order to be generic...
            if ip.protocol == ipv4.ICMP_PROTOCOL:
                self.__resolve_path(pkt_utils.ip_to_str(ip.srcip),
                                    pkt_utils.ip_to_str(ip.dstip),
                                    packet)

        return CONTINUE

    def __do_l2_learning(self, dpid, inport, packet):
        assert(dpid   is not None)
        assert(inport is not None)
        assert(packet is not None)
        # learn MAC on incoming port
        srcaddr = packet.src.tostring()
        if ord(srcaddr[0]) & 1:
            return
        if self.st[dpid].has_key(srcaddr):
            dst = self.st[dpid][srcaddr]
            if dst[0] != inport:
                log.debug("MAC has moved from '%s' to '%s' " % (str(dst),
                                                                str(inport)))
            else:
                return
        else:
            log.debug("Learned MAC '%s' on %d %d " % \
                        (pkt_utils.mac_to_str(packet.src),
                         dpid, inport))

        # learn or update timestamp of entry
        self.st[dpid][srcaddr] = (inport, time(), packet)

    def __forward_l2_packet(self, dpid, inport, packet, buf, bufid):
        dstaddr = packet.dst.tostring()
        if not ord(dstaddr[0]) & 1 and self.st[dpid].has_key(dstaddr):
            prt = self.st[dpid][dstaddr]
            if prt[0] == inport:
                log.err("**WARNING** Learned port = inport")
                self.send_openflow(dpid, bufid, buf,
                                   openflow.OFPP_FLOOD,
                                   inport)
            else:
                # We know the outport, set up a flow
                log.debug("Installing flow for %s" % str(packet))
                flow = extract_flow(packet)
                actions = [[openflow.OFPAT_OUTPUT, [0, prt[0]]]]
                self.install_datapath_flow(dpid, flow, 5,
                                           openflow.OFP_FLOW_PERMANENT,
                                           actions, bufid,
                                           openflow.OFP_DEFAULT_PRIORITY,
                                           inport, buf)
                log.info("New installed flow entry for dpid '%s': %s" % \
                          (str(dpid), str(flow)))
        else:
            # haven't learned destination MAC. Flood
            self.send_openflow(dpid, bufid, buf, openflow.OFPP_FLOOD, inport)
            log.debug("Flooding received packet...")

    def datapath_join_handler(self, dpid, stats):
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
            log.debug("Successfull committed information!")

        except nxw_utils.DBException as e:
            log.error(str(e))
            # rollback transaction
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

        # check ior-dispatcher on pce node
        if not self.ior_topo and not self.pce_topology_enable():
            log.error("Unable to contact ior-dispatcher on PCE node!")
            return CONTINUE

        # get datapath and ports index from topology-db
        nodes = []
        try:
            for p_info in stats['ports']:
                node = self.node_get_frompidport(dpid, p_info['port_no'])
                nodes.append(node)

        except nxw_utils.DBException as e:
            log.error(str(e))

        except Exception, e:
            log.error(str(e))

        # update flow-pce topology (nodes)
        log.debug("Nodes=%s", nodes)
        for node in nodes:
            self.fpce.add_node_from_string(node)

        # update flow-pce topology (links)
        for node in nodes:
            others = [n for n in nodes if n != node]

            for o in others:
                self.fpce.add_link_from_strings(node, o)

        return CONTINUE

    def datapath_leave_handler(self, dpid):
        assert (dpid is not None)

        # check ior-dispatcher on pce node
        if not self.ior_topo and not self.pce_topology_enable():
            log.error("Unable to contact ior-dispatcher on PCE node!")
        else:
            # get nodes and links from topology-db
            (nodes, links) = self.__datapath_leave_db_actions(dpid)

            # update flow-pce topology (delete links)
            log.info("DataPath_leave nodes=%s", nodes)
            for node in nodes:
                others = [n for n in nodes if n != node]

                for o in others:
                    self.fpce.del_link_from_strings(node, o)

            # update flow-pce topology (delete interswitch links)
            log.info("DataPath_leave links=%s", links)
            for src, dst in links:
                self.fpce.del_link_from_strings(src, dst)
                self.fpce.del_link_from_strings(dst, src)

            # update flow-pce topology (delete nodes)
            for node in nodes:
                self.fpce.del_node_from_string(node)

        # delete values into topology-db
        try:
            self.db_conn.open_transaction()

            # datapath_delete
            # (automatically delete all ports and hosts associated with it)
            self.db_conn.datapath_delete(d_id=dpid)

            self.db_conn.commit()
            log.debug("Successfull committed information!")

        except nxw_utils.DBException as e:
            log.error(str(e))
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

        return CONTINUE

    def link_key_build(self, from_node, to_node):
        assert(from_node is not None)
        assert(to_node is not None)
        key = None
        key = str(from_node) + "TO" + str(to_node)
        return key

    def link_add(self, data):
        assert(data is not None)
        try:
            link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
            if self.links.has_key(link_key):
                log.debug("Link '%s' will be updated with received info" % \
                           str(link_key))
            else:
                log.debug("Adding new detected link '%s'..." % str(link_key))
                self.links[link_key] = nxw_utils.Link(link_key,
                                                      data['dpsrc'],
                                                      data['dpdst'])

            self.links[link_key].adjacency_add(int(data['sport']),
                                               int(data['dport']))
            log.info("Added a new adjacency for link '%s'" % str(link_key))

            # check ior-dispatcher on pce node
            if not self.ior_topo and not self.pce_topology_enable():
                log.error("Unable to contact ior-dispatcher on PCE node!")
                return CONTINUE

            nodes = []
            try:
                src_node = self.node_get_frompidport(data['dpsrc'],
                                                     data['sport'])
                nodes.append(src_node)

                dst_node = self.node_get_frompidport(data['dpdst'],
                                                     data['dport'])
                nodes.append(dst_node)

            except nxw_utils.DBException as e:
                log.error(str(e))

            except Exception, e:
                log.error(str(e))

            for node in nodes:
                others = [n for n in nodes if n != node]

                for o in others:
                    self.fpce.add_link_from_strings(node, o)

        except Exception, err:
            log.error("Cannot add link ('%s')" % str(err))

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

        except nxw_utils.DBException as e:
            log.error(str(e))
            # rollback transaction
            self.db_conn.rollback()

        finally:
            self.db_conn.close()

    def link_del(self, data):
        assert(data is not None)
        try:
            link_key = self.link_key_build(data['dpsrc'], data['dpdst'])
            if self.links.has_key(link_key):
                log.debug("Link '%s' will be updated by removing adjancency" % \
                           str(link_key))
            else:
                log.error("Cannot find any link with id '%s'" % str(link_key))

            self.links[link_key].adjacency_del(data['sport'],
                                               data['dport'])
            log.info("Removed an existing adjacency for link '%s'" % \
                      str(link_key))

        except Exception, err:
            log.error("Cannot remove info for link ('%s')" % str(err))

    def link_event_handler(self, ingress):
        assert (ingress is not None)
        try:
            link_data = ingress.__dict__
            log.debug("Received link event with the following data: %s" % \
                       str(link_data))
            if link_data['action'] == "add":
                log.debug("Adding new detected link...")
                self.link_add(link_data)

            elif link_data['action'] == "remove":
                log.debug("Removing link...")
                self.link_del(link_data)

            else:
                log.error("Cannot handle the following action: '%s'" % \
                           str(link_data['action']))
                return CONTINUE

        except Exception, err:
            log.error("Got errors in link_event handler ('%s')" % str(err))
            return CONTINUE

        log.debug("Link_event handled successfully...")
        link_key = self.link_key_build(link_data['dpsrc'], link_data['dpdst'])
        log.debug(str(self.links[link_key]))
        return CONTINUE

    def __host_insert_db(self, mac_addr, dpid, port, ip_addr = None):
        try:
            # Host_insert
            self.db_conn.host_insert(mac_addr, dpid, port, ip_addr)

            # commit transaction
            self.db_conn.commit()
            log.debug("Successfully committed information!")

        except nxw_utils.DBException:
            self.db_conn.rollback()
            raise

    def __host_update_db(self, mac_addr, ip_addr):
        try:
            # connect and open transaction
            self.db_conn.open_transaction()
            # Host_insert
            self.db_conn.host_update(mac_addr, ip_addr)
            # commit transaction
            self.db_conn.commit()
            log.debug("Successfully committed information!")
        except nxw_utils.DBException:
            self.db_conn.rollback()
            raise
        finally:
            self.db_conn.close()

    def host_bind_event_handler(self, data):
        assert(data is not None)
        try:
            auth_data = data.__dict__
            log.info("Received host_bind_ev with the following data: %s" %
                      str(auth_data))

        except Exception, e:
            log.error("Got error in host_bind_event handler ('%s')" % str(e))

    def host_auth_event_handler(self, data):
        assert(data is not None)
        try:
            auth_data = data.__dict__
            log.info("Received host_auth_ev with the following data: %s" %
                      str(auth_data))
            dladdr    = pkt_utils.mac_to_str(auth_data['dladdr'])
            host_ipaddr = nxw_utils.convert_ipv4_to_str(auth_data['nwaddr'])
            try:
                # connect and open transaction
                self.db_conn.open_transaction()
                if auth_data['nwaddr'] == 0:
                    log.debug("Received auth_event without IP address...")
                    mac_addresses = self.db_conn.port_get_macs()
                    if dladdr in mac_addresses:
                        log.debug("Ignoring received auth_ev for OF switch...")
                        return CONTINUE

                if dladdr in self.auth_hosts:
                    log.debug("Ignoring auth_event (more notifications for" + \
                              " multiple inter-switch links")
                    return CONTINUE
                self.auth_hosts.append(dladdr)

                host_idx = None
                try:
                    host_idx = self.db_conn.host_get_index(dladdr)
                except Exception, e:
                    log.debug("Any host with mac='%s' in DB" % str(dladdr))

                if host_idx is None:
                    log.debug("Adding new host with MAC addr '%s'" % \
                              str(dladdr))
                    try:
                        # Insert Host info into DB
                        self.__host_insert_db(dladdr,
                                              auth_data['datapath_id'],
                                              auth_data['port'],
                                              host_ipaddr)
                        log.info("Added host '%s' into DB" % str(dladdr))
                        self.auth_hosts.pop(self.auth_hosts.index(dladdr))
                    except nxw_utils.DBException as e:
                        log.error(str(e))
                    except Exception, e:
                        log.error("Cannot insert host info into DB ('%s')")
                else:
                    log.debug("Found entry for an host with mac_addr '%s'" %
                               str(dladdr))
                    try:
                        # XXX FIXME: Add proper checks for host info updating
                        self.__host_update_db(dladdr, host_ipaddr)
                        log.debug("Updated host '%s'" % str(dladdr))
                    except nxw_utils.DBException as e:
                        log.error(str(e))
                    except Exception, e:
                        log.error("Cannot insert host info into DB ('%s')")


            except nxw_utils.DBException as e:
                self.db_conn.rollback()
                return CONTINUE
            finally:
                self.db_conn.close()

            if auth_data['nwaddr'] != 0:
                # check ior-dispatcher on pce node
                if not self.ior_topo and not self.pce_topology_enable():
                    log.error("Unable to contact ior-dispatcher on PCE node!")
                    return CONTINUE

                nodes = [host_ipaddr]

                # Update flow-pce topology (hosts)
                log.debug("Hosts=%s", nodes)
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
                    log.debug("Successfully committed information!")
                except nxw_utils.DBException as e:
                    self.db_conn.rollback()
                finally:
                    self.db_conn.close()

                try:
                    node = self.node_get_frompidport(dpid, in_port)
                    nodes.append(node)
                except nxw_utils.DBException as e:
                    log.error(str(e))
                except Exception, e:
                    log.error(str(e))

                # update flow-pce topology (links)
                for node in nodes:
                    others = [n for n in nodes if n != node]

                    for o in others:
                        self.fpce.add_link_from_strings(node, o)

            return CONTINUE

        except Exception, err:
            log.error("Got errors in host_auth_ev handler ('%s')" % str(err))
            return CONTINUE

    def node_get_frompidport(self, dpid, port):
        try:
            # connect and open transaction
            self.db_conn.open_transaction()

            didx = self.db_conn.datapath_get_index(dpid)
            pidx = self.db_conn.port_get_index(dpid, port)
            node = "0." + str(didx) + ".0." + str(pidx)

            return node

        finally:
            self.db_conn.close()

    def install(self):
        self.register_for_datapath_join(self.datapath_join_handler)
        self.register_for_datapath_leave(self.datapath_leave_handler)
        self.register_for_packet_in(self.packet_in_handler)
        self.register_handler(Link_event.static_get_name(),
                              self.link_event_handler)
        self.register_handler(Host_auth_event.static_get_name(),
                              self.host_auth_event_handler)
        self.register_handler(Host_bind_event.static_get_name(),
                              self.host_bind_event_handler)


        self.mysql_enable()
        self.pce_topology_enable()
        self.pce_routing_enable()
        self.bindings = self.resolve(pybindings_storage)
        log.debug("%s started..." % str(self.__class__.__name__))

    def getInterface(self):
        return str(TopologyMgr)

    # private methods
    def __resolve_path(self, ingress, egress, packet):
        log.debug("Ingress=%s, Egress=%s", ingress, egress)

        # check ior-dispatcher on pce node
        if not self.ior_rout and not self.pce_routing_enable():
            log.error("Unable to contact ior-dispatcher on PCE node!")
        else:
            (w, p) = self.fpce.connection_route_from_hosts(ingress, egress)
            if not w: return

            log.info("Wlen=%d, WorkingEro=%s", len(w), str(w))

            flows = []
            for x, y in zip(w, w[1:]):
                (din_idx, pin_idx)   = self.fpce.decode_ero_item(x)
                (dout_idx, pout_idx) = self.fpce.decode_ero_item(y)

                flows.append((din_idx, pin_idx, dout_idx, pout_idx))

            cflows = self.__convert_flows_from_index(flows)
            for d_in, p_in, d_out, p_out in cflows:
                log.info("d_in=%s, p_in=%s, d_out=%s, p_out=%s",
                         str(d_in), str(p_in), str(d_out), str(p_out))

                self.__manage_flow_mod(ingress, egress,
                                       d_in, p_in, d_out, p_out,
                                       packet)

    def __convert_flows_from_index(self, flows):
        log.debug("Flows=%s", str(flows))
        try:
            self.db_conn.open_transaction()

            res = []
            for din, pin, dout, pout in flows:
                try:
                    (d_in, p_in)   = self.db_conn.port_get_did_pno(pin)
                    (d_out, p_out) = self.db_conn.port_get_did_pno(pout)

                    res.append((d_in, p_in, d_out, p_out))

                except nxw_utils.DBException as e:
                    log.error(str(e))

            return res

        except nxw_utils.DBException as e:
            log.error(str(e))
            return []

        finally:
            self.db_conn.close()

    def __manage_flow_mod(self, flow_ip_in, flow_ip_out,
                          dpid_in, port_in, dpid_out, port_out,
                          packet):
        try:
            log.debug("Got requests for flow_mod sending...")
            if dpid_in != dpid_out:
                log.debug("Nothing to do (received request for flow_mod" + \
                          "sending with different dpids)")
                return
            else:
                dpid = dpid_in
            # Build flow entry
            log.debug("Building flow entry for OF switch '%s'" % str(dpid))
            attrs = self.__flow_entry_build(flow_ip_in,
                                            flow_ip_out,
                                            port_in,
                                            packet)
            log.debug("Built the following flow entry for dpid '%s': %s" % \
                       (str(dpid), str(attrs)))
            actions = [[openflow.OFPAT_OUTPUT, [0, port_out]]]

            # Send flow_mod message
            log.debug("Sending FLOW_MOD message to dpid '%s'" % str(dpid))
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
            log.info("Sent FLOW_MOD to dpid %s: Flowentry=%s, actions=%s" % \
                      (str(dpid), str(attrs), str(actions)))

        except Exception, e:
            log.error("Got error in manage_flow_mod ('%s')" % str(e))

    def __flow_entry_build(self, src_ip, dst_ip, in_port, packet):
        assert(src_ip  is not None)
        assert(dst_ip  is not None)
        assert(in_port is not None)
        assert(packet  is not None)
        try:
            attributes = extract_flow(packet)

            attributes[core.IN_PORT]  = in_port
            attributes[core.NW_SRC]   = src_ip
            attributes[core.NW_DST]   = dst_ip
            return attributes

        except Exception:
            raise

    def __datapath_leave_db_actions(self, dpid):
        nodes = []
        links = []
        try:
            self.db_conn.open_transaction()

            d_idx  = self.db_conn.datapath_get_index(d_id=dpid)
            p_idxs = self.db_conn.port_get_indexes(d_id=dpid)
            for p_idx in p_idxs:
                node = "0." + str(d_idx) + ".0." + str(p_idx)
                nodes.append(node)

            try: # optional
                h_idxs = self.db_conn.host_get_indexes(d_id=dpid)
                for in_port, ip_addr in h_idxs:
                    port = self.db_conn.port_get_index(d_id=dpid,
                                                       port_no=in_port)
                    node = "0." + str(d_idx) + ".0." + str(port)

                    links.append((ip_addr, node))

            except nxw_utils.DBException as e:
                log.error("host_get_indexes: " + str(e))

            try: # optional
                l_idxs = self.db_conn.link_get_indexes(src_dpid=dpid)
                for src_pno, dst_dpid, dst_pno in l_idxs:
                    src_port = self.db_conn.port_get_index(d_id=dpid,
                                                           port_no=src_pno)
                    src_node = "0." + str(d_idx) + ".0." + str(src_port)

                    dst_id = self.db_conn.datapath_get_index(d_id=dst_dpid)
                    dst_port = self.db_conn.port_get_index(d_id=dst_dpid,
                                                           port_no=dst_pno)
                    dst_node = "0." + str(dst_id) + ".0." + str(dst_port)

                    links.append((src_node, dst_node))

            except nxw_utils.DBException as e:
                log.error("link_get_indexes: " + str(e))

        except nxw_utils.DBException as e:
            log.error("dp_leave_db_actions: " + str(e))

        finally:
            self.db_conn.close()

        return (nodes, links)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return TopologyMgr(ctxt)

    return Factory()
