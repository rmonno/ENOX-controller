#
# topologymgr
#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Alessandro Canessa <a DOT canessa AT nextworks DOT it>
#

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
# Python L2 learning switch
#
# ----------------------------------------------------------------------

from   nox.lib.core                      import *
from   twisted.python                    import log
from   nox.netapps.discovery.pylinkevent import Link_event
from   nox.lib.packet.packet_utils       import array_to_octstr
from   nox.lib.packet.ethernet           import LLDP_MULTICAST, NDP_MULTICAST
from   nox.lib.packet.ethernet           import ethernet
from   nox.lib.packet.lldp               import lldp, chassis_id, port_id, end_tlv
from   nox.lib.packet.lldp               import ttl
from   nox.lib.openflow                  import OFPP_LOCAL

import logging

logger = logging.getLogger('nox.coreapps.examples.topologymgr')

# Global topologymgr instance
inst     = None

class Port(object):
    def __init__(self):
        self.hw_addr    = None
        self.curr       = None
        self.name       = None
        self.speed      = None
        self.supported  = None
        self.enabled    = None
        self.flood      = None
        self.state      = None
        self.link       = None
        self.advertised = None
        self.peer       = None
        self.config     = None
        self.number     = None

class Switch(object):
    def __init__(self):
        self.tables  = None
        self.buffers = None
        self.caps    = None
        self.actions = None
        self.ports   = None

class Topology(object):
    def __init__(self, data = { }):
        assert(type(data) == dict)
        self.data     = data

    def topology_get(self):
        return self.data

    def __str__(self):
        ret = ""
        for i in self.data:
            ret += "SWITCH '%s': " % i
            if self.data[i].has_key("n_tables"):
                ret += "NumberTables=%d, "  % int(self.data[i]["n_tables"])
            if self.data[i].has_key("n_bufs"):
                ret += "NumberBuffers=%d, " % int(self.data[i]["n_bufs"])
            if self.data[i].has_key("caps"):
                ret += "Capabilities=%s, "  % str(self.data[i]["caps"])
            if self.data[i].has_key("actions"):
                ret += "Actions=%s, "       % str(self.data[i]["actions"])
            # XXX FIXME: Return a more readable string for ports
            if self.data[i].has_key("ports"):
                ret += "Ports=%s "         % str(self.data[i]["ports"])
        return ret

topology       = Topology()
dps            = { }
adjacency_list = { }
lldp_packets   = { }

#def flow_removed_callback(dpid, attrs, priority, reason, cookie, dur_sec,
#	                  dur_nsec, byte_count, packet_count):
#    return CONTINUE

def datapath_join_callback(dpid, attrs):
    assert(dpid  is not None)
    assert(attrs is not None)

    logger.info("Registred Switch '%s'"  % str(dpid))
    if topology.data.has_key(dpid):
        logger.error("A switch with dpid '%s' has already registred" % \
                      str(dpid))
        return

    dps[dpid] = attrs
    lldp_packets[dpid]  = {}
    for port in attrs[PORTS]:
        if port[PORT_NO] == OFPP_LOCAL:
            continue
        #lldp_packets[dpid][port[PORT_NO]] = create_discovery_packet(dpid,
        #                                                                 port[PORT_NO],
        #                                                                 LLDP_TTL);

    topology.data[dpid] = attrs
    logger.debug(topology)
    return CONTINUE

def datapath_leave_callback(dpid):
    assert(dpid is not None)

    logger.info("Switch '%s' has left the network" % str(dpid))
    if not topology.data.has_key(dpid):
        logger.debug("No switches to be deleted from topology data structure")
    else:
        topology.data.pop(dpid)
        logger.info("Deleted info for switch '%s'" % str(dpid))

def lldp_input_handler(dp_id, inport, ofp_reason, total_frame_len, buffer_id, packet):

    assert (packet.type == ethernet.LLDP_TYPE)

    if not packet.next:
        lg.error("lldp_input_handler lldp packet could not be parsed")
        return

    #assert (isinstance(packet.next, lldp))

    lldph = packet.next
    if  (len(lldph.tlvs) < 4) or \
    (lldph.tlvs[0].type != lldp.CHASSIS_ID_TLV) or\
    (lldph.tlvs[1].type != lldp.PORT_ID_TLV) or\
    (lldph.tlvs[2].type != lldp.TTL_TLV):
        lg.error("lldp_input_handler invalid lldp packet")
        return

    # parse out chassis id
    if lldph.tlvs[0].subtype != chassis_id.SUB_LOCAL:
        lg.error("lldp chassis ID subtype is not 'local', ignoring")
        return
    if not lldph.tlvs[0].id.tostring().startswith('dpid:'):
        lg.error("lldp chassis ID is not a dpid, ignoring")
        return
    try:
        chassid = int(lldph.tlvs[0].id.tostring()[5:], 16)
    except:
        lg.error("lldp chassis ID is not numeric', ignoring")
        return

    # if chassid is from a switch we're not connected to, ignore
    if chassid not in dps:
        lg.debug('Recieved LLDP packet from unconnected switch')
        return

    # grab 16bit port ID from port tlv
    if lldph.tlvs[1].subtype != port_id.SUB_PORT:
        return # not one of ours
    if len(lldph.tlvs[1].id) != 2:
        lg.error("invalid lldph port_id format")
        return
    (portid,)  =  struct.unpack("!H", lldph.tlvs[1].id)

    if (dp_id, inport) == (chassid, portid):
        lg.error('Loop detected, received our own LLDP event')
        return

    # print 'LLDP packet in from',longlong_to_octstr(chassid),' port',str(portid)

    linktuple = (dp_id, inport, chassid, portid)
    print(linktuple)

    #if linktuple not in adjacency_list:
    #    self.add_link(linktuple)
    #    lg.warn('new link detected ('+longlong_to_octstr(linktuple[0])+' p:'\
    #               +str(linktuple[1]) +' -> '+\
    #               longlong_to_octstr(linktuple[2])+\
    #               ' p:'+str(linktuple[3])+')')

    # add to adjaceny list or update timestamp
    #adjacency_list[(dp_id, inport, chassid, portid)] = time.time()

#def handle_link_event(self, e):
#    print("AAAAAAAAAAAAAAAAAAAAAAAAAA")

class topologymgr(Component):
    def __init__(self, ctxt):
        global inst
        Component.__init__(self, ctxt)
        self.st  = { }
        inst = self

    def install(self):
        inst.register_for_datapath_leave(datapath_leave_callback)
        inst.register_for_datapath_join(datapath_join_callback)
        #inst.register_handler(Link_event.static_get_name(),
        #                      handle_link_event)
	#inst.register_for_flow_removed(flow_removed_callback)
        #self.register_for_port_status( lambda dp, reason, port : discovery.port_status_change(self, dp, reason, port) )
        # register handler for all LLDP packets
        match = {DL_DST : array_to_octstr(array.array('B',NDP_MULTICAST)),
                 DL_TYPE: ethernet.LLDP_TYPE}
        self.register_for_packet_match(lambda dp,inport,reason,len,bid,packet :
                                        lldp_input_handler(dp,
                                                           inport,
                                                           reason,
                                                           len,
                                                           bid,
                                                           packet),
                                        0xffff,
                                        match)

        #self.start_lldp_timer_thread()


    def getInterface(self):
        return str(topologymgr)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return topologymgr(ctxt)

    return Factory()
