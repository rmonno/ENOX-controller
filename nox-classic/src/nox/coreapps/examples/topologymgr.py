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

from nox.lib.core     import *

from nox.lib.packet.ethernet     import ethernet
from nox.lib.packet.packet_utils import mac_to_str, mac_to_int

from twisted.python import log

import logging
from time import time
from socket import htons
from struct import unpack

logger = logging.getLogger('nox.coreapps.examples.topologymgr')

# Global topologymgr instance
inst = None

# Timeout for cached MAC entries
CACHE_TIMEOUT = 5

# --
# Given a packet, learn the source and peg to a switch/inport
# --
def do_l2_learning(dpid, inport, packet):
    global inst

    # learn MAC on incoming port
    srcaddr = packet.src.tostring()
    if ord(srcaddr[0]) & 1:
        return
    if inst.st[dpid].has_key(srcaddr):
        dst = inst.st[dpid][srcaddr]
        if dst[0] != inport:
            log.msg('MAC has moved from '+str(dst)+'to'+str(inport), system='topologymgr')
        else:
            return
    else:
        log.msg('learned MAC '+mac_to_str(packet.src)+' on %d %d'% (dpid,inport), system="topologymgr")

    # learn or update timestamp of entry
    inst.st[dpid][srcaddr] = (inport, time(), packet)

    # Replace any old entry for (switch,mac).
    mac = mac_to_int(packet.src)

# --
# If we've learned the destination MAC set up a flow and
# send only out of its inport.  Else, flood.
# --
def forward_l2_packet(dpid, inport, packet, buf, bufid):
    dstaddr = packet.dst.tostring()
    if not ord(dstaddr[0]) & 1 and inst.st[dpid].has_key(dstaddr):
        prt = inst.st[dpid][dstaddr]
        if  prt[0] == inport:
            log.err('**warning** learned port = inport', system="topologymgr")
            inst.send_openflow(dpid, bufid, buf, openflow.OFPP_FLOOD, inport)
        else:
            # We know the outport, set up a flow
            log.msg('installing flow for ' + str(packet), system="topologymgr")
            flow = extract_flow(packet)
            flow[core.IN_PORT] = inport
            actions = [[openflow.OFPAT_OUTPUT, [0, prt[0]]]]
            inst.install_datapath_flow(dpid, flow, CACHE_TIMEOUT,
                                       openflow.OFP_FLOW_PERMANENT, actions,
                                       bufid, openflow.OFP_DEFAULT_PRIORITY,
                                       inport, buf)
    else:
        # haven't learned destination MAC. Flood
        inst.send_openflow(dpid, bufid, buf, openflow.OFPP_FLOOD, inport)

# --
# Responsible for timing out cache entries.
# Is called every 1 second.
# --
def timer_callback():
    global inst
    curtime  = time()
    for dpid in inst.st.keys():
        for entry in inst.st[dpid].keys():
            if (curtime - inst.st[dpid][entry][1]) > CACHE_TIMEOUT:
                log.msg('timing out entry'+mac_to_str(entry)+str(inst.st[dpid][entry])+' on switch %x' % dpid, system='topologymgr')
                inst.st[dpid].pop(entry)

    inst.post_callback(1, timer_callback)
    return True

def datapath_leave_callback(dpid):
    print("IN DATAPATH_LEAVE_CALLBACK")
    logger.info('Switch %x has left the network' % dpid)
    if inst.st.has_key(dpid):
        del inst.st[dpid]

#def datapath_join_callback(dpid, stats):
#    logger.info('Switch %x has joined the network' % dpid)

# --
# Packet entry method.
# Drop LLDP packets (or we get confused) and attempt learning and
# forwarding
# --
def packet_in_callback(dpid, inport, reason, len, bufid, packet):

    print("PACKET_IN_CALLBACK")
    if not packet.parsed:
        log.msg('Ignoring incomplete packet',system='topologymgr')

    if not inst.st.has_key(dpid):
        log.msg('registering new switch %x' % dpid,system='topologymgr')
        inst.st[dpid] = {}

    # don't forward lldp packets
    if packet.type == ethernet.LLDP_TYPE:
        return CONTINUE

    # learn MAC on incoming port
    do_l2_learning(dpid, inport, packet)

    forward_l2_packet(dpid, inport, packet, packet.arr, bufid)

    return CONTINUE

def flow_removed_callback(dpid, attrs, priority, reason, cookie, dur_sec,
	                  dur_nsec, byte_count, packet_count):
	print("IN MY FLOW_REMOVED_CALLBACK")
	print("SWITCH PID  = '%s'" % str(dpid))
	print("REASON      = '%s'" % str(reason))
	print("BYTE COUNT  = '%s'" % str(byte_count))

	return CONTINUE

def datapath_join_callback(dpid, attrs):
	print("SWITCH ID  = '%s'" % str(dpid))
	print(type("Type DPID = '%s'" % type(dpid)))
	print("ATTRIBUTES = '%s'" % str(attrs))
	print(type("Type attrs = '%s'" % type(attrs)))
	print("Test in order to send a flow entry when a switch is connected to NOX....")
	actions = [ ]
	#inst.send_openflow_packet(dpid, packet, actions)
	idle_timeout = 5
	hard_timeout = 10
	attrs = { }
	inst.install_datapath_flow(dpid, attrs, idle_timeout, hard_timeout, actions)

	return CONTINUE

class topologymgr(Component):

    def __init__(self, ctxt):
        global inst
        Component.__init__(self, ctxt)
        self.st = {}

        inst = self

    def install(self):
        inst.register_for_packet_in(packet_in_callback)
        inst.register_for_datapath_leave(datapath_leave_callback)
        inst.register_for_datapath_join(datapath_join_callback)

	log.msg("Inserted new simple handlers for more events...")
	inst.register_for_flow_removed(flow_removed_callback)
	#inst.register_for_datapath_join(datapath_join_callback)

        inst.post_callback(1, timer_callback)

    def getInterface(self):
        return str(topologymgr)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return topologymgr(ctxt)

    return Factory()
