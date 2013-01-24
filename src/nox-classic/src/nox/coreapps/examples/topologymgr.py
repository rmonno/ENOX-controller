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

from nox.lib.core             import *
from nox.lib.packet.ethernet  import ethernet

import nox.coreapps.examples.connections as connections
import threading
import logging

log = logging.getLogger('topologymgr')

class ReceiverHandler(threading.Thread):
    def __init__(self, name = None, sock = None):
        self.__name = name
        self.__sock = sock
        log.debug("Initializing ReceiverHandler....")
        super(ReceiverHandler, self).__init__()
        self.__stop = threading.Event()

    def msg_handle(self, msg):
        assert(msg is not None)
        if msg == "GET_TOPOLOGY":
            log.debug("Got the following topology: %s" %
                       str(discovery_sample.getTopology()))
            topo = discovery_sample.getTopology()
            # XXX FIXME: Move the following lines into a proper function...
            for i in topo._entities.keys():
                name = topo._entities[i].__class__.__name__
                if name in ents.ents_supp.keys():
                    log.debug("Got an '%s' entity" % str(name))
                    log.debug("Initializing entity...")
                    self.__entity_create(topo._entities[i])
            log.debug("TOPOLOGY='%s'" % str(self.test))
            return self.test

        # XXX FIXME: Merge GET_ENTRY_INFO with GET_TABLE_INFO
        elif msg == "GET_ENTRIES":
            try:
            	log.debug("Received info_request for entries")
                #msg_request = of.ofp_stats_request()
                #msg_request.type = 1

                if self.test is None:
                    # XXX FIXME: Insert topology information retrieval
                    log.error("Topology info has not been retrieved yet")
                for dpid in self.test.of_switch_dpids_get():
                    # Used sendToDPID method in the pox.pox.connection_arbiter
                    # module
                    log.debug("Sending stats_req msg to OF switch %d" % \
                               int(dpid))
                #    core.openflow.sendToDPID(dpid, msg_request.pack())
                #    log.debug("Sent stats_req msg to OF switch %d" % int(dpid))
                    return("HELLO")
            except Exception, e:
                log.error("Cannot get requested info ('%s')" % str(e))

        elif msg == "GET_TABLES":
            try:
                log.debug("Received info_request for tables")
                #msg_request = of.ofp_stats_request()
                #msg_request.type = 3

                if self.test is None:
                    # XXX FIXME: Insert topology information retrieval
                    log.error("Topology info has not been retrieved yet")
                for dpid in self.test.of_switch_dpids_get():
                    # Used sendToDPID method in the pox.pox.connection_arbiter
                    # module
                    log.debug("Sending stats_req msg to OF switch %d" % \
                               int(dpid))
                #    core.openflow.sendToDPID(dpid, msg_request.pack())
                #    log.debug("Sent stats_req msg to OF switch %d" % int(dpid))
                return("HELLO")
            except Exception, e:
                log.error("Cannot get requested info ('%s')" % str(e))
        else:
            log.debug("Cannot handle this message")

    def run(self):
        assert(self.__name is not None)
        assert(self.__sock is not None)
	# XXX FIXME: Use the functions and members defined in the directory module
        #self.test = ents.Topology()
        log.debug("ReceiverHandler '%s' started" % str(self.__name))
        log.debug("ReceiverHandler '%s' is listening mode" % self.__name)

        while not self.__stop.is_set():
            try:
                message = self.__msg_recv()
                time.sleep(5)
                if len(message) == 0:
                    continue
                log.debug("Received the following message: %s" % str(message))
                resp = self.msg_handle(message)
                try:
                    connections.message_send(self.__sock, str(resp))
                except Exception, e:
                    log.error("Cannot send response ('%s')" % str(e))
            except Exception, e:
                log.error(e)

    def __entity_create(self, entity):
        assert(entity is not None)
        name = entity.__class__.__name__
        if name == "OpenFlowSwitch":
            of_switch = ents.OFSwitch(entity.dpid)
            of_switch.create(entity.dpid,
                             entity.ports,
                             entity.flow_table,
                             entity.capabilities,
                             entity._connection,
                             entity._listeners)
            self.test.add_ofswitch(of_switch)

    def __msg_recv(self):
        msg = None
        try:
            msg = connections.msg_receive(self.__sock)
            if len(msg) > 0:
                log.debug("Received a message...")
            return msg
        except Exception, e:
            log.error(e)

    def create(self, name, sock):
        assert(name is not None)
        assert(sock is not None)
        self.__name = name
        self.__sock = sock
        self.daemon = True
        self.start()

    def stop(self):
        self.__stop.set()

class Receiver(object):
    def __init__(self):
        self.handler = ReceiverHandler()
        # XXX FIXME: Fill with proper values
        self.server    = connections.Server("test",
                                            "localhost",
                                            9001,
                                            5,
                                            self.handler)

class TopologyMgr(Component):

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.dpids = { }

    def packet_in_handler(self, dpid, inport, reason, len, bufid, packet):
	assert packet is not None
	log.debug("%s has catched the packet_in event" %
                   str(self.__class__.__name__))
        if not packet.parsed:
            log.debug("Ignoring incomplete packet")

        if packet.type == ethernet.LLDP_TYPE:
            log.debug("Ignoring received LLDP packet...")
            return CONTINUE

        return CONTINUE

    def datapath_join_handler(self, dpid, stats):
        assert (dpid  is not None)
        assert (stats is not None)

        if self.dpids.has_key(str(dpid)):
            log.error("Switch %s is already registred...")
            return CONTINUE
        else:
            log.debug("Switch %s joined with the following stats:\n %s" %
                      (str(dpid), str(stats)))
            self.dpids[str(dpid)] = stats
            log.debug("Now TopologyDB contains the following parms: \n %s" %
                       str(self.dpids))

        return CONTINUE

    def datapath_leave_handler(self, dpid):
        assert (dpid  is not None)
        # XXX FIXME: Insert code here (delete dpid from dict created before)

        if not self.dpids.has_key(str(dpid)):
            log.error("Received Switch %s is already registred")
            return CONTINUE
        del self.dpids[str(dpid)]
        log.debug("Switch %s has left network" % str(dpid))
        log.debug("Now TopologyDB contains the following parms: \n %s" %
                   str(self.dpids))
        return CONTINUE

    def install(self):
        self.register_for_datapath_join(self.datapath_join_handler)
        self.register_for_datapath_leave(self.datapath_leave_handler)
	self.register_for_packet_in(self.packet_in_handler)

	log.debug("%s started..." % str(self.__class__.__name__))
	self.receiver = Receiver()

    def getInterface(self):
        return str(TopologyMgr)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return TopologyMgr(ctxt)

    return Factory()
