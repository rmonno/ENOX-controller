# Copyright 2011 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

# This file is based on the discovery component in NOX, though it has
# been substantially rewritten.

from pox.lib.revent                import *
from pox.core                      import core
from pox.messenger.messenger       import *
from collections                   import *

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery      as discovery
import entities                    as ents

import time
import connections

log = core.getLogger()

class Discovery_sample(discovery.Discovery):
    def __init__(self, name):
        assert(name is not None)
        super(Discovery_sample, self).__init__()
        self.__topology =  None

    def getTopology(self):
        log.debug("Getting topology from topology module")
        try:
            self.__topology = core.components['topology']
            return self.__topology
        except Exception, e:
            log.error("Cannot get the topology ('%s')" % str(e))

options = {}

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

        elif msg == "GET_INFO":
            try:
                log.debug("Received info_request message")
                msg_request = of.ofp_stats_request()
                msg_request.type = 3
                print(msg_request.show())

                if self.test is None:
                    # XXX FIXME: Insert topology information retrieval
                    log.error("Topology info has not been retrieved yet")
                for dpid in self.test.of_switch_dpids_get():
                    # Used sendToDPID method in the pox.pox.connection_arbiter
                    # module
                    log.debug("Sending stats_req msg to OF switch %d" % \
                               int(dpid))
                    core.openflow.sendToDPID(dpid, msg_request.pack())
                    log.debug("Sent stats_req msg to OF switch %d" % int(dpid))
                    return("HELLO")
            except Exception, e:
                log.error("Cannot get requested info ('%s')" % str(e))
        else:
            log.debug("Cannot handle this message")

    def run(self):
        assert(self.__name is not None)
        assert(self.__sock is not None)
        self.test = ents.Topology()
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

def launch (shell = False, name = "topology"):
    if shell is False:
        log.debug("Component will not interact with any shell")
    else:
        log.debug("Component can interact with an external shell \
                  to extract and/or populated topology DB")
        options[name] = Receiver()

    if 'openflow_discovery' not in core.components:
        core.registerNew(discovery.Discovery)

    log.debug("Launching of_discovery component...")
    global discovery_sample
    discovery_sample = Discovery_sample("sample")

    def flow_stats_recv(event):
        log.debug("Received flow_stats msg...")

    def table_stats_recv(event):
        log.debug("Received table_stats msg...")

    def switch_desc_recv(event):
        log.debug("Received switch_desc msg...")

    core.openflow.addListenerByName("FlowStatsReceived",  flow_stats_recv)
    core.openflow.addListenerByName("TableStatsReceived", table_stats_recv)
    core.openflow.addListenerByName("SwitchDescReceived", switch_desc_recv)
