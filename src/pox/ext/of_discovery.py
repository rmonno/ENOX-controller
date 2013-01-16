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
from pox.lib.recoco                import Timer
from pox.lib.packet.ethernet       import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.ethernet       import ethernet
from pox.lib.packet.lldp           import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp           import ttl, system_description
from pox.lib.util                  import dpidToStr
from pox.core                      import core
from pox.messenger.messenger       import *
from collections                   import *

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery      as discovery

import struct
import array
import socket
import time
import copy
import pickle
import entities
import connections

log = core.getLogger()

class Discovery_sample (discovery.Discovery):

  def getTopology(self):
    self.topology_ex = core.components['topology']
    return self.topology_ex.serialize()

options = {}

class ReceiverHandler(threading.Thread):
    def __init__(self, name = None, sock = None):
        self.__name = name
        self.__sock = sock
        log.debug("Initializing ReceiverHandler....")
        super(ReceiverHandler, self).__init__()
        self.__stop = threading.Event()

    def run(self):
        assert(self.__name is not None)
        assert(self.__sock is not None)
        log.debug("ReceiverHandler '%s' started" % str(self.__name))
        log.debug("ReceiverHandler '%s' is listening mode" % self.__name)

        while not self.__stop.is_set():
            try:
                print("HELLO")
                message = self.__msg_recv()
                time.sleep(5)
                if len(message) == 0:
                    continue
                log.debug("Received the following message: %s" % str(message))
            except Exception, e:
                log.error(e)

    def __msg_recv(self):
        msg = None
        try:
            msg = connections.msg_receive(self.__sock)
            if len(msg) > 0:
                log.debug("Received a message...")
            return msg
        except Exception, e:
            log.error(e)

    def create(self, name, server):
        assert(name   is not None)
        assert(server is not None)
        self.__name = name
        self.__sock = server.socket_get()
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
        # XXX FIXME: Fill with proper values
        self.handler.create("handler1", self.server)

def launch (shell = False, name = "topology"):
    if shell is False:
        log.debug("Component will not interact with any shell")
    else:
        log.debug("Component can interact with an external shell \
                  to extract and/or populated topology DB")
        options[name] = Receiver()

    log.debug("Launching of_discovery component...")
    core.registerNew(Discovery_sample, "Discovery_sample")
