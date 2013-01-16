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

"""
This module discovers the connectivity between OpenFlow switches by sending
out LLDP packets. To be notified of this information, listen to LinkEvents
on core.Discovery.

It's possible that some of this should be abstracted out into a generic
Discovery module, or a Discovery superclass.
"""

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

log = core.getLogger()

class Discovery_sample (discovery.Discovery):

  def getTopology(self):
    self.topology_ex = core.components['topology']
    return self.topology_ex.serialize()

class MessengerHandler (object):
  def __init__ (self, targetName):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)
    self._targetName = targetName
    self._commands   = ["get_topology",
                        "set_topology"]

  def _handle_global_MessageReceived (self, event, msg):
    try:
      command = None
      # XXX FIXME: Modify the received message (now it is a string)
      log.debug("Received the following msg: '%s'" % str(msg))
      for i in msg.values():
          if (i.encode('utf-8') in self._commands):
              command = i.encode('utf-8')
              break
      if command in self._commands:
        log.debug("Received a message containing a command to be executed...")
        event.con.read()
        event.claim()
        event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
        print self._targetName, "- started conversation with", event.con
      else:
        print self._targetName, "- ignoring", command
    except Exception, e:
      print(e)
      pass

  def _handle_MessageReceived (self, event, msg):
    try:
      topology_dict = core.openflow_discovery.getTopology()
      topology_obj  = entities.Topology()
      for i in topology_dict:
        topology_obj.add_entity(topology_dict[i])
      topology_2sent = topology_obj.serialize()
      event.con.send(pickle.dumps(topology_2sent))
      log.debug("Sent the following response: '%s'" % topology_2sent)

      if event.con.isReadable():
        r = event.con.read()
        log.debug("%s - %s" % (str(self._targetName),
                               str(r)))
        if type(r) is dict and r.get("end",False):
          log.debug("%s - BYE"  % str(self._targetName))
          event.con.close()
    except Exception, e:
        log.error("Cannot send the response ('%s')" % str(e))

options = {}

def launch (shell = False, name = "topology"):
    if shell is False:
        log.debug("Component will not interact with any shell")
    else:
        log.debug("Component can interact with an external shell \
                  to extract and/or populated topology DB")
        options[name] = MessengerHandler(name)

    log.debug("Launching of_discovery component...")
    core.registerNew(Discovery_sample, "Discovery_sample")
