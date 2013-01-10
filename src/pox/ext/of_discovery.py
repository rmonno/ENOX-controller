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

from pox.lib.revent               import *
from pox.lib.recoco               import Timer
from pox.lib.packet.ethernet      import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl, system_description
import pox.openflow.libopenflow_01 as of
from pox.lib.util                 import dpidToStr
from pox.core import core
from pox.messenger.messenger import *

import struct
import array
import socket
import time
import copy
from collections import *
import pox.openflow.discovery as discovery

log = core.getLogger()

class Discovery_sample (discovery.Discovery):

  def getTopology(self):
    return self._dps

class MessengerHandler (object):
  def __init__ (self, targetName):
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)
    self._targetName = targetName

  def _handle_global_MessageReceived (self, event, msg):
    try:
      b = core.openflow_discovery.getTopology()
      print(type(b))
      print(b)
      for i in b:
        print("HERE")
        print i
      n = msg['start']
      if n == self._targetName:
        event.con.read()
        event.claim()
        event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
        print self._targetName, "- started conversation with", event.con
      else:
        print self._targetName, "- ignoring", n
    except Exception, e:
      print(e)
      pass

  def _handle_MessageReceived (self, event, msg):
    if event.con.isReadable():
      r = event.con.read()
      print self._targetName, "-",r
      if type(r) is dict and r.get("end",False):
        print self._targetName, "- GOODBYE!"
        event.con.close()
      if type(r) is dict and "echo" in r:
        event.con.send({"echo":r["echo"]})

    else:
      print self._targetName, "- conversation finished"

examples = {}

def launch (shell = False, name = "topology"):
    if shell is False:
        log.debug("Component will not interact with any shell")
    else:
        log.debug("Component can interact with an external shell \
                  to extract and/or populated topology DB")
        examples[name] = MessengerHandler(name)

    log.debug("Launching of_discovery component...")
    core.registerNew(Discovery_sample, "Discovery_sample")
