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
#
# ----------------------------------------------------------------------

from   nox.lib.core                      import *
from   twisted.python                    import log

import logging

logger = logging.getLogger('nox.coreapps.examples.topologymgr')
lg     = logging.getLogger('topologymgr')

# Global topologymgr instance
inst   = None

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

topology = Topology()

def datapath_join_callback(dpid, attrs):
    assert(dpid  is not None)
    assert(attrs is not None)

    logger.info("Registred Switch '%s'"  % str(dpid))
    if topology.data.has_key(dpid):
        logger.error("A switch with dpid '%s' has already registred" % \
                     str(dpid))
        return

    topology.data[dpid] = attrs
    logger.debug(topology)
    return CONTINUE

def datapath_leave_callback(dpid):
    assert(dpid is not None)

    logger.info("Switch '%s' has left the network" % str(dpid))
    if not topology.data.has_key(dpid):
        logger.debug("No switches to be deleted from topology data model")
    else:
        topology.data.pop(dpid)
        logger.info("Deleted info for switch '%s'" % str(dpid))

class topologymgr(Component):
    def __init__(self, ctxt):
        global inst
        Component.__init__(self, ctxt)
        self.st  = { }
        inst = self

    def install(self):
        inst.register_for_datapath_leave(datapath_leave_callback)
        inst.register_for_datapath_join(datapath_join_callback)
	#inst.register_for_flow_removed(flow_removed_callback)

    def getInterface(self):
        return str(topologymgr)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return topologymgr(ctxt)

    return Factory()
