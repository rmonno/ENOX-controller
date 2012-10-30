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
import nox.netapps.discovery.pylinkevent as event
import nox.netapps.discovery.discovery   as discovery

me     = "TopologyManager"
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

class TopologyManager(Component):
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.st   = { }
        self.data = { }

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

    def datapath_join_callback(self, dpid, attrs):
        assert(dpid  is not None)
        assert(attrs is not None)

        logger.info("Registred Switch '%s'"  % str(dpid))
        if self.data.has_key(dpid):
            logger.error("A switch with dpid '%s' has already registred" % \
                         str(dpid))
            return

        self.data[dpid] = attrs
        logger.debug(self.data)
        return CONTINUE

    def datapath_leave_callback(self, dpid):
        assert(dpid is not None)

        logger.info("Switch '%s' has left the network" % str(dpid))
        if not self.data.has_key(dpid):
            logger.debug("No switches to be deleted from topology data model")
        else:
            self.data.pop(dpid)
            logger.info("Deleted info for switch '%s'" % str(dpid))

    def handle_link_event(self, e):
        logger.debug("%s got the following event %s" % (me,
                                                        str(e)))
        logger.debug("Processing the following information: %s"
                      % str(e.__dict__))
        return CONTINUE

    def install(self):
        self.register_for_datapath_leave(self.datapath_leave_callback)
        self.register_for_datapath_join(self.datapath_join_callback)
        self.register_handler(event.Link_event_static_get_name(),
                              self.handle_link_event)

    def getInterface(self):
        return str(TopologyManager)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return TopologyManager(ctxt)

    return Factory()
