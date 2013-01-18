#
# entities
#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Alessandro Canessa    <a DOT canessa AT nextworks DOT it>
#

import logging as log
import pickle
import socket
import pox.openflow.topology as of_topology
log.basicConfig(level=log.DEBUG)

ents_supp = {'OpenFlowSwitch': "OFSwitch"}

class Topology(object):
    def __init__(self):
        self.ofswitches = { }
        self.hosts      = { }
        self.links      = { }

    def add_entity(self, entity):
        if (entity.__class__.__name__ == "OpenFlowSwitch"):
            self.add_ofswitch(entity)

    def add_ofswitch(self, ofswitch):
        self.ofswitches[ofswitch.dpid] = ofswitch

    def of_switch_dpids_get(self):
        return self.ofswitches.keys()

    def serialize(self):
        serialized = { }
        # XXX FIXME: Return all serialized dictionaries (also hosts and links)
        for i in self.ofswitches:
            serialized[i] = pickle.dumps(self.ofswitches[i])
        return serialized

    def __str__(self):
        ret = ""
        for i in self.ofswitches:
            ret += str(self.ofswitches[i])
        return ret

class OFSwitch(of_topology.OpenFlowSwitch):
    def __init__(self, dpid):
        self.dpid         = dpid
        #super(OFSwitch, self).__init__(dpid)

    def create(self, dpid, ports, flow_table, caps, connection, listeners):
        self.dpid         = dpid
        self.ports        = ports
        self.flow_table   = flow_table
        self.capabilities = caps
        self._connection  = connection
        # XXX FIXME: Maybe useless for our scope
        self._listeners   = listeners

    def serialize(self):
        return pickle.dumps(self)

    def __str__(self):
        ret = "OFSwitch(DPID='%s', PORTS='%s', FLOWTABLE='%s'," % \
                (str(self.dpid),
                 str(self.ports),
                 str(self.flow_table.entries)) + \
               "CAPS='%s', CONNS='%s', LISTNERS='%s')" % \
                (str(self.capabilities),
                 str(self._connection),
                 str(self._listeners))
        return ret
