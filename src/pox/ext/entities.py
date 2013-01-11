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
log.basicConfig(level=log.DEBUG)

class Topology(object):
    def __init__(self):
        self.ofswitches = { }
        self.hosts      = { }
        self.links      = { }

    def add_entity(self, entity):
        if (entity.__class__.__name__ == "OpenFlowSwitch"):
            self.add_ofswitch(entity)

    def add_ofswitch(self, ofswitch):
        self.ofswitches[ofswitch.dpid] = OFSwitch(ofswitch.dpid,
                                                  ofswitch.ports,
                                                  ofswitch.capabilities)

    def serialize(self):
        serialized = { }
        # XXX FIXME: Return all serialized dictionaries (also hosts and links)
        for i in self.ofswitches:
            serialized[i] = pickle.dumps(self.ofswitches[i])
        return serialized

class OFSwitch(object):
    def __init__(self,
                 dpid  = None,
                 ports = None,
                 caps  = None):
        self.dpid  = dpid
        self.ports = { }
        self.caps  = 0

    def serialize(self):
        return pickle.dumps(self)
