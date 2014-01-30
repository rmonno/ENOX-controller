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
""" Discovey Circuit NOX application """

from nox.lib.core import Component

import sys
import os
#import json
#import requests
import logging
from fysom import Fysom

# update sys python path
KEY = 'nox-classic'
BASEPATH  = os.path.dirname(os.path.abspath(sys.argv[0]))
NOX_INDEX = BASEPATH.find(KEY)

LIBS_PATH = BASEPATH[0:NOX_INDEX-1]
sys.path.insert(0, LIBS_PATH)

IDL_FIND_PATH = BASEPATH[0:NOX_INDEX] + KEY + '/build/src'
for (root, dirs, names) in os.walk(IDL_FIND_PATH):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')

import libs as nxw_utils

LOG = nxw_utils.ColorLog(logging.getLogger('discovery_circuit'))


class FSM(Fysom):
    def __init__(self, address, port, region):
        self.url = "http://%s:%s/" % (address, port)
        self.hs = {'content-type': 'application/json'}
        self.region = region
        self.dpids = []
        self.ports = []
        self.links = []

        super(FSM, self).__init__({
            'initial': 'init',
            'events': [{'name': 'click', 'src': 'init', 'dst': 'get'},
                       {'name': 'click', 'src': 'get', 'dst': 'update'},
                       {'name': 'click', 'src': 'update', 'dst': 'clean'},
                       {'name': 'click', 'src': 'clean', 'dst': 'get'}]
        })

    def onbeforeclick(self, e):
        if e.src == 'get' and (not len(self.dpids) and
                               not len(self.ports) and not len(self.links)):
            LOG.info("Do not leave GET, not information are available!")
            self.onget(e)
            return False

        if e.src == 'update' and (len(self.dpids) or
                                  len(self.ports) or len(self.links)):
            LOG.info("Do not leave UPDATE, ongoing db-update procedure!")
            self.onupdate(e)
            return False

        return True

    def onget(self, e):
        LOG.info("FSM-get: src=%s, dst=%s" % (e.src, e.dst,))

    def onupdate(self, e):
        LOG.info("FSM-update: src=%s, dst=%s" % (e.src, e.dst,))

        if len(self.dpids):
            LOG.debug("Missing dpids=%d" % (len(self.dpids),))

        elif len(self.ports):
            LOG.debug("Missing ports=%d" % (len(self.ports),))

        elif len(self.links):
            LOG.debug("Missing links=%d" % (len(self.links),))

    def onclean(self, e):
        LOG.info("FSM-clean: src=%s, dst=%s" % (e.src, e.dst,))

        del self.dpids[:]
        del self.ports[:]
        del self.links[:]


class DiscoveryCircuit(Component):
    FCONFIG = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.ccp_ = nxw_utils.CircuitConfigParser(DiscoveryCircuit.FCONFIG)
        self.timeout = self.ccp_.timeout
        self.fsm_ = FSM(self.ccp_.address, self.ccp_.port,
                        self.ccp_.circuit_region)

    def configure(self, configuration):
        LOG.debug('configuring %s' % str(self.__class__.__name__))

    def install(self):
        self.post_callback(int(self.timeout), self.timer_handler)

    def timer_handler(self):
        LOG.debug("%s timeout fired" % str(self.__class__.__name__))
        self.fsm_.click()
        self.post_callback(int(self.timeout), self.timer_handler)

    def getInterface(self):
        return str(DiscoveryCircuit)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return DiscoveryCircuit(ctxt)

    return Factory()
