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
from nox.coreapps.pyrt.pycomponent import CONTINUE

import sys
import os
import logging

import bottle
import threading
import json
import requests
from fysom import Fysom, FysomError

from nox.lib.core import Component

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

DCLOG = nxw_utils.ColorLog(logging.getLogger('discovery-circuit-emul'))

# HTTP interface
#
@bottle.get('/hello_world')
def hello_world():
    DCLOG.info("ok!")
    return "Hello World!"


class DCemulFSM(Fysom):
    def __init__(self, host, port):
        super(DCemulFSM, self).__init__({
            'initial': 'dpid',
            'events': [{'name':'fire', 'src':'dpid', 'dst':'port'},
                       {'name':'fire', 'src':'port', 'dst':'end'},
                       {'name':'fire', 'src':'end', 'dst':'dpid'}]
        })
        self._url = "http://" + str(host) + ":" + str(port) + "/"
        self._hs = {'content-type': 'application/json'}

    def onleavedpid(self, e):
        DCLOG.info("%s->%s called..." % (e.src, e.dst,))
        r_ = requests.get(url=self._url + "dpids")
        DCLOG.debug("Response=%s" % r_.text)

        payload = {"dpid": 1,
                   "region": "circuit_bristol",
                   "ofp_capabilities": 0xff,
                   "ofp_actions": 0xeb,
                   "buffers": 2,
                   "tables": 9,
                   "ports": []}
        r_ = requests.post(url=self._url + "pckt_dpid", headers=self._hs,
                           data=json.dumps(payload))
        DCLOG.debug("URL=%s, response(code=%d, content=%s)",
                    r_.url, r_.status_code, str(r_.content))

    def onleaveport(self, e):
        DCLOG.info("%s->%s called..." % (e.src, e.dst,))

    def onleaveend(self, e):
        DCLOG.info("%s->%s called..." % (e.src, e.dst,))


class DiscoveryCircuitService(threading.Thread):
    def __init__(self, name, host, port, debug):
        threading.Thread.__init__(self, name=name)
        self._host = host
        self._port = port
        self._debug = debug
        self.daemon = True
        self.start()

    def run(self):
        DCLOG.debug("Starting thread: %s,%s" % (self._host, self._port))
        bottle.run(host=self._host, port=self._port, debug=self._debug)


class DiscoveryCircuitEmul(Component):
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_ws = nxw_utils.WebServConfigParser(self.CONFIG_FILE)
        self._server = None
        self._fsm = DCemulFSM(self._conf_ws.host, self._conf_ws.port)

    def install(self):
        port = int(self._conf_ws.port) + 1
        self._server = DiscoveryCircuitService('dc-emul-service',
                                               self._conf_ws.host,
                                               str(port),
                                               self._conf_ws.debug)
        self.post_callback(int(self._conf_ws.timeout), self.timer_handler)
        return CONTINUE

    def getInterface(self):
        return str(DiscoveryCircuitEmul)

    def timer_handler(self):
        DCLOG.debug("DC-emul timeout fired")
        if self._server.isAlive():
            self.post_callback(int(self._conf_ws.timeout), self.timer_handler)
            try:
                self._fsm.fire()

            except FysomError as e:
                DCLOG.error(str(e))
        else:
            DCLOG.error('DC-emul is NOT running!')


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return DiscoveryCircuitEmul(ctxt)

    return Factory()
