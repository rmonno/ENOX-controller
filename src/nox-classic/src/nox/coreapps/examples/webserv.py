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
""" Web-Server NOX application """

import sys
import os
import logging

import bottle
import threading

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

WLOG = nxw_utils.ColorLog(logging.getLogger('web-log'))
PROXY_POST = None


@bottle.route('/hello')
def hello():
    evt_ = nxw_utils.Pck_setFlowEntryEvent('192.168.1.1', '192.168.1.2')
    PROXY_POST(evt_.describe())
    return "Hello World!"


class Service(threading.Thread):
    def __init__(self, name, host, port, debug):
        threading.Thread.__init__(self, name=name)
        self._host = host
        self._port = port
        self._debug = debug
        self.daemon = True
        self.start()

    def run(self):
        WLOG.debug("Starting web-server thread")
        bottle.run(host=self._host, port=self._port, debug=self._debug)


class WebServMgr(Component):
    """ Web-Server Manager Class """
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf = nxw_utils.WebServConfigParser(WebServMgr.CONFIG_FILE)
        self._server = None

    def install(self):
        """ Install """
        global PROXY_POST
        self._server = Service('web-server', self._conf.host,
                               self._conf.port, self._conf.debug)
        self.post_callback(int(self._conf.timeout), self.timer_handler)

        PROXY_POST = self.post

    def getInterface(self):
        """ Get interface """
        return str(WebServMgr)

    def timer_handler(self):
        WLOG.debug("WebServMgr timeout fired")
        if self._server.isAlive():
            self.post_callback(int(self._conf.timeout), self.timer_handler)
        else:
            WLOG.error('WebServer is not running!')


def getFactory():
    """ Get factory """
    class Factory:
        """ Class Factory """
        def instance(self, ctxt):
            """ Return Web-Server Manager object """
            return WebServMgr(ctxt)

    return Factory()
