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
PROXY_DB = None


# API
methods = ["hello", "help", "get_dpids", "get_links", "get_hosts", \
           "get_dpid_info/dpid", "get_dpid_stats/dpid",
           "get_dpid_flowentries/dpid", "get_dpid_links/dpid"]

@bottle.route('/hello')
def hello():
    evt_ = nxw_utils.Pck_setFlowEntryEvent('192.168.1.1', '192.168.1.2')
    PROXY_POST(evt_.describe())
    return "Hello World!"


@bottle.route('/help')
def get_methods():
    return "Supported methods: %s" % str(methods)


@bottle.get('/dpids')
def dpids():
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.datapath_select()
        ids_ = [str(r['id']) for r in rows_]

        return {'ids': ids_}

    except nxw_utils.DBException as err:
        WLOG.error("dpids: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/dpids/<dpid:int>')
def dpids_dpid(dpid):
    try:
        PROXY_DB.open_transaction()
        row_ = PROXY_DB.datapath_select(d_id=dpid)

        if len(row_) > 1:
            bottle.abort(500, 'Duplicated key!')

        return row_[0]

    except nxw_utils.DBException as err:
        WLOG.error("dpids_dpid: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.route('/get_links')
def get_links():
    pass

@bottle.route('/get_hosts')
def get_hosts():
    pass

@bottle.route('/get_dpid_info/:dpid')
def get_dpid_info(dpid):
    return "DPID '%s' INFO = xxx" % str(dpid)

@bottle.route('/get_dpid_stats/:dpid')
def get_dpid_stats(dpid):
    return "DPID '%s' STATS = xxx" % str(dpid)

@bottle.route('/get_dpid_flowentries/:dpid')
def get_dpid_flowentries(dpid):
    return "dpid '%s' flowentries = xxx" % str(dpid)

@bottle.route('/get_dpid_links/:dpid')
def get_dpid_links(dpid):
    return "dpid '%s' links = xxx" % str(dpid)


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
        self._conf_db = nxw_utils.DBConfigParser(WebServMgr.CONFIG_FILE)
        self._server = None

    def install(self):
        """ Install """
        global PROXY_POST
        global PROXY_DB
        self._server = Service('web-server', self._conf.host,
                               self._conf.port, self._conf.debug)
        self.post_callback(int(self._conf.timeout), self.timer_handler)

        PROXY_POST = self.post
        PROXY_DB = nxw_utils.TopologyOFCManager(host=self._conf_db.host,
                                                user=self._conf_db.user,
                                                pswd=self._conf_db.pswd,
                                                database=self._conf_db.name,
                                                logger=WLOG)

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
