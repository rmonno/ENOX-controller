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


@bottle.route('/hello')
def hello():
    evt_ = nxw_utils.Pck_setFlowEntryEvent('192.168.1.1', '192.168.1.2')
    PROXY_POST(evt_.describe())
    return "Hello World!"


@bottle.get('/dpids')
def dpids():
    WLOG.info("Enter http dpids")
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.datapath_select()
        resp_ = nxw_utils.HTTPResponseGetDPIDS([str(r['id']) for r in rows_])
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("dpids: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/dpids/<dpid:int>')
def dpid_info(dpid):
    WLOG.info("Enter http dpid_info: dpid=%d", dpid)
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.datapath_select(d_id=dpid)

        if len(rows_) > 1:
            bottle.abort(500, 'Duplicated key!')

        resp_ = nxw_utils.HTTPResponseGetDPIDInfo(db_row=rows_[0])
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("dpid_info: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/ports')
def ports():
    WLOG.info("Enter http ports")
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.port_select()
        ids_ = [(r['datapath_id'], r['port_no']) for r in rows_]
        resp_ = nxw_utils.HTTPResponseGetPORTS(ids_)
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("ports: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/ports/')
def port_info():
    dpid_ = int(bottle.request.query.dpid)
    portno_ = int(bottle.request.query.portno)

    WLOG.info("Enter http port_info: dpid=%d, portno=%d", dpid_, portno_)
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.port_select(d_id=dpid_, port_no=portno_)

        if len(rows_) > 1:
            bottle.abort(500, 'Duplicated key!')

        resp_ = nxw_utils.HTTPResponseGetPORTInfo(db_row=rows_[0])
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("port_info: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/links')
def links():
    WLOG.info("Enter http links")
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.link_select()
        ids_ = [(r['src_dpid'], r['src_pno'],
                 r['dst_dpid'], r['dst_pno']) for r in rows_]
        resp_ = nxw_utils.HTTPResponseGetLINKS(ids_)
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("links: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/hosts')
def hosts():
    WLOG.info("Enter http hosts")
    try:
        PROXY_DB.open_transaction()
        rows_ = PROXY_DB.host_select()
        ids_ = [(r['dpid'], r['ip_addr'],
                 r['in_port'], r['mac_addr']) for r in rows_]
        resp_ = nxw_utils.HTTPResponseGetHOSTS(ids_)
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("hosts: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.get('/pckt_flows/<dpid:int>')
def pckt_flows(dpid):
    WLOG.info("Enter http pckt_flows: dpid=%d", dpid)
    try:
        PROXY_DB.open_transaction()
        ids_ = PROXY_DB.flow_select(dpid=dpid)
        resp_ = nxw_utils.HTTPResponseGetPCKTFLOWS(ids_)
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("pckt_flows: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


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
