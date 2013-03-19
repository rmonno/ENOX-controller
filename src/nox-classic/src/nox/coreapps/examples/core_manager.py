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
""" Core-Manager NOX application """

from nox.coreapps.pyrt.pycomponent import CONTINUE

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

WLOG = nxw_utils.ColorLog(logging.getLogger('core-manager'))
PROXY_POST = None
PROXY_DB = None
PROXY_PCE_CHECK = None
PROXY_PCE = None


# utilities
def create_node_ipv4(dpid, portno):
    try:
        PROXY_DB.open_transaction()
        didx = PROXY_DB.datapath_get_index(dpid)
        pidx = PROXY_DB.port_get_index(dpid, portno)
        return nxw_utils.createNodeIPv4(didx, pidx)

    finally:
        PROXY_DB.close()


def datapath_leave_db_actions(dpid):
    nodes = []
    links = []
    hosts = []
    try:
        PROXY_DB.open_transaction()

        d_idx  = PROXY_DB.datapath_get_index(d_id=dpid)
        p_idxs = PROXY_DB.port_get_indexes(d_id=dpid)
        for p_idx in p_idxs:
            nodes.append(nxw_utils.createNodeIPv4(d_idx, p_idx))

        try: # optional
            h_idxs = PROXY_DB.host_get_indexes(d_id=dpid)
            for in_port, ip_addr in h_idxs:
                port = PROXY_DB.port_get_index(d_id=dpid, port_no=in_port)
                node = nxw_utils.createNodeIPv4(d_idx, port)

                links.append((ip_addr, node))
                hosts.append(ip_addr)

        except nxw_utils.DBException as err:
            WLOG.error("host_get_indexes: " + str(err))

        try: # optional
            l_idxs = PROXY_DB.link_get_indexes(src_dpid=dpid)
            for src_pno, dst_dpid, dst_pno in l_idxs:
                src_port = PROXY_DB.port_get_index(d_id=dpid, port_no=src_pno)
                src_node = nxw_utils.createNodeIPv4(d_idx, src_port)

                dst_id = PROXY_DB.datapath_get_index(d_id=dst_dpid)
                dst_port = PROXY_DB.port_get_index(d_id=dst_dpid, port_no=dst_pno)
                dst_node = nxw_utils.createNodeIPv4(dst_id, dst_port)

                links.append((src_node, dst_node))

        except nxw_utils.DBException as err:
            WLOG.error("link_get_indexes: " + str(err))

    except nxw_utils.DBException as err:
        WLOG.error("dp_leave_db_actions: " + str(err))

    finally:
        PROXY_DB.close()

    return (nodes, links, hosts)


# HTTP southbound interface
#
# POST /pckt_dpid + json params
@bottle.post('/pckt_dpid')
def pckt_dpid_create():
    WLOG.info("Enter http pckt_dpid_create")

    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    dpid_ = bottle.request.json['dpid']
    try:
        PROXY_DB.open_transaction()
        PROXY_DB.datapath_insert(d_id=dpid_,
                                 d_name="ofswitch-" + str(dpid_),
                                 caps=bottle.request.json['ofp_capabilities'],
                                 actions=bottle.request.json['ofp_actions'],
                                 buffers=bottle.request.json['buffers'],
                                 tables=bottle.request.json['tables'])

        for port in bottle.request.json['ports']:
            PROXY_DB.port_insert(d_id=dpid_,
                                 port_no=port['port_no'],
                                 hw_addr=port['hw_addr'],
                                 name=port['name'],
                                 config=port['config'],
                                 state=port['state'],
                                 curr=port['curr'],
                                 advertised=port['advertised'],
                                 supported=port['supported'],
                                 peer=port['peer'])

        PROXY_DB.commit()
        WLOG.debug("Successfull committed information!")

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_dpid_create: " + str(err))

    finally:
        PROXY_DB.close()

    if not PROXY_PCE_CHECK('topology'):
        bottle.abort(500, "Unable to contact ior-dispatcher on PCE node!")

    nodes = []
    try:
        for port in bottle.request.json['ports']:
            node = create_node_ipv4(dpid_, port['port_no'])
            nodes.append(node)

    except Exception as err:
        WLOG.error("pckt_dpid_create: " + str(err))
        bottle.abort(500, str(err))

    WLOG.debug("Nodes=%s", nodes)
    # update flow-pce topology (nodes)
    for node in nodes:
        PROXY_PCE.add_node_from_string(node)

    # update flow-pce topology (links)
    for node in nodes:
        others = [n for n in nodes if n != node]

        for oth in others:
            PROXY_PCE.add_link_from_strings(node, oth)

    return bottle.HTTPResponse(body='Operation completed', status=201)


# DELETE /pckt_dpid/<id>
@bottle.delete('/pckt_dpid/<id:int>')
def pckt_dpid_delete(id):
    WLOG.info("Enter http pckt_dpid_delete: id=%d", id)
    if PROXY_PCE_CHECK('topology'):
        (nodes, links, hosts) = datapath_leave_db_actions(id)

        WLOG.info("nodes=%s", nodes)
        for node in nodes:
            others = [n for n in nodes if n != node]

            for oth in others:
                PROXY_PCE.del_link_from_strings(node, oth)

        WLOG.info("links=%s", links)
        for src, dst in links:
            PROXY_PCE.del_link_from_strings(src, dst)
            PROXY_PCE.del_link_from_strings(dst, src)

        for node in nodes:
            PROXY_PCE.del_node_from_string(node)

        WLOG.info("hosts=%s", hosts)
        for host in hosts:
            PROXY_PCE.del_node_from_string(host)

    try:
        PROXY_DB.open_transaction()
        PROXY_DB.datapath_delete(d_id=id)
        PROXY_DB.commit()
        WLOG.debug("Successfull committed information!")

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_dpid_delete: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()

    return bottle.HTTPResponse(body='Operation completed', status=204)


# POST /pckt_intersw_link + json params
@bottle.post('/pckt_intersw_link')
def pckt_intersw_link_create():
    WLOG.info("Enter http pckt_intersw_link_create")

    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    src_dpid_ = bottle.request.json['src_dpid']
    dst_dpid_ = bottle.request.json['dst_dpid']
    src_portno_ = bottle.request.json['src_portno']
    dst_portno_ = bottle.request.json['dst_portno']
    try:
        PROXY_DB.open_transaction()
        PROXY_DB.link_insert(src_dpid=src_dpid_, src_pno=src_portno_,
                             dst_dpid=dst_dpid_, dst_pno=dst_portno_)
        PROXY_DB.commit()
        WLOG.debug("Successfull committed information!")

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_intersw_link_create: " + str(err))

    finally:
        PROXY_DB.close()

    if not PROXY_PCE_CHECK('topology'):
        bottle.abort(500, "Unable to contact ior-dispatcher on PCE node!")

    try:
        src_node_ = create_node_ipv4(src_dpid_, src_portno_)
        dst_node_ = create_node_ipv4(dst_dpid_, dst_portno_)
        WLOG.debug("Src Node=%s, Dst Node=%s", src_node_, dst_node_)

        PROXY_PCE.add_link_from_strings(src_node_, dst_node_)
        PROXY_PCE.add_link_from_strings(dst_node_, src_node_)

    except Exception as err:
        WLOG.error("pckt_intersw_link_create: " + str(err))
        bottle.abort(500, str(err))

    return bottle.HTTPResponse(body='Operation completed', status=201)


# DELETE /pckt_intersw_link
@bottle.delete('/pckt_intersw_link')
def pckt_intersw_link_delete():
    WLOG.info("Enter http pckt_intersw_link_delete")

    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    src_dpid_ = bottle.request.json['src_dpid']
    dst_dpid_ = bottle.request.json['dst_dpid']
    src_portno_ = bottle.request.json['src_portno']
    dst_portno_ = bottle.request.json['dst_portno']

    if PROXY_PCE_CHECK('topology'):
        src_node_ = create_node_ipv4(src_dpid_, src_portno_)
        dst_node_ = create_node_ipv4(dst_dpid_, dst_portno_)
        WLOG.debug("Src Node=%s, Dst Node=%s", src_node_, dst_node_)

        PROXY_PCE.del_link_from_strings(src_node_, dst_node_)
        PROXY_PCE.del_link_from_strings(dst_node_, src_node_)

    try:
        PROXY_DB.open_transaction()
        PROXY_DB.link_delete(src_dpid=src_dpid_, src_pno=src_portno_)
        PROXY_DB.commit()
        WLOG.debug("Successfull committed information!")

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_intersw_link_delete: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()

    return bottle.HTTPResponse(body='Operation completed', status=204)


# HTTP northbound interface
#
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


@bottle.get('/pckt_flows/<id:int>')
def pckt_flows(id):
    WLOG.info("Enter http pckt_flows: dpid=%d", id)
    try:
        PROXY_DB.open_transaction()
        ids_ = PROXY_DB.flow_select(dpid=id)
        resp_ = nxw_utils.HTTPResponseGetPCKTFLOWS(ids_)
        return resp_.body()

    except nxw_utils.DBException as err:
        WLOG.error("pckt_flows: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.delete('/pckt_flows/<id:int>')
def pckt_flow_delete(id):
    WLOG.info("Enter http pckt_flow_delete: id=%d", id)
    try:
        PROXY_DB.open_transaction()
        PROXY_DB.flow_delete(idd=id)
        PROXY_DB.commit()
        return bottle.HTTPResponse(body='Operation completed', status=204)

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_flow_delete: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


@bottle.post('/pckt_flows')
def pckt_flow_create():
    WLOG.info("Enter http pckt_flow_create")
    try:
        PROXY_DB.open_transaction()
        PROXY_DB.flow_insert(dpid=bottle.request.params.get('dpid'),
            table_id=bottle.request.params.get('table_id'),
            action=bottle.request.params.get('action'),
            idle_timeout=bottle.request.params.get('idle_timeout'),
            hard_timeout=bottle.request.params.get('hard_timeout'),
            priority=bottle.request.params.get('priority'),
            cookie=bottle.request.params.get('cookie'),
            dl_type=bottle.request.params.get('datalink_type'),
            dl_vlan=bottle.request.params.get('datalink_vlan'),
            dl_vlan_pcp=bottle.request.params.get('datalink_vlan_priority'),
            dl_src=bottle.request.params.get('datalink_source'),
            dl_dst=bottle.request.params.get('datalink_destination'),
            nw_src=bottle.request.params.get('network_source'),
            nw_dst=bottle.request.params.get('network_destination'),
            nw_src_n_wild=bottle.request.params.get('network_source_num_wild'),
            nw_dst_n_wild=bottle.request.params.get('network_destination_num_wild'),
            nw_proto=bottle.request.params.get('network_protocol'),
            tp_src=bottle.request.params.get('transport_source'),
            tp_dst=bottle.request.params.get('transport_destination'),
            in_port=bottle.request.params.get('input_port'))

        PROXY_DB.commit()
        return bottle.HTTPResponse(body='Operation completed', status=201)

    except nxw_utils.DBException as err:
        PROXY_DB.rollback()
        WLOG.error("pckt_flow_create: " + str(err))
        bottle.abort(500, str(err))

    finally:
        PROXY_DB.close()


class CoreService(threading.Thread):
    def __init__(self, name, host, port, debug):
        threading.Thread.__init__(self, name=name)
        self._host = host
        self._port = port
        self._debug = debug
        self.daemon = True
        self.start()

    def run(self):
        WLOG.debug("Starting core-service thread")
        bottle.run(host=self._host, port=self._port, debug=self._debug)


class CoreManager(Component):
    """ Core-Manager Class """
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_ws = nxw_utils.WebServConfigParser(CoreManager.CONFIG_FILE)
        self._conf_db = nxw_utils.DBConfigParser(CoreManager.CONFIG_FILE)
        self._conf_pce = nxw_utils.NoxConfigParser(CoreManager.CONFIG_FILE)
        self._fpce = nxw_utils.FPCE()
        self._server = None

        self._ior_topo = False
        self._ior_rout = False
        self._pce_client = nxw_utils.PCEClient(self._conf_pce.address,
                                               self._conf_pce.port,
                                               int(self._conf_pce.size))
        self._pce_client.create()

    def __pce_interface_enable(self, interf):
        WLOG.debug("Retrieving IOR for %s requests" % interf)
        try:
            r_ = self._pce_client.send_msg(interf)
            if r_ is None:
                return (False, None)

            WLOG.debug("Received the following response: %s", str(r_))
            pr_ = self._pce_client.decode_requests(r_)
            if not pr_:
                WLOG.error("Got an error in response parsing...")
                return (False, None)

            WLOG.info("Received the following IOR: '%s'", str(pr_))
            return (True, pr_)

        except Exception as err:
            WLOG.error("Pce Interface Failure: %s", str(err))
            return (False, None)

    def pce_topology_enable(self):
        """ Enable PCE-topology """
        (self._ior_topo, ior) = self.__pce_interface_enable("topology")
        if self._ior_topo:
            self._fpce.ior_topology_add(ior)

        return self._ior_topo

    def pce_routing_enable(self):
        """ Enable PCE-routing """
        (self._ior_rout, ior) = self.__pce_interface_enable("routing")
        if self._ior_rout:
            self._fpce.ior_routing_add(ior)

        return self._ior_rout

    def pce_check(self, interf):
        if interf == 'topology':
            if not self._ior_topo and not self.pce_topology_enable():
                return False

        elif interf == 'routing':
            if not self._ior_rout and not self.pce_routing_enable():
                return False

        return True

    def configure(self, configuration):
        """ Enable communication to flow-pce """
        self.pce_topology_enable()
        self.pce_routing_enable()

        """ Register python events """
        #self.register_python_event(nxw_utils.Pck_setFlowEntryEvent.NAME)
        return CONTINUE

    def install(self):
        """ Install """
        global PROXY_POST
        global PROXY_DB
        global PROXY_PCE_CHECK
        global PROXY_PCE
        self._server = CoreService('core-service', self._conf_ws.host,
                                   self._conf_ws.port, self._conf_ws.debug)
        self.post_callback(int(self._conf_ws.timeout), self.timer_handler)

        PROXY_POST = self.post
        PROXY_DB = nxw_utils.TopologyOFCManager(host=self._conf_db.host,
                                                user=self._conf_db.user,
                                                pswd=self._conf_db.pswd,
                                                database=self._conf_db.name,
                                                logger=WLOG)
        PROXY_PCE_CHECK = self.pce_check
        PROXY_PCE = self._fpce
        return CONTINUE

    def getInterface(self):
        """ Get interface """
        return str(CoreManager)

    def timer_handler(self):
        WLOG.debug("CoreManager timeout fired")
        if self._server.isAlive():
            self.post_callback(int(self._conf_ws.timeout), self.timer_handler)
        else:
            WLOG.error('CoreManager is not running!')


def getFactory():
    """ Get factory """
    class Factory:
        """ Class Factory """
        def instance(self, ctxt):
            """ Return Core-Manager object """
            return CoreManager(ctxt)

    return Factory()
