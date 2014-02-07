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
import requests
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
PROXY_DB = None


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
        if e.src == 'get' and (not len(self.dpids) or
                               not len(self.ports) or not len(self.links)):
            LOG.debug("Do not leave GET, info incompleted!")
            self.onget(e)
            return False

        if e.src == 'update' and (len(self.dpids) or
                                  len(self.ports) or len(self.links)):
            LOG.debug("Do not leave UPDATE, ongoing db-update procedure!")
            self.onupdate(e)
            return False

        return True

    def seq_val(self, obj, i):
        if i in range(len(obj)):
            return obj[i]

        return None

    def __get_dpids(self):
        try:
            r_ = requests.get(url=self.url + 'get_topology')
            if r_.status_code != requests.codes.ok:
                LOG.error(r_.text)
                return

            LOG.debug("Response=%s" % r_.text)
            self.dpids = [(v_.get('id'), v_.get('noofports'), v_.get('swtype'),
                           v_.get('swcap'), v_.get('regtime', None))
                          for v_ in r_.json()['switches']]

        except Exception as e:
            LOG.error('get_dpid exec: %s', (e,))

        LOG.debug('dpids(%d)=%s', len(self.dpids), self.dpids)

    def __get_ports(self):
        for dpid_ in self.dpids:
            self.__get_dpid_ports(self.seq_val(dpid_, 0))

        LOG.debug('ports(%d)=%s', len(self.ports), self.ports)

    def __get_dpid_ports(self, dpid):
        try:
            r_ = requests.get(url=self.url +
                              'get_topology_ports/' + dpid)
            if r_.status_code != requests.codes.ok:
                LOG.error(r_.text)
                return

            LOG.debug("Response=%s" % r_.text)
            info_ = [(dpid, v_.get('portnum'), v_.get('portname'),
                      v_.get('portconfig'), v_.get('peercap', None),
                      v_.get('peerdpid', None), v_.get('peerportnum', None),
                      v_.get('portbw', None))
                     for v_ in r_.json()['switches']]

            self.ports.extend(info_)

        except Exception as e:
            LOG.error('get_dpid_ports exec: %s', (e,))

    def __get_links(self):
        self.links = [(dpid, num, pdpid, ppno, bw)
                for dpid, num, name, conf, caps, pdpid, ppno, bw in self.ports]

        LOG.debug('links(%d)=%s', len(self.links), self.links)

    def onget(self, e):
        LOG.debug("FSM-get: src=%s, dst=%s" % (e.src, e.dst,))
        if not len(self.dpids):
            self.__get_dpids()

        elif not len(self.ports):
            self.__get_ports()

        else:
            self.__get_links()

    def __update(self, values, types, fget, finsert, fupdate):
        try:
            PROXY_DB.open_transaction()
            ret = False
            for info in values:
                action_ = fget(info)
                if action_ == 'INSERT':
                    ret = finsert(info)
                elif action_ == 'UPDATE':
                    ret = fupdate(info)

            if ret is True:
                PROXY_DB.commit()
                LOG.debug("Successfull committed information (%s)!" % (types,))

            del values[:]

        finally:
            PROXY_DB.close()

    def __get_dpid_db(self, info):
        try:
            values_ = PROXY_DB.datapath_select(d_id=self.seq_val(info, 0))

            if values_[0]['cports'] != self.seq_val(info, 1) or\
               values_[0]['ofp_capabilities'] != self.seq_val(info, 3):
                return 'UPDATE'

        except nxw_utils.DBException:
            return 'INSERT'

        return 'SKIP'

    def __get_port_db(self, info):
        try:
            values_ = PROXY_DB.port_select(d_id=self.seq_val(info, 0),
                                           port_no=self.seq_val(info, 1))

            if values_[0]['name'] != self.seq_val(info, 2) or\
               values_[0]['curr'] != self.seq_val(info, 3) or\
               values_[0]['supported'] != self.seq_val(info, 4) or\
               values_[0]['peer_dpath_id'] != self.seq_val(info, 5) or\
               values_[0]['peer_port_no'] != self.seq_val(info, 6):
                return 'UPDATE'

        except nxw_utils.DBException:
            return 'INSERT'

        return 'SKIP'

    def __get_link_db(self, info):
        try:
            values_ = PROXY_DB.link_select(src_dpid=self.seq_val(info, 0),
                                           src_pno=self.seq_val(info, 1))

            bw_ = self.seq_val(info, 4) if self.seq_val(info, 4) else 1000

            if values_[0]['dst_dpid'] != self.seq_val(info, 2) or\
               values_[0]['dst_pno'] != self.seq_val(info, 3) or\
               values_[0]['available_bw'] != bw_:
                return 'UPDATE'

        except nxw_utils.DBException:
            return 'INSERT'

        return 'SKIP'

    def __insert_dpid_db(self, info):
        try:
            name_ = self.seq_val(info, 2) + '_' + self.region
            PROXY_DB.datapath_insert(d_id=self.seq_val(info, 0),
                                     d_name=name_,
                                     caps=self.seq_val(info, 3),
                                     cports=self.seq_val(info, 1))
            return True

        except nxw_utils.DBException as err:
            LOG.error("(insert_dpid_db) %s" % (err,))
            return False

    def __insert_port_db(self, info):
        try:
            PROXY_DB.port_insert(d_id=self.seq_val(info, 0),
                                 port_no=self.seq_val(info, 1),
                                 name=self.seq_val(info, 2),
                                 curr=self.seq_val(info, 3),
                                 supported=self.seq_val(info, 4),
                                 peer_dpath_id=self.seq_val(info, 5),
                                 peer_port_no=self.seq_val(info, 6))
            return True

        except nxw_utils.DBException as err:
            LOG.error("(insert_port_db) %s" % (err,))
            return False

    def __insert_link_db(self, info):
        try:
            # default value: 1000 - 1 Gb half/full-duplex
            bw_ = self.seq_val(info, 4) if self.seq_val(info, 4) else 1000
            PROXY_DB.link_insert(src_dpid=self.seq_val(info, 0),
                                 src_pno=self.seq_val(info, 1),
                                 dst_dpid=self.seq_val(info, 2),
                                 dst_pno=self.seq_val(info, 3),
                                 bandwidth=bw_,
                                 domain="circuit")
            return True

        except nxw_utils.DBException as err:
            LOG.error("(insert_link_db) %s" % (err,))
            return False

    def __update_dpid_db(self, info):
        LOG.error('Not supported yet!')
        return False

    def __update_port_db(self, info):
        LOG.error('Not supported yet!')
        return False

    def __update_link_db(self, info):
        LOG.error('Not supported yet!')
        return False

    def onupdate(self, e):
        LOG.debug("FSM-update: src=%s, dst=%s" % (e.src, e.dst,))

        if len(self.dpids):
            self.__update(self.dpids, "dpids", self.__get_dpid_db,
                          self.__insert_dpid_db, self.__update_dpid_db)

        elif len(self.ports):
            self.__update(self.ports, "ports", self.__get_port_db,
                          self.__insert_port_db, self.__update_port_db)

        elif len(self.links):
            self.__update(self.links, "links", self.__get_link_db,
                          self.__insert_link_db, self.__update_link_db)

    def onclean(self, e):
        LOG.debug("FSM-clean: src=%s, dst=%s" % (e.src, e.dst,))

        del self.dpids[:]
        del self.ports[:]
        del self.links[:]


class DiscoveryCircuit(Component):
    FCONFIG = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.db_ = nxw_utils.DBConfigParser(DiscoveryCircuit.FCONFIG)
        self.ccp_ = nxw_utils.CircuitConfigParser(DiscoveryCircuit.FCONFIG)
        self.timeout = self.ccp_.timeout
        self.fsm_ = FSM(self.ccp_.address, self.ccp_.port,
                        self.ccp_.circuit_region)

    def configure(self, configuration):
        LOG.debug('configuring %s' % str(self.__class__.__name__))

    def install(self):
        global PROXY_DB
        PROXY_DB = nxw_utils.TopologyOFCManager(host=self.db_.host,
                            user=self.db_.user, pswd=self.db_.pswd,
                            database=self.db_.name, logger=LOG)

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
