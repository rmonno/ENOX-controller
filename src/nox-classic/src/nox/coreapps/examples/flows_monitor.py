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
""" Flow-entries Monitoring NOX application """

import sys
import os
import logging
import requests
import json

from nox.lib.core import *
from nox.netapps.flow_fetcher.pyflow_fetcher import flow_fetcher_app
from nox.lib.netinet.netinet import datapathid

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

FFLOG = nxw_utils.ColorLog(logging.getLogger('flows-monitor'))

def opt(key_, dict_):
    if key_ in dict_:
        return dict_[key_]

    return None


class FlowsMonitor(Component):
    """ Flows-Monitor Class """
    FCONF = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_ff = nxw_utils.FlowsMonitorConfigParser(FlowsMonitor.FCONF)
        self._conf_ws = nxw_utils.WebServConfigParser(FlowsMonitor.FCONF)
        self._url = "http://%s:%s/" % (self._conf_ws.host, self._conf_ws.port)
        self._ffa = None
        self._queue = []
        self._table_queue = []
        self._port_queue = []

    def __get_dpids(self, rtype):
        try:
            r_ = requests.get(url=self._url + 'dpids')
            if r_.status_code != requests.codes.ok:
                return

            if rtype == 'flows':
                self._queue = [long(id_['dpid'], 16)
                               for id_ in r_.json()['dpids']]

            elif rtype == 'tables':
                self._table_queue = [long(id_['dpid'], 16)
                                     for id_ in r_.json()['dpids']]
            else:
                FFLOG.error("Unmanaged request-type!")

        except Exception as e:
            FFLOG.error(str(e))

    def __get_ports(self):
        try:
            r_ = requests.get(url=self._url + 'ports')
            if r_.status_code != requests.codes.ok:
                return

            self._port_queue = [(ids_['dpid'], ids_['port_no'])
                                for ids_ in r_.json()['ports']]

        except Exception as e:
            FFLOG.error(str(e))

    def __dpid_request(self):
        try:
            dpid = datapathid.from_host(self._queue.pop())
            FFLOG.debug("Request flows for dpid=%s", str(dpid))
            ff = self._ffa.fetch(dpid, {},
                                 lambda: self.__flows_replay(dpid, ff))

        except Exception as e:
            FFLOG.error(str(e))

    def __table_stats_request(self):
        try:
            dpid = self._table_queue.pop()
            FFLOG.debug("Request table-stats for dpid=%s", str(dpid))
            self.ctxt.send_table_stats_request(dpid)

        except Exception as e:
            FFLOG.error(str(e))

    def __port_stats_request(self):
        try:
            (dpid, portno) = self._port_queue.pop()
            FFLOG.debug("Request port-stats for dpid=%s, portno=%s",
                        str(dpid), str(portno))
            self.ctxt.send_port_stats_request(dpid, portno)

        except Exception as e:
            FFLOG.error(str(e))

    def __flows_request(self):
        if len(self._queue) == 0:
            self.__get_dpids('flows')
        else:
            FFLOG.debug("Queue=%s", str(self._queue))
            self.__dpid_request()

    def __tables_request(self):
        if len(self._table_queue) == 0:
            self.__get_dpids('tables')
        else:
            FFLOG.debug("Table-Queue=%s", str(self._table_queue))
            self.__table_stats_request()

    def __ports_request(self):
        if len(self._port_queue) == 0:
            self.__get_ports()
        else:
            FFLOG.debug("Port-Queue=%s", str(self._port_queue))
            self.__port_stats_request()

    def __flow_create(self, dpid, info):
        try:
            nw_src = opt('nw_src', info['match'])
            if nw_src:
                nw_src = nxw_utils.convert_ipv4_to_str(nw_src)

            nw_dst = opt('nw_dst', info['match'])
            if nw_dst:
                nw_dst = nxw_utils.convert_ipv4_to_str(nw_dst)

            payload = {"dpid": dpid,
                "table_id": info['table_id'],
                "input_port": opt('in_port', info['match']),
                "idle_timeout": info['idle_timeout'],
                "hard_timeout": info['hard_timeout'],
                "priority": info['priority'],
                "cookie": info['cookie'],
                "datalink_type": opt('dl_type', info['match']),
                "datalink_vlan": opt('dl_vlan', info['match']),
                "datalink_vlan_priority": opt('dl_vlan_pcp', info['match']),
                "datalink_source": opt('dl_src', info['match']),
                "datalink_destination": opt('dl_dst', info['match']),
                "network_source": nw_src,
                "network_destination": nw_dst,
                "network_source_num_wild": opt('nw_src_n_wild', info['match']),
                "network_destination_num_wild": opt('nw_dst_n_wild',
                                                    info['match']),
                "network_protocol": opt('nw_proto', info['match']),
                "transport_source": opt('tp_src', info['match']),
                "transport_destination": opt('tp_dst', info['match'])}

            r_ = requests.post(url=self._url + 'pckt_flows', params=payload)
            if r_.text != 'Operation completed':
                FFLOG.error("An error occurring during flow-post!")

        except Exception as e:
            FFLOG.error(str(e))

    def __table_stats_create(self, dpid, info):
        h_ = {'content-type': 'application/json'}
        try:
            payload = {"dpid": dpid,
                       "table_id": info['table_id'],
                       "max_entries": info['max_entries'],
                       "active_count": info['active_count'],
                       "lookup_count": info['lookup_count'],
                       "matched_count": info['matched_count']}

            r_ = requests.post(url=self._url + 'pckt_table_stats',
                               headers=h_, data=json.dumps(payload))
            if r_.text != 'Operation completed':
                FFLOG.error("An error occurring during table-stats-post!")

        except Exception as e:
            FFLOG.error(str(e))

    def __port_stats_create(self, dpid, info):
        h_ = {'content-type': 'application/json'}
        try:
            payload = {"dpid": dpid,
                       "port_no": info['port_no'],
                       "rx_pkts": info['rx_packets'],
                       "tx_pkts": info['tx_packets'],
                       "rx_bytes": info['rx_bytes'],
                       "tx_bytes": info['tx_bytes'],
                       "rx_dropped": info['rx_dropped'],
                       "tx_dropped": info['tx_dropped'],
                       "rx_errors": info['rx_errors'],
                       "tx_errors": info['tx_errors'],
                       "rx_frame_err": info['rx_frame_err'],
                       "rx_crc_err": info['rx_crc_err'],
                       "rx_over_err": info['rx_over_err'],
                       "collisions": info['collisions']}

            r_ = requests.post(url=self._url + 'pckt_port_stats',
                               headers=h_, data=json.dumps(payload))
            if r_.text != 'Operation completed':
                FFLOG.error("An error occurring during port-stats-post!")

        except Exception as e:
            FFLOG.error(str(e))

    def __flows_replay(self, dpid, ff):
        if ff.get_status() != 0:
            FFLOG.error("An error occurring during flows-request!")
            return

        FFLOG.debug("DPID=%s, FLOWS=%s", str(dpid), str(ff.get_flows()))
        requests.delete(url=self._url + 'pckt_flows/' + str(dpid))

        for flow_ in ff.get_flows():
            self.__flow_create(dpid, flow_)

    def install(self):
        self._ffa = self.resolve(flow_fetcher_app)
        self.register_for_table_stats_in(self.table_stats_handler)
        self.register_for_port_stats_in(self.port_stats_handler)

        self.post_callback(int(self._conf_ff.timeout),
                           self.timer_handler)
        self.post_callback(int(self._conf_ff.table_timeout),
                           self.table_timer_handler)
        self.post_callback(int(self._conf_ff.port_timeout),
                           self.port_timer_handler)
        return CONTINUE

    def table_stats_handler(self, dpid, tables):
        FFLOG.debug("TABLE_STATS dpid=%s, tables=%s", dpid, str(tables))
        requests.delete(url=self._url + 'pckt_table_stats/' + str(dpid))

        for table_ in tables:
            self.__table_stats_create(dpid, table_)

    def port_stats_handler(self, dpid, ports):
        FFLOG.debug("PORT_STATS dpid=%s, ports=%s", dpid, str(ports))
        h_ = {'content-type': 'application/json'}

        for port_ in ports:
            payload = {"dpid": dpid,
                       "portno": port_['port_no']}
            requests.delete(url=self._url + 'pckt_port_stats', headers=h_,
                            data=json.dumps(payload))

            self.__port_stats_create(dpid, port_)

    def timer_handler(self):
        FFLOG.debug("FlowsMonitor timeout fired")
        self.__flows_request()
        self.post_callback(int(self._conf_ff.timeout), self.timer_handler)

    def table_timer_handler(self):
        FFLOG.debug("FlowsMonitor table-timeout fired")
        self.__tables_request()
        self.post_callback(int(self._conf_ff.table_timeout),
                           self.table_timer_handler)

    def port_timer_handler(self):
        FFLOG.debug("FlowsMonitor port-timeout fired")
        self.__ports_request()
        self.post_callback(int(self._conf_ff.port_timeout),
                           self.port_timer_handler)

    def getInterface(self):
        return str(FlowsMonitor)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return FlowsMonitor(ctxt)

    return Factory()
