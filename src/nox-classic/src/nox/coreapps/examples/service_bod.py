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
import sys
import os
import logging
import time

from nox.lib.core import Component
from nox.lib.packet.ethernet import ethernet
import nox.lib.openflow as openflow

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

BoDLOG = nxw_utils.ColorLog(logging.getLogger('service-bod'))


class ServiceBoD(Component):
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_db = nxw_utils.DBConfigParser(self.CONFIG_FILE)
        self._conf_sbd = nxw_utils.ServiceBoDConfigParser(self.CONFIG_FILE)
        self._conf_pce = nxw_utils.NoxConfigParser(self.CONFIG_FILE)
        self._db = None
        self._fpce = None

    def install(self):
        self._db = nxw_utils.TopologyOFCManager(host=self._conf_db.host,
                                                user=self._conf_db.user,
                                                pswd=self._conf_db.pswd,
                                                database=self._conf_db.name,
                                                logger=BoDLOG)
        self._fpce = nxw_utils.FPCEManager(addr=self._conf_pce.address,
                                           port=self._conf_pce.port,
                                           size=int(self._conf_pce.size))
        self._fpce.topology_enable()
        self._fpce.routing_enable()
        self.post_callback(int(self._conf_sbd.timeout), self.timer_handler)

    def getInterface(self):
        return str(ServiceBoD)

    def timer_handler(self):
        BoDLOG.debug("ServiceBoD timeout fired")
        (pending_, started_) = self.__get_services()
        operations_ = []
        for service in pending_:
            BoDLOG.info("Pending service=%s", service)
            if int(service['start_time'].strftime('%s')) <= time.time():
                (status, comm) = self.__manage_start(service)
                operations_.append((service['serviceID'], status, comm))

        for service in started_:
            BoDLOG.info("Started service=%s", service)
            if int(service['end_time'].strftime('%s')) >= time.time():
                self.__manage_stop(service)

        if len(operations_):
            self.__manage_operations(operations_)

        self.post_callback(int(self._conf_sbd.timeout), self.timer_handler)

    def __get_services(self):
        try:
            self._db.open_transaction()
            ps_ = self.__secure_service(status='pending', param='start_time')
            ss_ = self.__secure_service(status='started', param='end_time')
            return (ps_, ss_)

        except nxw_utils.DBException as err:
            BoDLOG.debug("get_services: " + str(err))
            return ({}, {})

        finally:
            self._db.close()

    def __secure_service(self, status, param):
        try:
            return self._db.request_select_ordered(status, param)

        except nxw_utils.DBException as err:
            BoDLOG.debug("secure_service(%s,%s): %s" %
                         (status, param, str(err)))
            return {}

    def __secure_convert_flows_from_index(self, flows):
        BoDLOG.debug("Flows=%s", str(flows))
        res = []
        for din, pin, dout, pout in flows:
            try:
                (d_in, p_in) = self._db.port_get_did_pno(pin)
                (d_out, p_out) = self._db.port_get_did_pno(pout)

                res.append((d_in, p_in, d_out, p_out))

            except nxw_utils.DBException as err:
                BoDLOG.warning(str(err))

        return res

    def __secure_interswitch_link_update(self, dpid_in, port_in, dpid_out,
                                         port_out, bw):
        try:
            avail_bw_ = self._db.link_get_bw(dpid_in, port_in,
                                             dpid_out, port_out)
            bw_ = ((avail_bw_ * 1000) - bw) / 1000
            self._db.link_update_bw(dpid_in, port_in, dpid_out, port_out, bw_)

            didx_in_ = self._db.datapath_get_index(dpid_in)
            pidx_in_ = self._db.port_get_index(dpid_in, port_in)
            didx_out_ = self._db.datapath_get_index(dpid_out)
            pidx_out_ = self._db.port_get_index(dpid_out, port_out)

            src_node = nxw_utils.createNodeIPv4(didx_in_, pidx_in_)
            dst_node = nxw_utils.createNodeIPv4(didx_out_, pidx_out_)

            self._fpce.update_link_bw_from_strings(src_node, dst_node, bw_)

        except nxw_utils.DBException as err:
            BoDLOG.warning(str(err))

    def __manage_start(self, req):
        BoDLOG.debug("Start %s" % req)
        if not self._fpce.check('routing'):
            self._fpce.disable('routing')
            return ('failed', 'Unable to contact ior-dispatcher on PCE node!')

        (w_,p_,s_) = self._fpce.connection_route_from_hosts_bw(req['ip_src'],
                                                               req['ip_dst'],
                                                               req['bw'])
        if s_ != 'ok':
            return ('failed', s_)
        elif not w_:
            return ('failed', 'Unable to found working ERO!')

        BoDLOG.info("WorkingEro(%d)=%s", len(w_), str(w_))
        BoDLOG.debug("ProtectedEro(%d)=%s", len(p_), str(p_))

        flows = []
        for idx_x, idx_y in zip(w_, w_[1:]):
            (din_idx, pin_idx) = self._fpce.decode_ero_item(idx_x)
            (dout_idx, pout_idx) = self._fpce.decode_ero_item(idx_y)

            flows.append((din_idx, pin_idx, dout_idx, pout_idx))

        default_action = openflow.OFPAT_OUTPUT
        default_idle = 300
        default_hard = openflow.OFP_FLOW_PERMANENT
        default_priority = openflow.OFP_DEFAULT_PRIORITY
        default_etype = ethernet.IP_TYPE

        try:
            self._db.open_transaction()
            cflows = self.__secure_convert_flows_from_index(flows)
            for d_in, p_in, d_out, p_out in cflows:
                evt_ = nxw_utils.Pckt_flowEntryEvent(dp_in=d_in,
                                                     port_in=p_in,
                                                     dp_out=d_out,
                                                     port_out=p_out,
                                                     ip_src=req['ip_src'],
                                                     ip_dst=req['ip_dst'],
                                                     tcp_dport=req['port_dst'],
                                                     tcp_sport=req['port_src'],
                                                     ip_proto=req['ip_proto'],
                                                     vid=req['vlan_id'],
                                                     etype=default_etype,
                                                     action=default_action,
                                                     idle=default_idle,
                                                     hard=default_hard,
                                                     prio=default_priority)
                BoDLOG.debug(str(evt_))
                self.post(evt_.describe())

                self._db.flow_insert(dpid=d_in,
                                     action=default_action,
                                     idle_timeout=default_idle,
                                     hard_timeout=default_hard,
                                     priority=default_priority,
                                     dl_vlan=req['vlan_id'],
                                     nw_src=req['ip_src'],
                                     nw_dst=req['ip_dst'],
                                     tp_src=req['port_src'],
                                     tp_dst=req['port_dst'],
                                     in_port=p_in)

                self._db.service_insert(req['serviceID'], d_in, p_in,
                                        d_out, p_out, req['bw'])

                if d_in != d_out:
                    self.__secure_interswitch_link_update(d_in, p_in,
                                                          d_out, p_out,
                                                          req['bw'])
            self._db.commit()

        except nxw_utils.DBException as err:
            self._db.rollback()
            return ('failed', str(err))

        finally:
            self._db.close()

        return ('started', '')

    def __manage_stop(self, request):
        BoDLOG.debug("Stop %s" % request)

    def __manage_operations(self, operations):
        try:
            self._db.open_transaction()
            for (service, status, comm) in operations:
                self._db.request_update_status(service, status, comm)

            self._db.commit()

        except nxw_utils.DBException as err:
            self._db.rollback()
            BoDLOG.error("Manage operations failed: %s" % str(err))

        finally:
            self._db.close()


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return ServiceBoD(ctxt)

    return Factory()
