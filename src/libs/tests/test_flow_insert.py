#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @authors: Roberto Monno
#           Alessandro Canessa

import sys, os

basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

from log import *
from topology_ofc_manager import *
from topology_ofc_inf import *


def main (argv=None):
    LOG.level_set("DEBUG")
    conn = TopologyOFCManager("127.0.0.1", "root", "root",
                              "topology_ofc_db", LOG)
    try:
        # connect and open transaction
        conn.open_transaction()

        # make an action
        # flow_insert: dpid, table_id, action, idle_timeout,
        #              hard_timeout, priority, cookie, dl_type, dl_vlan,
        #              dl_vlan_pcp, dl_src, dl_dst, nw_src, nw_dst,
        #              nw_src_n_wild, nw_dst_n_wild, nw_proto, tp_src, tp_dst

        # port_insert: d_id, port_no, hw_addr=None, name=None,
        #              config=None, state=None, curr=None, advertised=None,
        #              supported=None, peer=None
        conn.datapath_insert(1)

        conn.flow_insert(1,1,"OUTPUT")
        conn.flow_insert(1,1,"OUTPUT", 30)
        conn.flow_insert(1,1,"OUTPUT", 30, 60)
        conn.flow_insert(1,1,"OUTPUT", 30, 60, 0)
        conn.flow_insert(1,1,"OUTPUT", 30, 60, 0, "cookie")
        conn.flow_insert(1,1,"OUTPUT", 30, 60, 0, "cookie",
                         nw_src="192.168.1.1")
        conn.flow_insert(1,1,"OUTPUT", 30, 60, 0, "cookie",
                         dl_src="00:00:00:00:00:01", nw_src="192.168.1.1")
        conn.flow_insert(1,1,"OUTPUT", 30, 60, 0, "cookie",
                         dl_src="00:00:00:00:00:01",
                         dl_dst="00:00:00:00:00:02",
                         nw_src="192.168.1.1")

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()

if __name__ == "__main__":
    sys.exit(main())
