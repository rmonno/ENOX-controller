#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @authors: Roberto Monno
#          Alessandro Canessa

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
        # flow_get_index: dpid, table_id, dl_src=None, dl_dst=None,
        #                 nw_src=None, nw_dst=None, tp_src=None, tp_dst=None
        index = conn.flow_get_index(1,1)
        LOG.debug("INDEX=%s", index)

        index = conn.flow_get_index(1,1, nw_src="192.168.1.1")
        LOG.debug("INDEX=%s", index)
        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01")
        LOG.debug("INDEX=%s", index)
        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01",
                                    dl_dst="00:00:00:00:00:02")
        LOG.debug("INDEX=%s", index)
        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01",
                                    dl_dst="00:00:00:00:00:02",
                                    in_port=10)

    except DBException as e:
        LOG.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
