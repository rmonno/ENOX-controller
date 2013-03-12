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
        # port_delete: flow_id,
        index = conn.flow_get_index(1,1)
        LOG.debug("INDEX=%s", index)
        conn.flow_delete(index)

        index = conn.flow_get_index(1,1, nw_src="192.168.1.1")
        LOG.debug("INDEX=%s", index)
        conn.flow_delete(index)

        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01")
        LOG.debug("INDEX=%s", index)
        conn.flow_delete(index)

        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01",
                                    dl_dst="00:00:00:00:00:02")
        LOG.debug("INDEX=%s", index)
        conn.flow_delete(index)

        index = conn.flow_get_index(1,1, nw_src="192.168.1.1",
                                    dl_src="00:00:00:00:00:01",
                                    dl_dst="00:00:00:00:00:02",
                                    in_port=10)
        LOG.debug("INDEX=%s", index)
        conn.flow_delete(index)

        conn.datapath_delete(1)

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
