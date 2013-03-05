#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

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
        # cport_bandwidth_insert: dpid, port_no, num_bandwidth, bandwidth=None
        conn.datapath_insert(1)
        conn.port_insert(1,1)

        conn.cport_bandwidth_insert(1,1,0,1000)
        conn.cport_bandwidth_insert(1,1,1,1001)
        conn.cport_bandwidth_insert(1,1,2,1002)
        conn.cport_bandwidth_insert(1,1,3,1003)
        conn.cport_bandwidth_insert(1,1,4,1004)

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
