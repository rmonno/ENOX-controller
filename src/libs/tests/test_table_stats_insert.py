#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Alessandro Canessa

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

        conn.datapath_insert(1)
        conn.table_stats_insert(dpid=1, table_id=1,
                                max_entries=64,
                                active_count=5,
                                lookup_count=4,
                                matched_count=3)

        conn.table_stats_insert(dpid=1, table_id=2,
                                max_entries=128,
                                active_count=10,
                                lookup_count=8,
                                matched_count=6)

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()

if __name__ == "__main__":
    sys.exit(main())
