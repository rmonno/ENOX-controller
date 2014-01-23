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
        # datapath_delete: d_id
        conn.datapath_delete(1)
        conn.datapath_delete(2)
        conn.datapath_delete(3)
        conn.datapath_delete(4)
        conn.datapath_delete(5)
        conn.datapath_delete(6)
        conn.datapath_delete(7)

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
