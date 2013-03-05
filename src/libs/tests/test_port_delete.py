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
        # port_delete: d_id, port_no
        conn.port_delete(1,1)
        conn.port_delete(1,2)
        conn.port_delete(1,3)
        conn.port_delete(1,4)
        conn.port_delete(1,5)
        conn.port_delete(1,6)
        conn.port_delete(1,7)
        conn.port_delete(1,8)
        conn.port_delete(1,9)
        conn.port_delete(1,10)
        conn.port_delete(1,11)
        conn.port_delete(1,12)
        conn.port_delete(1,13)

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
