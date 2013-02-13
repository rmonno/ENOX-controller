#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright XXX Fixme XXX
#
# @author: Roberto Monno

import sys, os

basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

from log import *
from topology_ofc_manager import *


def main (argv=None):
    log.level_set("DEBUG")
    conn = TopologyOFCManager("127.0.0.1", "root", "root", "topology_ofc_db", log)
    try:
        # connect and open transaction
        conn.open_transaction()

        # make an action
        # port_insert: d_id, port_no, hw_addr=None, name=None,
        #              config=None, state=None, curr=None, advertised=None,
        #              supported=None, peer=None
        conn.datapath_insert(1)

        conn.port_insert(1,1)
        conn.port_insert(1,2, "00:11:22:33:44:55")
        conn.port_insert(1,3, "00:11:22:33:44:55", 'pippo')
        conn.port_insert(1,4, "00:11:22:33:44:55", 'pippo', 15)
        conn.port_insert(1,5, "00:11:22:33:44:55", 'pippo', 15, 7)
        conn.port_insert(1,6, "00:11:22:33:44:55", 'pippo', 15, 7, 2)
        conn.port_insert(1,7, "00:11:22:33:44:55", 'pippo', 15, 7, 2, 10)
        conn.port_insert(1,8, "00:11:22:33:44:55", 'pippo', 15, 7, 2, 10, 22)
        conn.port_insert(1,9, "00:11:22:33:44:55", 'pippo', 15, 7, 2, 10, 22, 77)

        # commit transaction
        conn.commit()

    except DBException as e:
        log.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
