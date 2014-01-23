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
        # port_insert: d_id, port_no, hw_addr=None, name=None,
        #              config=None, state=None, curr=None, advertised=None,
        #              supported=None, peer=None
        conn.datapath_insert(1)

        conn.port_insert(1,1)
        conn.port_insert(1,2,"00:11:22:33:44:55")
        conn.port_insert(1,3,"00:11:22:33:44:55",'pippo')
        conn.port_insert(1,4,"00:11:22:33:44:55",'pippo',15)
        conn.port_insert(1,5,"00:11:22:33:44:55",'pippo',15,7)
        conn.port_insert(1,6,"00:11:22:33:44:55",'pippo',15,7,2)
        conn.port_insert(1,7,"00:11:22:33:44:55",'pippo',15,7,2,10)
        conn.port_insert(1,8,"00:11:22:33:44:55",'pippo',15,7,2,10,22)
        conn.port_insert(1,9,"00:11:22:33:44:55",'pippo',15,7,2,10,22,77)

        conn.port_insert(1,10,sw_tdm_gran=27)
        conn.port_insert(1,11,sw_type=3)
        conn.port_insert(1,12,peer_dpath_id=7)
        conn.port_insert(1,13,peer_port_no=17)

        # commit transaction
        conn.commit()

    except DBException as e:
        LOG.error(str(e))
        # rollback transaction
        conn.rollback()

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
