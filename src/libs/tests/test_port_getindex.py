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
        # port_get_index: d_id, port_no
        index = conn.port_get_index(1,1)
        LOG.debug("INDEX=%s", index)

        index = conn.port_get_index(22,55)
        LOG.debug("INDEX=%s", index)

    except DBException as e:
        LOG.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
