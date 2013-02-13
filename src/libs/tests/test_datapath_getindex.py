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
        # datapath_get_index: d_id
        index = conn.datapath_get_index(1)
        log.debug("INDEX=%s", index)

        index = conn.datapath_get_index(22)
        log.debug("INDEX=%s", index)

    except DBException as e:
        log.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
