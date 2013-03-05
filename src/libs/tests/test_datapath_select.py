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


def dump_dp_raws(raws):
    for r in raws:
        msg = "id=%s, name=%s, ofp_capabilities=%s, ofp_actions=%s,"
        msg += "buffers=%s, tables=%s, cports=%s, dID=%s"
        LOG.debug(msg % (r["id"], r["name"], r["ofp_capabilities"],
                         r["ofp_actions"], r["buffers"], r["tables"],
                         r["cports"], r["dID"]))


def main (argv=None):
    LOG.level_set("DEBUG")
    conn = TopologyOFCManager("127.0.0.1", "root", "root",
                              "topology_ofc_db", LOG)
    try:
        # connect and open transaction
        conn.open_transaction()

        raws = conn.datapath_select()
        dump_dp_raws(raws)

        raws = conn.datapath_select(1)
        dump_dp_raws(raws)

    except DBException as e:
        LOG.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
