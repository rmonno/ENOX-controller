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


def dump_port_raws(raws):
    for r in raws:
        msg = "datapath_id=%s, port_no=%s, hw_addr=%s, name=%s, config=%s,"
        msg += "state=%s, curr=%s, advertised=%s, supported=%s, peer=%s,"
        msg += "sw_tdm_gran=%s, sw_type=%s, peer_port_no=%s, peer_dpath_id=%s,"
        msg += "nodeID=%s"
        LOG.debug(msg % (r["datapath_id"], r["port_no"], r["hw_addr"],
                         r["name"], r["config"], r["state"], r["curr"],
                         r["advertised"], r["supported"], r["peer"],
                         r["sw_tdm_gran"], r["sw_type"], r["peer_port_no"],
                         r["peer_dpath_id"], r["nodeID"]))


def main (argv=None):
    LOG.level_set("DEBUG")
    conn = TopologyOFCManager("127.0.0.1", "root", "root",
                              "topology_ofc_db", LOG)
    try:
        # connect and open transaction
        conn.open_transaction()

        raws = conn.port_select()
        dump_port_raws(raws)

        raws = conn.port_select(1)
        dump_port_raws(raws)

        raws = conn.port_select(port_no=1)
        dump_port_raws(raws)

    except DBException as e:
        LOG.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
