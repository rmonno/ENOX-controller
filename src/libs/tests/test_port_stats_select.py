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


def dump_port_raws(raws):
    for r in raws:
        msg = "datapath_id=%s, port_no=%s, rx_pkts=%s, tx_pkts=%s,"
        msg += "rx_bytes=%s, tx_bytes=%s, rx_dropped=%s, tx_dropped=%s"
        msg += "rx_errors=%s, tx_errors=%s, rx_frame_err=%s, rx_over_err=%s"
        msg += "rx_crc_err=%s, collisions=%s"
        LOG.debug(msg % (r["datapath_id"], r["port_no"],
                         r["rx_pkts"], r["tx_pkts"],
                         r["rx_bytes"], r["tx_pkts"],
                         r["rx_dropped"], r["tx_dropped"],
                         r["rx_errors"], r["tx_errors"],
                         r["rx_frame_err"], r["rx_over_err"],
                         r["rx_crc_err"], r["collisions"]))

def main (argv=None):
    LOG.level_set("DEBUG")
    conn = TopologyOFCManager("127.0.0.1", "root", "root",
                              "topology_ofc_db", LOG)
    try:
        # connect and open transaction
        conn.open_transaction()

        raws = conn.port_stats_select()
        dump_port_raws(raws)
        raws = conn.port_stats_select(dpid=1, port_no=1)
        dump_port_raws(raws)

    except DBException as e:
        LOG.error(str(e))

    conn.close()


if __name__ == "__main__":
    sys.exit(main())
