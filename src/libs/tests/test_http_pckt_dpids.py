#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

import sys, os
import requests
import json


basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

from log import *


def main (argv=None):
    LOG.level_set("DEBUG")

    try:
        # post pckt flow
        url_ = "http://10.0.2.246:8080/"
        hs_ = {'content-type': 'application/json'}
        payload = { "dpid": 1,
                    "ofp_capabilities": 2,
                    "ofp_actions": 3,
                    "buffers": 4,
                    "tables": 5,
#                    "cports": 6,
                    "ports": [
                        {
                            "port_no": 1,
                            "hw_addr": "00:00:00:00:00:11",
                            "name": "port-1-1",
                            "config": 10,
                            "state": 11,
                            "curr": 12,
                            "advertised": 13,
                            "supported": 14,
                            "peer": 15,
#                           "sw_tdm_gran": 16,
#                           "sw_type": 17,
#                           "peer_port_no": 18,
#                           "peer_dpath_id": 19
                        },
                        {
                            "port_no": 2,
                            "hw_addr": "00:00:00:00:00:22",
                            "name": "port-1-2",
                            "config": 20,
                            "state": 21,
                            "curr": 22,
                            "advertised": 23,
                            "supported": 24,
                            "peer": 25,
#                           "sw_tdm_gran": 26,
#                           "sw_type": 27,
#                           "peer_port_no": 28,
#                           "peer_dpath_id": 29
                        }
                    ]
                  }
        r_ = requests.post(url=url_ + "pckt_dpid", headers=hs_,
                           data=json.dumps(payload))
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

    except Exception as e:
        LOG.error(str(e))
        return False

    LOG.debug("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())
