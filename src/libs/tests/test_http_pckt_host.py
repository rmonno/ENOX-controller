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
        url_ = "http://10.0.2.246:8080/"
        hs_ = {'content-type': 'application/json'}
        # post dpid#1
        payload = { "dpid": 1,
                    "ofp_capabilities": 12,
                    "ofp_actions": 13,
                    "buffers": 14,
                    "tables": 15,
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
                        },
                        {
                            "port_no": 2,
                            "hw_addr": "00:00:00:00:00:22",
                            "name": "port-1-2",
                            "config": 10,
                            "state": 11,
                            "curr": 12,
                            "advertised": 13,
                            "supported": 14,
                            "peer": 15,
                        }
                    ]
                  }
        r_ = requests.post(url=url_ + "pckt_dpid", headers=hs_,
                           data=json.dumps(payload))
        # post host
        payload = { "ip_addr": "192.168.1.1",
                    "mac": "00:11:22:33:44:55",
                    "peer_dpid": 1,
                    "peer_portno": 1
                  }
        r_ = requests.post(url=url_ + "pckt_host", headers=hs_,
                           data=json.dumps(payload))
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

        payload = { "ip_addr": "192.168.1.2",
                    "mac": "00:11:22:33:44:55",
                    "peer_dpid": 1,
                    "peer_portno": 2
                  }
        r_ = requests.post(url=url_ + "pckt_host", headers=hs_,
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
