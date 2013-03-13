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
        # get pckt flows
        url_ = "http://10.0.2.246:8080/"
        r_ = requests.get(url=url_ + "pckt_flows/1")
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

    except Exception as e:
        LOG.error(str(e))
        return False

    try:
        # post pckt flow
        url_ = "http://10.0.2.246:8080/"
        payload = {"action": "BLA BLA",
                   "cookie": 0,
                   "datalink_destination": 12,
                   "datalink_source": 3,
                   "datalink_type": "BHO",
                   "datalink_vlan": 100,
                   "datalink_vlan_priority": 4,
                   "dpid": 1,
                   "hard_timeout": 30,
                   "idle_timeout": 40,
                   "input_port": 5,
                   "network_destination": "10.2.4.0",
                   "network_destination_num_wild": 9,
                   "network_protocol": "IP",
                   "network_source": "192.168.10.0",
                   "network_source_num_wild": 1,
                   "priority": 0,
                   "table_id": "123456",
                   "transport_destination": "ETH",
                   "transport_source": "ETH"
                  }
        r_ = requests.post(url=url_ + "pckt_flows", params=payload)
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

        # post pckt flow
        url_ = "http://10.0.2.246:8080/"
        payload = {"table_id": 1,
                   "dpid": 2,
                   "network_source": "192.33.22.0",
                   "network_destination": "10.1.1.0",
                  }
        r_ = requests.post(url=url_ + "pckt_flows", params=payload)
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

    except Exception as e:
        LOG.error(str(e))
        return False

    LOG.debug("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())
