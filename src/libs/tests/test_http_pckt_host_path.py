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
        url_ = "http://10.0.2.146:8080/"
        hs_ = {'content-type': 'application/json'}
        # post host path request
        payload = {"ip_src": "10.0.0.1",
                   "ip_dst": "10.0.0.2",
                   "src_port": 8,
                   "dst_port": 0,
                   "ip_proto": 1,
                   "vlan_id": 65535
                  }
        r_ = requests.post(url=url_ + "pckt_host_path", headers=hs_,
                           data=json.dumps(payload))
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

        payload['ip_src'] = "10.0.0.2"
        payload['ip_dst'] = "10.0.0.1"
        payload['src_port'] = 0

        r_ = requests.post(url=url_ + "pckt_host_path", headers=hs_,
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
