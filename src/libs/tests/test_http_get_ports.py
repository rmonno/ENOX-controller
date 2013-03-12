#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

import sys, os
import requests


basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

from log import *


def main (argv=None):
    LOG.level_set("DEBUG")

    try:
        # get ports
        url_ = "http://10.0.2.246:8080/"
        r_ = requests.get(url=url_ + "ports")
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

        # get port info
        payload = {'dpid': '1', 'portno': '1'}
        r_ = requests.get(url=url_ + "ports/", params=payload)
        LOG.debug("URL=%s" % r_.url)
        LOG.debug("Response=%s" % r_.text)

    except Exception as e:
        LOG.error(str(e))
        return False

    LOG.debug("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())
