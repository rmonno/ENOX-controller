#!/usr/bin/env python

# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

import sys, os

basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

from log import *
from conversion import *


def main (argv=None):
    LOG.level_set("DEBUG")

    key = 0xf00f
    (upper, lower) = nodeIDtoUpperLower(key)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key, upper, lower)

    key = 0x0ea3
    (upper, lower) = nodeIDtoUpperLower(key)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key, upper, lower)

    key = 0x87bb
    (upper, lower) = nodeIDtoUpperLower(key)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key, upper, lower)

    key = 0x1c2d
    (upper, lower) = nodeIDtoUpperLower(key)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key, upper, lower)

if __name__ == "__main__":
    sys.exit(main())
