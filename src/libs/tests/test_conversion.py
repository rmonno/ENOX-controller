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

    key1 = 0xf00f
    (upper, lower) = indextoUpperLower(key1)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key1, upper, lower)

    key2 = 0x0ea3
    (upper, lower) = indextoUpperLower(key2)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key2, upper, lower)

    key3 = 0x87bb
    (upper, lower) = indextoUpperLower(key3)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key3, upper, lower)

    key4 = 0x1c2d
    (upper, lower) = indextoUpperLower(key4)
    LOG.debug("Key=%x, Upper=%x, Lower=%x", key4, upper, lower)

    node1 = createNodeIPv4(key1, key2)
    node2 = createNodeIPv4(key3, key4)

    LOG.debug("Node1=%s, Node2=%s", node1, node2)

if __name__ == "__main__":
    sys.exit(main())
