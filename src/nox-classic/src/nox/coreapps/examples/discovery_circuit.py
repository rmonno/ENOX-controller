# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of NOX.
#
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------
""" Discovey Circuit NOX application """

from nox.lib.core import Component
from nox.coreapps.pyrt.pycomponent import CONTINUE

import sys
import os
#import json
#import requests
import logging

# update sys python path
KEY = 'nox-classic'
BASEPATH  = os.path.dirname(os.path.abspath(sys.argv[0]))
NOX_INDEX = BASEPATH.find(KEY)

LIBS_PATH = BASEPATH[0:NOX_INDEX-1]
sys.path.insert(0, LIBS_PATH)

IDL_FIND_PATH = BASEPATH[0:NOX_INDEX] + KEY + '/build/src'
for (root, dirs, names) in os.walk(IDL_FIND_PATH):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')

import libs as nxw_utils

LOG = nxw_utils.ColorLog(logging.getLogger('discovery_circuit'))


class DiscoveryCircuit(Component):
    FCONFIG = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)

    def configure(self, configuration):
        LOG.debug('configuring %s' % str(self.__class__.__name__))

    def install(self):
        LOG.debug("%s started..." % str(self.__class__.__name__))

    def getInterface(self):
        return str(DiscoveryCircuit)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return DiscoveryCircuit(ctxt)

    return Factory()
