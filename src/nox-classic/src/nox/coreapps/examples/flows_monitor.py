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
#
""" Flow-entries Monitoring NOX application """

import sys
import os
import logging

from nox.lib.core import *
from nox.netapps.flow_fetcher.pyflow_fetcher import flow_fetcher_app
from nox.lib.netinet.netinet import datapathid

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

FFLOG = nxw_utils.ColorLog(logging.getLogger('flows-monitor'))


class FlowsMonitor(Component):
    """ Flows-Monitor Class """
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_ff = nxw_utils.FlowsMonitorConfigParser(FlowsMonitor.CONFIG_FILE)
        self._ffa = None

    def __flows_request(self):
        try:
            dpid = datapathid.from_host(long("1", 16))
            match = {}
            ff = self._ffa.fetch(dpid, match, lambda: self.__flows_replay(ff))

        except Exception as e:
            FFLOG.error(str(e))

    def __flows_replay(self, ff):
        if ff.get_status() == 0:
            FFLOG.info("Flows=%s", str(ff.get_flows()))
        else:
            FFLOG.error("An error occurring during flows-request!")

    def install(self):
        self._ffa = self.resolve(flow_fetcher_app)
        self.post_callback(int(self._conf_ff.timeout), self.timer_handler)
        return CONTINUE

    def timer_handler(self):
        FFLOG.debug("FlowsMonitor timeout fired")
        self.__flows_request()
        self.post_callback(int(self._conf_ff.timeout), self.timer_handler)

    def getInterface(self):
        return str(FlowsMonitor)


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return FlowsMonitor(ctxt)

    return Factory()
