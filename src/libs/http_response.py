# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" HTTP Response module """

import json

NULL_VALUE = ['null', 'NULL', None]


class HTTPResponseGetDPIDS(object):
    def __init__(self, ids):
        self._ids = ids

    def body(self):
        dpids_ = {'dpids':[]}
        for dpid_ in self._ids:
            dpids_['dpids'].append({'dpid': dpid_})

        return json.dumps(dpids_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetDPIDInfo(object):
    def __init__(self, id, tables, ofp_capabilities,
                 ofp_actions, buffers, cports):
        self._id = id
        self._tables = tables
        self._ofp_capabs = ofp_capabilities
        self._ofp_actions = ofp_actions
        self._buffers = buffers
        self._cports = cports

    def body(self):
        dpid_ = {'dpid':{}}

        dpid_['dpid']['id'] = self._id
        dpid_['dpid']['tables'] = self.tables()
        dpid_['dpid']['ofp_capabilities'] = self.ofp_capabilities()
        dpid_['dpid']['ofp_actions'] = self.ofp_actions()
        dpid_['dpid']['buffers'] = self.buffers()
        dpid_['dpid']['cports'] = self.cports()

        return json.dumps(dpid_, sort_keys=True, indent=4,
                          separators=(',', ': '))

    def tables(self):
        return "" if self._tables in NULL_VALUE else self._tables

    def ofp_capabilities(self):
        return "" if self._ofp_capabs in NULL_VALUE else self._ofp_capabs

    def ofp_actions(self):
        return "" if self._ofp_actions in NULL_VALUE else self._ofp_actions

    def buffers(self):
        return "" if self._buffers in NULL_VALUE else self._buffers

    def cports(self):
        return "" if self._cports in NULL_VALUE else self._cports
