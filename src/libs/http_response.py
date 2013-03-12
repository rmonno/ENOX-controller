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
    def __init__(self, db_row):
        self._row = db_row

    def body(self):
        dpid_ = {'dpid':{}}

        dpid_['dpid']['id'] = self._row['id']
        dpid_['dpid']['tables'] = self.tables()
        dpid_['dpid']['ofp_capabilities'] = self.ofp_capabilities()
        dpid_['dpid']['ofp_actions'] = self.ofp_actions()
        dpid_['dpid']['buffers'] = self.buffers()
        dpid_['dpid']['cports'] = self.cports()

        return json.dumps(dpid_, sort_keys=True, indent=4,
                          separators=(',', ': '))

    def tables(self):
        val_ = self._row['tables']
        return "" if val_ in NULL_VALUE else val_

    def ofp_capabilities(self):
        val_ = self._row['ofp_capabilities']
        return "" if val_ in NULL_VALUE else val_

    def ofp_actions(self):
        val_ = self._row['ofp_actions']
        return "" if val_ in NULL_VALUE else val_

    def buffers(self):
        val_ = self._row['buffers']
        return "" if val_ in NULL_VALUE else val_

    def cports(self):
        val_ = self._row['cports']
        return "" if val_ in NULL_VALUE else val_


class HTTPResponseGetPORTS(object):
    def __init__(self, ids):
        self._ids = ids

    def body(self):
        ports_ = {'ports':[]}
        for dpid_, port_no_ in self._ids:
            ports_['ports'].append({'dpid': dpid_, 'port_no': port_no_})

        return json.dumps(ports_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetPORTInfo(object):
    def __init__(self, db_row):
        self._row = db_row

    def body(self):
        port_ = {'port':{}}

        port_['port']['dpid'] = self._row['datapath_id']
        port_['port']['port_no'] = self._row['port_no']
        port_['port']['hw_addr'] = self.hw_addr()
        port_['port']['name'] = self.name()
        port_['port']['config'] = self.config()
        port_['port']['state'] = self.state()
        port_['port']['curr'] = self.curr()
        port_['port']['advertised'] = self.advertised()
        port_['port']['supported'] = self.supported()
        port_['port']['peer'] = self.peer()
        port_['port']['sw_tdm_gran'] = self.sw_tdm_gran()
        port_['port']['sw_type'] = self.sw_type()
        port_['port']['peer_port_no'] = self.peer_port_no()
        port_['port']['peer_dpath_id'] = self.peer_dpath_id()

        return json.dumps(port_, sort_keys=True, indent=4,
                          separators=(',', ': '))

    def hw_addr(self):
        val_ = self._row['hw_addr']
        return "" if val_ in NULL_VALUE else val_

    def name(self):
        val_ = self._row['name']
        return "" if val_ in NULL_VALUE else val_

    def config(self):
        val_ = self._row['config']
        return "" if val_ in NULL_VALUE else val_

    def state(self):
        val_ = self._row['state']
        return "" if val_ in NULL_VALUE else val_

    def curr(self):
        val_ = self._row['curr']
        return "" if val_ in NULL_VALUE else val_

    def advertised(self):
        val_ = self._row['advertised']
        return "" if val_ in NULL_VALUE else val_

    def supported(self):
        val_ = self._row['supported']
        return "" if val_ in NULL_VALUE else val_

    def peer(self):
        val_ = self._row['peer']
        return "" if val_ in NULL_VALUE else val_

    def sw_tdm_gran(self):
        val_ = self._row['sw_tdm_gran']
        return "" if val_ in NULL_VALUE else val_

    def sw_type(self):
        val_ = self._row['sw_type']
        return "" if val_ in NULL_VALUE else val_

    def peer_port_no(self):
        val_ = self._row['peer_port_no']
        return "" if val_ in NULL_VALUE else val_

    def peer_dpath_id(self):
        val_ = self._row['peer_dpath_id']
        return "" if val_ in NULL_VALUE else val_
