# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" HTTP Response module """

import json

NULL_VALUE = ['null', 'NULL', None]

def check_value(value):
    return "" if value in NULL_VALUE else value


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
        dpid_['dpid']['region'] = check_value(self._row['name'])
        dpid_['dpid']['tables'] = check_value(self._row['tables'])
        dpid_['dpid']['ofp_capabilities'] = check_value(self._row['ofp_capabilities'])
        dpid_['dpid']['ofp_actions'] = check_value(self._row['ofp_actions'])
        dpid_['dpid']['buffers'] = check_value(self._row['buffers'])
        dpid_['dpid']['cports'] = check_value(self._row['cports'])

        return json.dumps(dpid_, sort_keys=True, indent=4,
                          separators=(',', ': '))


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
        port_['port']['hw_addr'] = check_value(self._row['hw_addr'])
        port_['port']['name'] = check_value(self._row['name'])
        port_['port']['config'] = check_value(self._row['config'])
        port_['port']['state'] = check_value(self._row['state'])
        port_['port']['curr'] = check_value(self._row['curr'])
        port_['port']['advertised'] = check_value(self._row['advertised'])
        port_['port']['supported'] = check_value(self._row['supported'])
        port_['port']['peer'] = check_value(self._row['peer'])
        port_['port']['sw_tdm_gran'] = check_value(self._row['sw_tdm_gran'])
        port_['port']['sw_type'] = check_value(self._row['sw_type'])
        port_['port']['peer_port_no'] = check_value(self._row['peer_port_no'])
        port_['port']['peer_dpath_id'] = check_value(self._row['peer_dpath_id'])

        return json.dumps(port_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetLINKS(object):
    def __init__(self, ids):
        self._ids = ids

    def body(self):
        links_ = {'links':[]}
        for src_dpid_, src_port_no_, dst_dpid_, dst_port_no_, bw_ in self._ids:
            links_['links'].append({'source_dpid': src_dpid_,
                                    'source_port_no': src_port_no_,
                                    'destination_dpid': dst_dpid_,
                                    'destination_port_no': dst_port_no_,
                                    'available_bw': check_value(bw_)})

        return json.dumps(links_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetHOSTS(object):
    def __init__(self, ids):
        self._ids = ids

    def body(self):
        hosts_ = {'hosts':[]}
        for dpid_, ip_, port_, mac_ in self._ids:
            hosts_['hosts'].append({'dpid': dpid_, 'ip_address': ip_,
                                    'port_no': port_, 'mac_address': mac_})

        return json.dumps(hosts_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetPCKTFLOWS(object):
    def __init__(self, db_rows):
        self._rows = db_rows

    def body(self):
        p_flows_ = {'packet_flows':[]}
        for row_ in self._rows:
            p_flows_['packet_flows'].append({'dpid': row_['dpid'],
                                             'flow_id': row_['flow_id'],
                    'table_id': check_value(row_['table_id']),
                    'input_port': check_value(row_['in_port']),
                    'idle_timeout': check_value(row_['idle_timeout']),
                    'hard_timeout': check_value(row_['hard_timeout']),
                    'priority': check_value(row_['priority']),
                    'action': check_value(row_['action']),
                    'cookie': check_value(row_['cookie']),
                    'datalink_type': check_value(row_['dl_type']),
                    'datalink_vlan': check_value(row_['dl_vlan']),
                    'datalink_vlan_priority': check_value(row_['dl_vlan_pcp']),
                    'datalink_source': check_value(row_['dl_src']),
                    'datalink_destination': check_value(row_['dl_dst']),
                    'network_source': check_value(row_['nw_src']),
                    'network_destination': check_value(row_['nw_dst']),
                    'network_source_num_wild': check_value(row_['nw_src_n_wild']),
                    'network_destination_num_wild': check_value(row_['nw_dst_n_wild']),
                    'network_protocol': check_value(row_['nw_proto']),
                    'transport_source': check_value(row_['tp_src']),
                    'transport_destination': check_value(row_['tp_dst'])})

        return json.dumps(p_flows_, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetPCKTPortStats(object):
    def __init__(self, db_rows):
        self._rows = db_rows

    def body(self):
        p_port_stats = {'packet_port_stats':[]}
        for row_ in self._rows:
            p_port_stats['packet_port_stats'].append({
                    'port_no': row_['port_no'],
                    'rx_pkts': check_value(row_['rx_pkts']),
                    'tx_pkts': check_value(row_['tx_pkts']),
                    'rx_bytes': check_value(row_['rx_bytes']),
                    'tx_bytes': check_value(row_['tx_bytes']),
                    'rx_dropped': check_value(row_['rx_dropped']),
                    'tx_dropped': check_value(row_['tx_dropped']),
                    'rx_errors': check_value(row_['rx_errors']),
                    'tx_errors': check_value(row_['tx_errors']),
                    'rx_frame_err': check_value(row_['rx_frame_err']),
                    'rx_crc_err': check_value(row_['rx_crc_err']),
                    'rx_over_err': check_value(row_['rx_over_err']),
                    'collisions': check_value(row_['collisions'])})

        return json.dumps(p_port_stats, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetPCKTTableStats(object):
    def __init__(self, db_rows):
        self._rows = db_rows

    def body(self):
        p_table_stats = {'packet_table_stats':[]}
        for row_ in self._rows:
            p_table_stats['packet_table_stats'].append({
                            'dpid': row_['datapath_id'],
                            'table_id': row_['table_id'],
                            'max_entries': check_value(row_['max_entries']),
                            'matched': check_value(row_['matched_count']),
                            'active': check_value(row_['active_count']),
                            'lookup': check_value(row_['lookup_count'])})

        return json.dumps(p_table_stats, sort_keys=True, indent=4,
                          separators=(',', ': '))


class HTTPResponseGetSERVICES(object):
    def __init__(self, db_rows):
        self._rows = db_rows

    def body(self):
        services = {'services':[]}
        for row_ in self._rows:
            services['services'].append({'ip_src': row_['ip_src'],
                                         'ip_dst': row_['ip_dst'],
                                         'port_src': row_['port_src'],
                                         'port_dst': row_['port_dst'],
                                         'ip_proto': row_['ip_proto'],
                                         'vlan_id': row_['vlan_id'],
                                         'service_id': row_['serviceID'],
                                         'bw': check_value(row_['bw'])})

        return json.dumps(services, sort_keys=True, indent=4,
                          separators=(',', ': '))
