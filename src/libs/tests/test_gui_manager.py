#!/usr/bin/env python
# -*- coding: utf-8 -*-
# #
# # roberto monno r.monno@nextworks.it

import os
import sys
import requests
import json
import argparse as ap
from PySide import QtGui, QtCore

basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)


class Shell(QtGui.QTextEdit):

    def __init__(self, tc='white', bc='black', sc='yellow', sbc='gray'):
        QtGui.QTextEdit.__init__(self)
        style_ = "color: %s; background-color: %s; selection-color: %s;\
                  selection-background-color: %s;" % (tc, bc, sc, sbc)
        self.setStyleSheet(style_)

    def debug(self, msg):
        self.append(msg)


class Button(QtGui.QPushButton):

    def __init__(self, name, parent):
        QtGui.QPushButton.__init__(self, name)
        self.__parent = parent

    def debug(self, msg):
        self.__parent.shell().debug(msg)

    def error(self, msg):
        self.__parent.critical(msg)

    def info_popup(self, msg):
        QtGui.QMessageBox.information(self, 'Info', msg, QtGui.QMessageBox.Ok)


class DpidsInfoButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'details', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        self.debug("get_dpid_info action: url=%s" % self.__url)
        try:
            r_ = requests.get(url=self.__url)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                info_ = r_.json()['dpid']
                lbs_ = ['id', 'region', 'buffers', 'tables',
                        'ofp_capabilities', 'ofp_actions', 'cports']
                self.__central.setRowCount(1)
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)
                self.__central.setCellWidget(0, 0,
                            QtGui.QTextEdit(str(info_['id'])))
                self.__central.setCellWidget(0, 1,
                            QtGui.QTextEdit(str(info_['region'])))
                self.__central.setCellWidget(0, 2,
                            QtGui.QTextEdit(str(info_['buffers'])))
                self.__central.setCellWidget(0, 3,
                            QtGui.QTextEdit(str(info_['tables'])))
                self.__central.setCellWidget(0, 4,
                            QtGui.QTextEdit(str(info_['ofp_capabilities'])))
                self.__central.setCellWidget(0, 5,
                            QtGui.QTextEdit(str(info_['ofp_actions'])))
                self.__central.setCellWidget(0, 6,
                            QtGui.QTextEdit(str(info_['cports'])))

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PortsInfoButton(Button):

    def __init__(self, url, payload, central, parent):
        Button.__init__(self, 'details', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__params = payload
        self.__central = central

    def onClick(self):
        self.debug("get_port_info action: url=%s, params=%s" %
                   (self.__url, self.__params))
        try:
            r_ = requests.get(url=self.__url, params=self.__params)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                info_ = r_.json()['port']
                lbs_ = ['dpid', 'port_no', 'name', 'hw_addr', 'state',  'curr',
                        'config', 'advertised', 'supported', 'peer',
                        'peer_dpid', 'peer_port_no', 'sw_tdm_gran', 'sw_type']
                self.__central.setRowCount(1)
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)
                self.__central.setCellWidget(0, 0,
                            QtGui.QTextEdit(str(info_['dpid'])))
                self.__central.setCellWidget(0, 1,
                            QtGui.QTextEdit(str(info_['port_no'])))
                self.__central.setCellWidget(0, 2,
                            QtGui.QTextEdit(str(info_['name'])))
                self.__central.setCellWidget(0, 3,
                            QtGui.QTextEdit(str(info_['hw_addr'])))
                self.__central.setCellWidget(0, 4,
                            QtGui.QTextEdit(str(info_['state'])))
                self.__central.setCellWidget(0, 5,
                            QtGui.QTextEdit(str(info_['curr'])))
                self.__central.setCellWidget(0, 6,
                            QtGui.QTextEdit(str(info_['config'])))
                self.__central.setCellWidget(0, 7,
                            QtGui.QTextEdit(str(info_['advertised'])))
                self.__central.setCellWidget(0, 8,
                            QtGui.QTextEdit(str(info_['supported'])))
                self.__central.setCellWidget(0, 9,
                            QtGui.QTextEdit(str(info_['peer'])))
                self.__central.setCellWidget(0, 10,
                            QtGui.QTextEdit(str(info_['peer_dpath_id'])))
                self.__central.setCellWidget(0, 11,
                            QtGui.QTextEdit(str(info_['peer_port_no'])))
                self.__central.setCellWidget(0, 12,
                            QtGui.QTextEdit(str(info_['sw_tdm_gran'])))
                self.__central.setCellWidget(0, 13,
                            QtGui.QTextEdit(str(info_['sw_type'])))

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class AddHostButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'create', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        params_ = {'ip_addr': self.__central.cellWidget(0, 0).text(),
                   'mac': self.__central.cellWidget(0, 1).text(),
                   'peer_dpid': self.__central.cellWidget(0, 2).text(),
                   'peer_portno': self.__central.cellWidget(0, 3).text()}

        self.debug("add_host_request action: url=%s, params=%s" %
                   (self.__url, str(params_)))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(params_),
                               headers={'content-type': 'application/json'})
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.info_popup(r_.text)

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PcktFlowsButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'send', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        dpid_ = self.__central.cellWidget(0, 0).text()
        self.debug("get_pckt_flows action: url=%s, dpid=%s" %
                   (self.__url, dpid_))
        try:
            r_ = requests.get(url=self.__url + dpid_)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                infos_ = r_.json()['packet_flows']
                lbs_ = ['dpid', 'in_port', 'flow_id', 'action', 'cookie',
                        'prio', 'table', 'hard', 'idle',
                        'dl_type', 'dl_src', 'dl_dst', 'vlan', 'vlan_prio',
                        'nw_proto', 'nw_src', 'nw_dst',
                        'nw_src_wc', 'nw_dst_wc', 'tp_src', 'tp_dst']
                self.__central.setRowCount(len(infos_))
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)

                i = 0
                for info_ in infos_:
                    self.__central.setCellWidget(i, 0,
                        QtGui.QTextEdit(str(info_['dpid'])))
                    self.__central.setCellWidget(i, 1,
                        QtGui.QTextEdit(str(info_['input_port'])))
                    self.__central.setCellWidget(i, 2,
                        QtGui.QTextEdit(str(info_['flow_id'])))
                    self.__central.setCellWidget(i, 3,
                        QtGui.QTextEdit(str(info_['action'])))
                    self.__central.setCellWidget(i, 4,
                        QtGui.QTextEdit(str(info_['cookie'])))
                    self.__central.setCellWidget(i, 5,
                        QtGui.QTextEdit(str(info_['priority'])))
                    self.__central.setCellWidget(i, 6,
                        QtGui.QTextEdit(str(info_['table_id'])))
                    self.__central.setCellWidget(i, 7,
                        QtGui.QTextEdit(str(info_['hard_timeout'])))
                    self.__central.setCellWidget(i, 8,
                        QtGui.QTextEdit(str(info_['idle_timeout'])))
                    self.__central.setCellWidget(i, 9,
                        QtGui.QTextEdit(str(info_['datalink_type'])))
                    self.__central.setCellWidget(i, 10,
                        QtGui.QTextEdit(str(info_['datalink_source'])))
                    self.__central.setCellWidget(i, 11,
                        QtGui.QTextEdit(str(info_['datalink_destination'])))
                    self.__central.setCellWidget(i, 12,
                        QtGui.QTextEdit(str(info_['datalink_vlan'])))
                    self.__central.setCellWidget(i, 13,
                        QtGui.QTextEdit(str(info_['datalink_vlan_priority'])))
                    self.__central.setCellWidget(i, 14,
                        QtGui.QTextEdit(str(info_['network_protocol'])))
                    self.__central.setCellWidget(i, 15,
                        QtGui.QTextEdit(str(info_['network_source'])))
                    self.__central.setCellWidget(i, 16,
                        QtGui.QTextEdit(str(info_['network_destination'])))
                    self.__central.setCellWidget(i, 17,
                        QtGui.QTextEdit(str(info_['network_source_num_wild'])))
                    self.__central.setCellWidget(i, 18,
                        QtGui.QTextEdit(str(info_['network_destination_num_wild'])))
                    self.__central.setCellWidget(i, 19,
                        QtGui.QTextEdit(str(info_['transport_source'])))
                    self.__central.setCellWidget(i, 20,
                        QtGui.QTextEdit(str(info_['transport_destination'])))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PathRequestButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'compute', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        params_ = {'ip_src': self.__central.cellWidget(0, 0).currentText(),
                   'ip_dst': self.__central.cellWidget(0, 1).currentText()}

        if self.__central.cellWidget(0, 2).text():
            src_port_ = int(self.__central.cellWidget(0, 2).text())
            params_.update({'src_port': src_port_})

        if self.__central.cellWidget(0, 3).text():
            dst_port_ = int(self.__central.cellWidget(0, 3).text())
            params_.update({'dst_port': dst_port_})

        if self.__central.cellWidget(0, 4).text():
            ip_proto_ = int(self.__central.cellWidget(0, 4).text())
            params_.update({'ip_proto': ip_proto_})

        if self.__central.cellWidget(0, 5).text():
            vlan_id_ = int(self.__central.cellWidget(0, 5).text())
            params_.update({'vlan_id': vlan_id_})

        self.debug("path_request action: url=%s, params=%s" %
                   (self.__url, str(params_)))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(params_),
                               headers={'content-type': 'application/json'})
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.info_popup(r_.text)

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PathBoDRequestButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'compute', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        start_ = self.__central.cellWidget(0, 0).dateTime().toTime_t()
        end_ = self.__central.cellWidget(0, 1).dateTime().toTime_t()

        params_ = {'start_time': start_,
                   'end_time': end_,
                   'ip_src': self.__central.cellWidget(0, 2).currentText(),
                   'ip_dst': self.__central.cellWidget(0, 3).currentText()}

        if self.__central.cellWidget(0, 4).text():
            src_port_ = int(self.__central.cellWidget(0, 4).text())
            params_.update({'src_port': src_port_})

        if self.__central.cellWidget(0, 5).text():
            dst_port_ = int(self.__central.cellWidget(0, 5).text())
            params_.update({'dst_port': dst_port_})

        if self.__central.cellWidget(0, 6).text():
            ip_proto_ = int(self.__central.cellWidget(0, 6).text())
            params_.update({'ip_proto': ip_proto_})

        if self.__central.cellWidget(0, 7).text():
            vlan_id_ = int(self.__central.cellWidget(0, 7).text())
            params_.update({'vlan_id': vlan_id_})

        if self.__central.cellWidget(0, 8).text():
            bw_ = int(self.__central.cellWidget(0, 8).text())
            if bw_ <= 0:
                self.error("Please, specify a reserved bandwidth value (>0)!")
                return

            params_.update({'bw': bw_})

        self.debug("bod_path_request action: url=%s, params=%s" %
                   (self.__url, str(params_)))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(params_),
                               headers={'content-type': 'application/json'})
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.info_popup(r_.text)

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PcktTableStatsButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'send', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        dpid_ = self.__central.cellWidget(0, 0).text()
        tableid_ = self.__central.cellWidget(0, 1).text()
        self.debug("get_pckt_port_stats action: url=%s, dpid=%s, tableid=%s" %
                   (self.__url, dpid_, tableid_))
        try:
            params_ = {'dpid': dpid_, 'tableid': tableid_}
            r_ = requests.get(url=self.__url, params=params_)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                infos_ = r_.json()['packet_table_stats']
                lbs_ = ['dpid', 'table_id', 'max_entries',
                        'active', 'matched', 'lookup']
                self.__central.setRowCount(len(infos_))
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)

                i = 0
                for info_ in infos_:
                    self.__central.setCellWidget(i, 0,
                        QtGui.QTextEdit(str(info_['dpid'])))
                    self.__central.setCellWidget(i, 1,
                        QtGui.QTextEdit(str(info_['table_id'])))
                    self.__central.setCellWidget(i, 2,
                        QtGui.QTextEdit(str(info_['max_entries'])))
                    self.__central.setCellWidget(i, 3,
                        QtGui.QTextEdit(str(info_['active'])))
                    self.__central.setCellWidget(i, 4,
                        QtGui.QTextEdit(str(info_['matched'])))
                    self.__central.setCellWidget(i, 5,
                        QtGui.QTextEdit(str(info_['lookup'])))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PcktPortStatsButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'send', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        dpid_ = self.__central.cellWidget(0, 0).text()
        portno_ = self.__central.cellWidget(0, 1).text()
        self.debug("get_pckt_port_stats action: url=%s, dpid=%s, portno=%s" %
                   (self.__url, dpid_, portno_))
        try:
            params_ = {'dpid': dpid_, 'portno': portno_}
            r_ = requests.get(url=self.__url, params=params_)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                infos_ = r_.json()['packet_port_stats']
                lbs_ = ['port_no', 'collisions',
                        'tx_pkts', 'tx_bytes', 'tx_dropped', 'tx_errors',
                        'rx_pkts', 'rx_bytes', 'rx_dropped', 'rx_errors',
                        'rx_crc_err', 'rx_frame_err', 'rx_over_err']
                self.__central.setRowCount(len(infos_))
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)

                i = 0
                for info_ in infos_:
                    self.__central.setCellWidget(i, 0,
                        QtGui.QTextEdit(str(info_['port_no'])))
                    self.__central.setCellWidget(i, 1,
                        QtGui.QTextEdit(str(info_['collisions'])))
                    self.__central.setCellWidget(i, 2,
                        QtGui.QTextEdit(str(info_['tx_pkts'])))
                    self.__central.setCellWidget(i, 3,
                        QtGui.QTextEdit(str(info_['tx_bytes'])))
                    self.__central.setCellWidget(i, 4,
                        QtGui.QTextEdit(str(info_['tx_dropped'])))
                    self.__central.setCellWidget(i, 5,
                        QtGui.QTextEdit(str(info_['tx_errors'])))
                    self.__central.setCellWidget(i, 6,
                        QtGui.QTextEdit(str(info_['rx_pkts'])))
                    self.__central.setCellWidget(i, 7,
                        QtGui.QTextEdit(str(info_['rx_bytes'])))
                    self.__central.setCellWidget(i, 8,
                        QtGui.QTextEdit(str(info_['rx_dropped'])))
                    self.__central.setCellWidget(i, 9,
                        QtGui.QTextEdit(str(info_['rx_errors'])))
                    self.__central.setCellWidget(i, 10,
                        QtGui.QTextEdit(str(info_['rx_crc_err'])))
                    self.__central.setCellWidget(i, 11,
                        QtGui.QTextEdit(str(info_['rx_frame_err'])))
                    self.__central.setCellWidget(i, 12,
                        QtGui.QTextEdit(str(info_['rx_over_err'])))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class ServiceInfoButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'details', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        self.debug("get_service_info action: url=%s" % self.__url)
        try:
            r_ = requests.get(url=self.__url)
            if r_.status_code != requests.codes.ok:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                infos_ = r_.json()['info']
                lbs_ = ['service_id', 'src_dpid', 'src_portno', 'dst_dpid',
                        'dst_portno','bw (Kb)']
                self.__central.setRowCount(len(infos_))
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)

                i = 0
                for info_ in infos_:
                    self.__central.setCellWidget(i, 0,
                        QtGui.QTextEdit(str(info_['service_id'])))
                    self.__central.setCellWidget(i, 1,
                        QtGui.QTextEdit(str(info_['src_dpid'])))
                    self.__central.setCellWidget(i, 2,
                        QtGui.QTextEdit(str(info_['src_portno'])))
                    self.__central.setCellWidget(i, 3,
                        QtGui.QTextEdit(str(info_['dst_dpid'])))
                    self.__central.setCellWidget(i, 4,
                        QtGui.QTextEdit(str(info_['dst_portno'])))
                    self.__central.setCellWidget(i, 5,
                        QtGui.QTextEdit(str(info_['bw'])))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class ServiceDeleteButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'delete', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central
        self.__parent = parent

    def onClick(self):
        self.debug("delete_service action: url=%s" % self.__url)
        try:
            requests.delete(url=self.__url)
            self.info_popup("Service Deleted!")
            self.__central.clear()
            self.__parent.get_services()

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class MediaPlayButton(Button):

    def __init__(self, url, payload, central, parent):
        Button.__init__(self, 'play', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__params = payload
        self.__central = central
        self.__parent = parent

    def onClick(self):
        self.debug("media_play action: url=%s, params=%s" %
                   (self.__url, self.__params))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(self.__params),
                               headers={'content-type': 'application/json'})
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.info_popup(r_.text)

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class HostsEnvButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'env-describe', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central
        self.__parent = parent

    def header(self, central):
        central.setColumnCount(3)

        central.setHorizontalHeaderLabels(['SRC_IP', 'DST_IP', 'BW'])
        central.setCellWidget(0, 0, QtGui.QLineEdit('a.b.c.d'))
        central.setCellWidget(0, 1, QtGui.QLineEdit('e.f.g.h'))
        central.setCellWidget(0, 2, QtGui.QLineEdit('0'))

    def routeButton(self, url, central, parent, ports, links, hosts):
        return HostsRouteButton(url, central, parent, ports, links, hosts)

    def onClick(self):
        ports_ = self.__central.cellWidget(0, 0).currentText()
        links_ = self.__central.cellWidget(0, 1).currentText()
        hosts_ = self.__central.cellWidget(0, 2).currentText()
        self.debug("hosts-env descr: url=%s, ports=%s, links=%s, hosts=%s" %
                   (self.__url, ports_, links_, hosts_))

        self.__central.clear()
        self.__central.setRowCount(3+int(ports_)+2+int(links_)+2+int(hosts_)+2)
        self.header(self.__central)

        self.__central.setCellWidget(2, 0, QtGui.QTextEdit('DPID'))
        self.__central.setCellWidget(2, 1, QtGui.QTextEdit('PORT-NO'))

        i = 3
        for x_ in range(0, int(ports_)):
            self.__central.setCellWidget(i,0,QtGui.QLineEdit('dpid-'+str(x_)))
            self.__central.setCellWidget(i,1,QtGui.QLineEdit('pno-'+str(x_)))
            i = i + 1

        i = i + 1
        self.__central.setCellWidget(i, 0, QtGui.QTextEdit('LINK-ID'))
        self.__central.setCellWidget(i, 1, QtGui.QTextEdit('CAPACITY'))
        i = i + 1
        for x_ in range(0, int(links_)):
            self.__central.setCellWidget(i,0,QtGui.QLineEdit('lid-'+str(x_)))
            self.__central.setCellWidget(i,1,QtGui.QLineEdit('cap-'+str(x_)))
            i = i + 1

        i = i + 1
        self.__central.setCellWidget(i, 0, QtGui.QTextEdit('IP-ADDRESS'))
        self.__central.setCellWidget(i, 1, QtGui.QTextEdit('DPID'))
        self.__central.setCellWidget(i, 2, QtGui.QTextEdit('PORT_NO'))
        i = i + 1
        for x_ in range(0, int(hosts_)):
            self.__central.setCellWidget(i,0,QtGui.QLineEdit('ip-'+str(x_)))
            self.__central.setCellWidget(i,1,QtGui.QLineEdit('dpid-'+str(x_)))
            self.__central.setCellWidget(i,2,QtGui.QLineEdit('pno-'+str(x_)))
            i = i + 1

        i = i + 1
        c0_ = self.routeButton(self.__url, self.__central, self.__parent,
                               ports_, links_, hosts_)
        self.__central.setCellWidget(i, 0, c0_)
        self.__central.resizeColumnsToContents()


class HostsRouteButton(Button):

    def __init__(self, url, central, parent, ps, ls, hs):
        Button.__init__(self, 'route', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__c = central
        self.__parent = parent
        self.__ps = ps
        self.__ls = ls
        self.__hs = hs

    def endpoints(self, central):
        return {'src_ip_addr':   central.cellWidget(0,0).text(),
                'dst_ip_addr':   central.cellWidget(0,1).text(),
                'bw_constraint': central.cellWidget(0,2).text()}

    def dpids(self, start, params):
        a_ = {}
        for x_ in range(0, int(self.__ps)):
            if a_.has_key(self.__c.cellWidget(start,0).text()):
                a_[self.__c.cellWidget(start,0).text()].append(
                                        self.__c.cellWidget(start,1).text())
            else:
                a_[self.__c.cellWidget(start,0).text()] =\
                                        [self.__c.cellWidget(start,1).text()]
            start = start + 1

        for k_ in a_.keys():
            tmp_ = {'dpid': k_, 'ports': []}
            for v_ in a_[k_]:
                tmp_['ports'].append({'port_no': v_})
            params.append(tmp_)

        return start

    def links(self, start, params):
        for x_ in range(0, int(self.__ls)):
            params.append({'id': self.__c.cellWidget(start,0).text(),
                           'capacity': self.__c.cellWidget(start,1).text()})
            start = start + 1

        return start

    def hosts(self, start, params):
        for x_ in range(0, int(self.__hs)):
            params.append({'ip_addr': self.__c.cellWidget(start,0).text(),
                           'dpid': self.__c.cellWidget(start,1).text(),
                           'port_no': self.__c.cellWidget(start,2).text()})
            start = start + 1

        return start

    def onClick(self):
        topo_ = {'dpids': [], 'links': [], 'hosts': []}
        params_={'endpoints': self.endpoints(self.__c),
                 'topology':  topo_}
        i = 3
        i = self.dpids(i, params_['topology']['dpids'])

        i = i + 2
        i = self.links(i, params_['topology']['links'])

        i = i + 2
        i = self.hosts(i, params_['topology']['hosts'])

        self.debug("route: url=%s, params=%s" % (self.__url, params_))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(params_),
                               headers={'content-type': 'application/json'})
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.info_popup(r_.text)

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class PortsEnvButton(HostsEnvButton):

    def __init__(self, url, central, parent):
        HostsEnvButton.__init__(self, url, central, parent)

    def header(self, central):
        central.setColumnCount(5)

        central.setHorizontalHeaderLabels(['SRC_DPID', 'SRC_PORT',
                                           'DST_DPID', 'DST_PORT', 'BW'])
        central.setCellWidget(0, 0, QtGui.QLineEdit('1'))
        central.setCellWidget(0, 1, QtGui.QLineEdit('1'))
        central.setCellWidget(0, 2, QtGui.QLineEdit('2'))
        central.setCellWidget(0, 3, QtGui.QLineEdit('2'))
        central.setCellWidget(0, 4, QtGui.QLineEdit('0'))

    def routeButton(self, url, central, parent, ports, links, hosts):
        return PortsRouteButton(url, central, parent, ports, links, hosts)


class PortsRouteButton(HostsRouteButton):

    def __init__(self, url, central, parent, ps, ls, hs):
        HostsRouteButton.__init__(self, url, central, parent, ps, ls, hs)

    def endpoints(self, central):
        return {'src_dpid':      central.cellWidget(0,0).text(),
                'src_port_no':   central.cellWidget(0,1).text(),
                'dst_dpid':      central.cellWidget(0,2).text(),
                'dst_port_no':   central.cellWidget(0,3).text(),
                'bw_constraint': central.cellWidget(0,4).text()}


class EntriesEnvButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'env-describe', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__c = central
        self.__parent = parent

    def onClick(self):
        entries_ = self.__c.cellWidget(0, 0).currentText()
        self.debug("entries-env descr: url=%s, entries=%s" %
                   (self.__url, entries_))

        self.__c.clear()
        self.__c.setRowCount(2+int(entries_))
        self.__c.setColumnCount(9)
        self.__c.setHorizontalHeaderLabels(['DPID','IN_PORT','OUT_PORT','VLAN',
                                 'SRC_IP','DST_IP','SRC_TCP','DST_TCP','IDLE'])
        i = 0
        for x_ in range(0, int(entries_)):
            self.__c.setCellWidget(i,0,QtGui.QLineEdit('dpid-'+str(x_)))
            self.__c.setCellWidget(i,1,QtGui.QLineEdit('in-pno-'+str(x_)))
            self.__c.setCellWidget(i,2,QtGui.QLineEdit('out-pno-'+str(x_)))
            self.__c.setCellWidget(i,3,QtGui.QLineEdit('vlan-'+str(x_)))
            self.__c.setCellWidget(i,4,QtGui.QLineEdit('src-ip-'+str(x_)))
            self.__c.setCellWidget(i,5,QtGui.QLineEdit('dst-ip-'+str(x_)))
            self.__c.setCellWidget(i,6,QtGui.QLineEdit('src-tcp-'+str(x_)))
            self.__c.setCellWidget(i,7,QtGui.QLineEdit('dst-tcp-'+str(x_)))
            self.__c.setCellWidget(i,8,QtGui.QLineEdit('idle-'+str(x_)))
            i = i + 1

        i = i + 1
        c0_ = EntriesButton(self.__url, self.__c, self.__parent, entries_)
        self.__c.setCellWidget(i, 0, c0_)
        self.__c.resizeColumnsToContents()


class EntriesButton(Button):

    def __init__(self, url, central, parent, es):
        Button.__init__(self, 'create', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__c = central
        self.__parent = parent
        self.__es = es

    def routes(self, start, params):
        for x_ in range(0, int(self.__es)):
            tmp_ = {'dpid':self.__c.cellWidget(start,0).text(),
                    'in_port_no':self.__c.cellWidget(start,1).text(),
                    'out_port_no':self.__c.cellWidget(start,2).text(),
                    'vlan_id':self.__c.cellWidget(start,3).text()}

            if self.__c.cellWidget(start,4).text():
                tmp_['src_ip_addr'] = self.__c.cellWidget(start,4).text()
            if self.__c.cellWidget(start,5).text():
                tmp_['dst_ip_addr'] = self.__c.cellWidget(start,5).text()
            if self.__c.cellWidget(start,6).text():
                tmp_['src_tcp_port'] = self.__c.cellWidget(start,6).text()
            if self.__c.cellWidget(start,7).text():
                tmp_['dst_tcp_port'] = self.__c.cellWidget(start,7).text()
            if self.__c.cellWidget(start,8).text():
                tmp_['idle_timeout'] = self.__c.cellWidget(start,8).text()

            params.append(tmp_)
            start = start + 1

    def __show_route(self, l, info):
        src_ip_ = str(info.get('src_ip_addr', ''))
        dst_ip_ = str(info.get('dst_ip_addr', ''))
        src_tcp_ = str(info.get('src_tcp_port', ''))
        dst_tcp_ = str(info.get('dst_tcp_port', ''))
        idle_ = str(info.get('idle_timeout', ''))

        self.__c.setCellWidget(l,0,QtGui.QTextEdit(str(info['entry_id'])))
        self.__c.setCellWidget(l,1,QtGui.QTextEdit(str(info['dpid'])))
        self.__c.setCellWidget(l,2,QtGui.QTextEdit(str(info['in_port_no'])))
        self.__c.setCellWidget(l,3,QtGui.QTextEdit(str(info['out_port_no'])))
        self.__c.setCellWidget(l,4,QtGui.QTextEdit(str(info['vlan_id'])))
        self.__c.setCellWidget(l,5,QtGui.QTextEdit(src_ip_))
        self.__c.setCellWidget(l,6,QtGui.QTextEdit(dst_ip_))
        self.__c.setCellWidget(l,7,QtGui.QTextEdit(src_tcp_))
        self.__c.setCellWidget(l,8,QtGui.QTextEdit(dst_tcp_))
        self.__c.setCellWidget(l,9,QtGui.QTextEdit(idle_))

    def onClick(self):
        params_ = {'routes': []}
        self.routes(0, params_['routes'])

        self.debug("create: url=%s, params=%s" % (self.__url, params_))
        try:
            r_ = requests.post(url=self.__url, data=json.dumps(params_),
                               headers={'content-type': 'application/json'})
            self.debug("Response obj=%s" % (r_))
            if r_.status_code != 201:
                self.error(r_.text)

            else:
                self.debug("Response=%s" % r_.text)
                self.__c.clear()
                self.__c.setRowCount(len(r_.json()['routes']))
                self.__c.setColumnCount(10)
                ls_ = ['ENTRY-ID','DPID','IN-PORT','OUT-PORT','VLAN-ID',
                       'SRC-IP','DST-IP','SRC-TCP-PORT','DST-TCP-PORT','IDLE']
                self.__c.setHorizontalHeaderLabels(ls_)

                i = 0
                for r_ in r_.json()['routes']:
                    self.__show_route(i, r_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class DeleteEntryButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'delete', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__c = central
        self.__parent = parent

    def onClick(self):
        id_ = self.__c.cellWidget(0,0).text()

        self.debug("delete-entry: url=%s, id=%s" % (self.__url, id_))
        try:
            r_ = requests.delete(url=self.__url + id_)
            self.debug("Response obj=%s" % (r_))
            if r_.status_code != 204:
                self.error(r_.text)

            else:
                self.info_popup('Successfully deleted!')

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class DeleteDBTopologyButton(Button):

    def __init__(self, url, central, parent):
        Button.__init__(self, 'delete topology db', parent)
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__c = central
        self.__parent = parent

    def onClick(self):
        self.debug("delete-topology-db: url=%s" % (self.__url,))
        try:
            r_ = requests.delete(url=self.__url)
            self.debug("Response obj=%s" % (r_))
            if r_.status_code != 204:
                self.error(r_.text)

            else:
                self.info_popup('Successfully deleted!')

        except requests.exceptions.RequestException as exc:
            self.error(str(exc))


class GUIManager(QtGui.QMainWindow):

    def __init__(self, cmaddr, cmport, msaddr, msport):
        QtGui.QMainWindow.__init__(self)
        self.__url = 'http://' + cmaddr + ':' + cmport + '/'
        self.__media_url = 'http://' + msaddr + ':' + msport + '/'
        self.__table = None
        self.__shell = None
        self.__initUI()

        self.shell().debug("GUIManager started: %s" % str(self))

    def __str__(self):
        return "core_manager_url=%s, media_server_url=%s" %\
               (self.__url, self.__media_url)

    def __center(self):
        qr_ = self.frameGeometry()
        cp_ = QtGui.QDesktopWidget().availableGeometry().center()
        qr_.moveCenter(cp_)
        self.move(qr_.topLeft())

    def __exitAction(self):
        act_ = QtGui.QAction('Exit', self)
        act_.setShortcut('Ctrl+Q')
        act_.setStatusTip('Exit application')
        act_.triggered.connect(self.close)
        return act_

    def __getDpidsAction(self):
        act_ = QtGui.QAction('Get DPIDS', self)
        act_.setStatusTip('GET dpids request')
        act_.triggered.connect(self.get_dpids)
        return act_

    def __getPortsAction(self):
        act_ = QtGui.QAction('Get PORTS', self)
        act_.setStatusTip('GET ports request')
        act_.triggered.connect(self.get_ports)
        return act_

    def __getLinksAction(self):
        act_ = QtGui.QAction('Get LINKS', self)
        act_.setStatusTip('GET links request')
        act_.triggered.connect(self.get_links)
        return act_

    def __getHostsAction(self):
        act_ = QtGui.QAction('Get HOSTS', self)
        act_.setStatusTip('GET hosts request')
        act_.triggered.connect(self.get_hosts)
        return act_

    def __addHostAction(self):
        act_ = QtGui.QAction('Add HOST', self)
        act_.setStatusTip('CREATE host request')
        act_.triggered.connect(self.add_host)
        return act_

    def __getPcktFlowsAction(self):
        act_ = QtGui.QAction('Get Pckt FLOWS', self)
        act_.setStatusTip('GET packet flow-entries request')
        act_.triggered.connect(self.get_pckt_flows)
        return act_

    def __pathRequestAction(self):
        act_ = QtGui.QAction('Path Request', self)
        act_.setStatusTip('COMPUTE path request')
        act_.triggered.connect(self.compute_path_request)
        return act_

    def __pathBoDRequestAction(self):
        act_ = QtGui.QAction('Path (BoD) Request', self)
        act_.setStatusTip('COMPUTE path request with bandwidth constraints')
        act_.triggered.connect(self.compute_path_bod_request)
        return act_

    def __getServicesAction(self):
        act_ = QtGui.QAction('GET SERVICES', self)
        act_.setStatusTip('GET services request')
        act_.triggered.connect(self.get_services)
        return act_

    def __getPcktTableStatsAction(self):
        act_ = QtGui.QAction('Get TABLE stats', self)
        act_.setStatusTip('GET table statistics request')
        act_.triggered.connect(self.get_pckt_table_stats)
        return act_

    def __getPcktPortStatsAction(self):
        act_ = QtGui.QAction('Get PORT stats', self)
        act_.setStatusTip('GET port statistics request')
        act_.triggered.connect(self.get_pckt_port_stats)
        return act_

    def __getMultiMediaAction(self):
        act_ = QtGui.QAction('Get CATALOG', self)
        act_.setStatusTip('GET catalog request')
        act_.triggered.connect(self.get_catalog)
        return act_

    def __getTopologyAction(self):
        act_ = QtGui.QAction('Get Topology', self)
        act_.setStatusTip('GET topology request')
        act_.triggered.connect(self.get_topology)
        return act_

    def __getRouteHostsAction(self):
        act_ = QtGui.QAction('Post RouteHosts', self)
        act_.setStatusTip('POST route-hosts request')
        act_.triggered.connect(self.get_routeHosts)
        return act_

    def __getRoutePortsAction(self):
        act_ = QtGui.QAction('Post RoutePorts', self)
        act_.setStatusTip('POST route-ports request')
        act_.triggered.connect(self.get_routePorts)
        return act_

    def __createEntryAction(self):
        act_ = QtGui.QAction('Post entry', self)
        act_.setStatusTip('POST entry request')
        act_.triggered.connect(self.create_entry)
        return act_

    def __deleteEntryAction(self):
        act_ = QtGui.QAction('Delete entry', self)
        act_.setStatusTip('DELETE entry request')
        act_.triggered.connect(self.delete_entry)
        return act_

    def __deleteDBAction(self):
        act_ = QtGui.QAction('Delete DB topology', self)
        act_.setStatusTip('DELETE db-topology request')
        act_.triggered.connect(self.delete_db_topology)
        return act_

    def __menuBar(self):
        mb_ = self.menuBar()
        fmenu_ = mb_.addMenu('&File')
        fmenu_.addAction(self.__exitAction())

        tmenu_ = mb_.addMenu('&Topology')
        tmenu_.addAction(self.__getDpidsAction())
        tmenu_.addAction(self.__getPortsAction())
        tmenu_.addAction(self.__getLinksAction())
        tmenu_.addAction(self.__getHostsAction())
        tmenu_.addSeparator()
        tmenu_.addAction(self.__addHostAction())

        pmenu_ = mb_.addMenu('&Provisioning')
        pmenu_.addAction(self.__pathRequestAction())
        pmenu_.addAction(self.__pathBoDRequestAction())
        pmenu_.addSeparator()
        pmenu_.addAction(self.__getServicesAction())
        pmenu_.addAction(self.__getPcktFlowsAction())

        smenu_ = mb_.addMenu('&Statistics')
        smenu_.addAction(self.__getPcktTableStatsAction())
        smenu_.addAction(self.__getPcktPortStatsAction())

        mmenu_ = mb_.addMenu('&MultiMedia')
        mmenu_.addAction(self.__getMultiMediaAction())

        exmenu_ = mb_.addMenu('&OscarsExtensions')
        exmenu_.addAction(self.__getTopologyAction())
        exmenu_.addAction(self.__getRouteHostsAction())
        exmenu_.addAction(self.__getRoutePortsAction())
        exmenu_.addAction(self.__createEntryAction())
        exmenu_.addAction(self.__deleteEntryAction())
        exmenu_.addAction(self.__deleteDBAction())

    def __toolBar(self):
        tb_ = self.addToolBar('gui-toolbar')
        tb_.addAction(self.__exitAction())
        tb_.addSeparator()

    def __centralTable(self):
        self.__table = QtGui.QTableWidget(1,1)
        self.__table.setHorizontalHeaderLabels(['Results'])

        self.__shell = Shell()

        central_ = QtGui.QWidget()
        layout_ = QtGui.QGridLayout()
        layout_.addWidget(self.__table, 0, 0)
        layout_.addWidget(self.__shell, 1, 0)
        central_.setLayout(layout_)

        self.setCentralWidget(central_)

    def __initUI(self):
        self.resize(500, 500)
        self.__center()
        self.setWindowTitle('Fibre controller GUI')

        self.__menuBar()
        self.__toolBar()
        self.__centralTable()

        self.statusBar().showMessage('Ready')
        self.show()

    def __get_time_widget(self):
        t_src_ = QtGui.QDateTimeEdit(QtCore.QDateTime.currentDateTime())
        t_src_.setDisplayFormat('dd/MM/yyyy hh:mm:ss')

        t_dst_ = QtGui.QDateTimeEdit(QtCore.QDateTime.currentDateTime())
        t_dst_.setDisplayFormat('dd/MM/yyyy hh:mm:ss')

        return (t_src_, t_dst_)

    def __set_time_widget(self, src, dst):
        if src != "":
            t_src_ = QtGui.QDateTimeEdit(QtCore.QDateTime.fromTime_t(int(src)))
            t_src_.setDisplayFormat('dd/MM/yyyy hh:mm:ss')

        else:
            t_src_ = QtGui.QTextEdit(src)

        if dst != "":
            t_dst_ = QtGui.QDateTimeEdit(QtCore.QDateTime.fromTime_t(int(dst)))
            t_dst_.setDisplayFormat('dd/MM/yyyy hh:mm:ss')

        else:
            t_dst_ = QtGui.QTextEdit(dst)

        return (t_src_, t_dst_)

    def __get_hosts_combo(self):
        src_ = QtGui.QComboBox()
        dst_ = QtGui.QComboBox()
        try:
            r_ = requests.get(url=self.__url + "hosts")
            if r_.status_code == requests.codes.ok:
                self.shell().debug("Response=%s" % r_.text)

                for host_ in r_.json()['hosts']:
                    src_.addItem(host_['ip_address'])
                    dst_.addItem(host_['ip_address'])

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

        return (src_, dst_)

    def centralWidget(self):
        return self.__table

    def shell(self):
        return self.__shell

    def warn(self, wrn_msg):
        QtGui.QMessageBox.warning(self,'Warning',wrn_msg,QtGui.QMessageBox.Ok)

    def critical(self, err_msg):
        QtGui.QMessageBox.critical(self,'Error',err_msg,QtGui.QMessageBox.Ok)

    def closeEvent(self, event):
        reply_ = QtGui.QMessageBox.question(self, 'Close Event',
                                            'Are you sure to quit?',
                         QtGui.QMessageBox.Yes|QtGui.QMessageBox.No,
                                            QtGui.QMessageBox.No)
        if reply_ == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    def get_dpids(self):
        self.shell().debug("get_dpids action")
        try:
            r_ = requests.get(url=self.__url + "dpids")
            if r_.status_code != requests.codes.ok:
                self.critical(r_.text)

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['dpids']))
                self.centralWidget().setColumnCount(2)
                self.centralWidget().setHorizontalHeaderLabels(['dpid', ''])
                i = 0
                for id_ in r_.json()['dpids']:
                    c1_ = DpidsInfoButton(self.__url + 'dpids/' + id_['dpid'],
                                          self.centralWidget(), self)
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(id_['dpid'])))
                    self.centralWidget().setCellWidget(i, 1, c1_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_ports(self):
        self.shell().debug("get_ports action")
        try:
            r_ = requests.get(url=self.__url + "ports")
            if r_.status_code != requests.codes.ok:
                self.critical(r_.text)

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['ports']))
                self.centralWidget().setColumnCount(3)
                self.centralWidget().setHorizontalHeaderLabels(['dpid',
                                                          'port-no', ''])
                i = 0
                for ids_ in r_.json()['ports']:
                    c2_ = PortsInfoButton(self.__url + 'ports/',
                            {'dpid': ids_['dpid'], 'portno': ids_['port_no']},
                                          self.centralWidget(), self)
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(ids_['dpid'])))
                    self.centralWidget().setCellWidget(i, 1,
                            QtGui.QTextEdit(str(ids_['port_no'])))
                    self.centralWidget().setCellWidget(i, 2, c2_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_links(self):
        self.shell().debug("get_links action")
        try:
            r_ = requests.get(url=self.__url + "links")
            if r_.status_code != requests.codes.ok:
                self.critical(r_.text)

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['links']))
                self.centralWidget().setColumnCount(5)
                lbs_ = ['src_dpid', 'src_port_no', 'dst_dpid',
                        'dst_port_no', 'available_bw (Kb)']
                self.centralWidget().setHorizontalHeaderLabels(lbs_)
                i = 0
                for ids_ in r_.json()['links']:
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(ids_['source_dpid'])))
                    self.centralWidget().setCellWidget(i, 1,
                            QtGui.QTextEdit(str(ids_['source_port_no'])))
                    self.centralWidget().setCellWidget(i, 2,
                            QtGui.QTextEdit(str(ids_['destination_dpid'])))
                    self.centralWidget().setCellWidget(i, 3,
                            QtGui.QTextEdit(str(ids_['destination_port_no'])))
                    self.centralWidget().setCellWidget(i, 4,
                            QtGui.QTextEdit(str(ids_['available_bw'] * 1000)))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_hosts(self):
        self.shell().debug("get_hosts action")
        try:
            r_ = requests.get(url=self.__url + "hosts")
            if r_.status_code != requests.codes.ok:
                self.warn("Not found any active host!")

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['hosts']))
                self.centralWidget().setColumnCount(4)
                lbs_ = ['ip', 'dpid', 'port_no', 'hw_addr']
                self.centralWidget().setHorizontalHeaderLabels(lbs_)
                i = 0
                for ids_ in r_.json()['hosts']:
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(ids_['ip_address'])))
                    self.centralWidget().setCellWidget(i, 1,
                            QtGui.QTextEdit(str(ids_['dpid'])))
                    self.centralWidget().setCellWidget(i, 2,
                            QtGui.QTextEdit(str(ids_['port_no'])))
                    self.centralWidget().setCellWidget(i, 3,
                            QtGui.QTextEdit(str(ids_['mac_address'])))
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def add_host(self):
        self.shell().debug("add_host action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(5)
        self.centralWidget().setHorizontalHeaderLabels(['ip-address',
                                        'mac', 'dpid', 'port-no', ''])

        c5_ = AddHostButton(self.__url + 'pckt_host',
                            self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0,QtGui.QLineEdit('x.x.x.x'))
        self.centralWidget().setCellWidget(0, 1,QtGui.QLineEdit('a:a:a:a:a:a'))
        self.centralWidget().setCellWidget(0, 2,QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 3,QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 4,c5_)

    def get_pckt_flows(self):
        self.shell().debug("get_pckt_flows action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(2)
        self.centralWidget().setHorizontalHeaderLabels(['Insert DPID', ''])

        c1_ = PcktFlowsButton(self.__url + 'pckt_flows/',
                              self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 1, c1_)

    def compute_path_request(self):
        self.shell().debug("compute_path_request action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(7)
        self.centralWidget().setHorizontalHeaderLabels(['ip_src', 'ip_dst',
                                    'tcp/udp port_src', 'tcp/udp port_dst',
                                    'ip_proto', 'vlan_id', ''])

        (combo_src_, combo_dst_) = self.__get_hosts_combo()

        c7_ = PathRequestButton(self.__url + 'pckt_host_path',
                                self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, combo_src_)
        self.centralWidget().setCellWidget(0, 1, combo_dst_)
        self.centralWidget().setCellWidget(0, 2, QtGui.QLineEdit('0'))
        self.centralWidget().setCellWidget(0, 3, QtGui.QLineEdit('0'))
        self.centralWidget().setCellWidget(0, 4, QtGui.QLineEdit('1'))
        self.centralWidget().setCellWidget(0, 5, QtGui.QLineEdit('65535'))
        self.centralWidget().setCellWidget(0, 6, c7_)

    def compute_path_bod_request(self):
        self.shell().debug("compute_path_bod_request action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(10)
        self.centralWidget().setHorizontalHeaderLabels(['start', 'end',
                                    'ip_src', 'ip_dst',
                                    'tcp/udp port_src', 'tcp/udp port_dst',
                                    'ip_proto', 'vlan_id', 'reserved bw (Kb)',
                                    ''])

        (time_start_, time_end_) = self.__get_time_widget()
        (combo_src_, combo_dst_) = self.__get_hosts_combo()

        c10_ = PathBoDRequestButton(self.__url + 'pckt_host_bod_path',
                                   self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, time_start_)
        self.centralWidget().setCellWidget(0, 1, time_end_)
        self.centralWidget().setCellWidget(0, 2, combo_src_)
        self.centralWidget().setCellWidget(0, 3, combo_dst_)
        self.centralWidget().setCellWidget(0, 4, QtGui.QLineEdit('0'))
        self.centralWidget().setCellWidget(0, 5, QtGui.QLineEdit('0'))
        self.centralWidget().setCellWidget(0, 6, QtGui.QLineEdit('1'))
        self.centralWidget().setCellWidget(0, 7, QtGui.QLineEdit('65535'))
        self.centralWidget().setCellWidget(0, 8, QtGui.QLineEdit('0'))
        self.centralWidget().setCellWidget(0, 9, c10_)

    def get_services(self):
        self.shell().debug("get_services action")
        try:
            r_ = requests.get(url=self.__url + "services")
            if r_.status_code != requests.codes.ok:
                self.warn("Not found any service!")

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['services']))
                self.centralWidget().setColumnCount(14)
                self.centralWidget().setHorizontalHeaderLabels(['serviceID',
                                 'status', 'notes', 'start_time', 'end_time',
                                 'ip_src', 'ip_dst', 'port_src', 'port_dst',
                                 'ip_proto', 'vlan_id', 'bw (Kb)', '', ''])
                i = 0
                for info_ in r_.json()['services']:
                    (start_, end_) = self.__set_time_widget(info_['start'],
                                                            info_['end'])

                    c13_ = ServiceInfoButton(self.__url + 'services/' +
                                             str(info_['service_id']),
                                             self.centralWidget(), self)
                    c14_ = ServiceDeleteButton(self.__url + 'services/' +
                                               str(info_['service_id']),
                                               self.centralWidget(), self)
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(info_['service_id'])))
                    self.centralWidget().setCellWidget(i, 1,
                            QtGui.QTextEdit(str(info_['status'])))
                    self.centralWidget().setCellWidget(i, 2,
                            QtGui.QTextEdit(str(info_['comments'])))
                    self.centralWidget().setCellWidget(i, 3, start_)
                    self.centralWidget().setCellWidget(i, 4, end_)
                    self.centralWidget().setCellWidget(i, 5,
                            QtGui.QTextEdit(str(info_['ip_src'])))
                    self.centralWidget().setCellWidget(i, 6,
                            QtGui.QTextEdit(str(info_['ip_dst'])))
                    self.centralWidget().setCellWidget(i, 7,
                            QtGui.QTextEdit(str(info_['port_src'])))
                    self.centralWidget().setCellWidget(i, 8,
                            QtGui.QTextEdit(str(info_['port_dst'])))
                    self.centralWidget().setCellWidget(i, 9,
                            QtGui.QTextEdit(str(info_['ip_proto'])))
                    self.centralWidget().setCellWidget(i, 10,
                            QtGui.QTextEdit(str(info_['vlan_id'])))
                    self.centralWidget().setCellWidget(i, 11,
                            QtGui.QTextEdit(str(info_['bw'])))
                    self.centralWidget().setCellWidget(i, 12, c13_)
                    self.centralWidget().setCellWidget(i, 13, c14_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_pckt_table_stats(self):
        self.shell().debug("get_pckt_table_stats action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(3)
        self.centralWidget().setHorizontalHeaderLabels(['Insert DPID',
                                                        'Insert TABLEID' ,''])

        c2_ = PcktTableStatsButton(self.__url + 'pckt_table_stats_info/',
                                   self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 1, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 2, c2_)

    def get_pckt_port_stats(self):
        self.shell().debug("get_pckt_port_stats action")
        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(3)
        self.centralWidget().setHorizontalHeaderLabels(['Insert DPID',
                                                        'Insert PORTNO' ,''])

        c2_ = PcktPortStatsButton(self.__url + 'pckt_port_stats_info/',
                                  self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 1, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 2, c2_)

    def get_catalog(self):
        self.shell().debug("get_catalog action")
        try:
            r_ = requests.get(url=self.__media_url + "media_catalog")
            if r_.status_code != requests.codes.ok:
                self.warn("Not found any MultiMedia object!")

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['catalog']))
                self.centralWidget().setColumnCount(2)
                self.centralWidget().setHorizontalHeaderLabels(['title', ''])

                i = 0
                for info_ in r_.json()['catalog']:
                    c2_ = MediaPlayButton(self.__media_url + 'media_play',
                                          {'title': str(info_['title'])},
                                          self.centralWidget(), self)
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(info_['title'])))
                    self.centralWidget().setCellWidget(i, 1, c2_)
                    i = i + 1

                self.centralWidget().resizeColumnsToContents()

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def __show_topology(self, r):
        c_ = self.centralWidget
        c_().clear()
        len_ = 1 + len(r.json()['topology']['dpids']) +\
               2 + len(r.json()['topology']['links']) +\
               2 + len(r.json()['topology']['hosts'])
        c_().setRowCount(len_)
        c_().setColumnCount(3)

        c_().setCellWidget(0, 0, QtGui.QLineEdit('DPIDs'))
        c_().setCellWidget(0, 1, QtGui.QLineEdit('PORTs'))
        i = 1
        for d_ in r.json()['topology']['dpids']:
            c_().setCellWidget(i,0,QtGui.QTextEdit(str(d_['dpid'])))
            cb_ = QtGui.QComboBox()
            for p_ in d_['ports']:
                cb_.addItem(str(p_['port_no']))

            c_().setCellWidget(i,1,cb_)
            i = i + 1

        i = i + 1
        c_().setCellWidget(i, 0, QtGui.QLineEdit('LINKs-ID'))
        c_().setCellWidget(i, 1, QtGui.QLineEdit('CAPACITY'))

        i = i + 1
        for l_ in r.json()['topology']['links']:
            c_().setCellWidget(i, 0, QtGui.QTextEdit(str(l_['id'])))
            c_().setCellWidget(i, 1, QtGui.QTextEdit(str(l_['capacity'])))
            i = i + 1

        i = i + 1
        c_().setCellWidget(i, 0, QtGui.QLineEdit('HOSTs-IP'))
        c_().setCellWidget(i, 1, QtGui.QLineEdit('DPID'))
        c_().setCellWidget(i, 2, QtGui.QLineEdit('PORT-No'))

        i = i + 1
        for h_ in r.json()['topology']['hosts']:
            c_().setCellWidget(i, 0, QtGui.QTextEdit(str(h_['ip_addr'])))
            c_().setCellWidget(i, 1, QtGui.QTextEdit(str(h_['dpid'])))
            c_().setCellWidget(i, 2, QtGui.QTextEdit(str(h_['port_no'])))
            i = i + 1

        c_().resizeColumnsToContents()

    def get_topology(self):
        self.shell().debug("get_topology action")
        try:
            r_ = requests.get(url=self.__url + "topology")
            self.shell().debug("Response obj=%s" % r_)
            if r_.status_code != requests.codes.ok:
                self.warn("Error code returned!")

            else:
                self.shell().debug("Response=%s" % r_.text)
                self.__show_topology(r_)

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_routeHosts(self):
        self.shell().debug("get_routeHosts action")
        self.centralWidget().clear()

        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(4)
        self.centralWidget().setHorizontalHeaderLabels(['N. PORTs',
                                        'N. LINKs', 'N. HOSTs', ''])

        c3_ = HostsEnvButton(self.__url + 'route_hosts',
                             self.centralWidget(), self)
        v_ = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        c0_ = QtGui.QComboBox()
        c0_.addItems(v_)
        c1_ = QtGui.QComboBox()
        c1_.addItems(v_)
        c2_ = QtGui.QComboBox()
        c2_.addItems(v_)

        self.centralWidget().setCellWidget(0, 0, c0_)
        self.centralWidget().setCellWidget(0, 1, c1_)
        self.centralWidget().setCellWidget(0, 2, c2_)
        self.centralWidget().setCellWidget(0, 3, c3_)

    def get_routePorts(self):
        self.shell().debug("get_routePorts action")
        self.centralWidget().clear()

        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(4)
        self.centralWidget().setHorizontalHeaderLabels(['N. PORTs',
                                        'N. LINKs', 'N. HOSTs', ''])

        c3_ = PortsEnvButton(self.__url + 'route_ports',
                             self.centralWidget(), self)
        v_ = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        c0_ = QtGui.QComboBox()
        c0_.addItems(v_)
        c1_ = QtGui.QComboBox()
        c1_.addItems(v_)
        c2_ = QtGui.QComboBox()
        c2_.addItems(v_)

        self.centralWidget().setCellWidget(0, 0, c0_)
        self.centralWidget().setCellWidget(0, 1, c1_)
        self.centralWidget().setCellWidget(0, 2, c2_)
        self.centralWidget().setCellWidget(0, 3, c3_)

    def create_entry(self):
        self.shell().debug("create_entry action")
        self.centralWidget().clear()

        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(2)
        self.centralWidget().setHorizontalHeaderLabels(['N. ENTRYs', ''])

        c1_ = EntriesEnvButton(self.__url + 'entry',
                               self.centralWidget(), self)
        v_ = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        c0_ = QtGui.QComboBox()
        c0_.addItems(v_)

        self.centralWidget().setCellWidget(0, 0, c0_)
        self.centralWidget().setCellWidget(0, 1, c1_)

    def delete_entry(self):
        self.shell().debug("delete_entry action")
        self.centralWidget().clear()

        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(2)
        self.centralWidget().setHorizontalHeaderLabels(['ENTRY-ID', ''])

        c1_ = DeleteEntryButton(self.__url+'entry/',self.centralWidget(),self)

        self.centralWidget().setCellWidget(0, 0, QtGui.QLineEdit('FFFF'))
        self.centralWidget().setCellWidget(0, 1, c1_)

    def delete_db_topology(self):
        self.shell().debug("delete_db_topology action")
        self.centralWidget().clear()

        self.centralWidget().setRowCount(1)
        self.centralWidget().setColumnCount(1)
        self.centralWidget().setHorizontalHeaderLabels([''])

        c1_ = DeleteDBTopologyButton(self.__url + 'topology_db',
                                     self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, c1_)


def main(argv=None):
    psr_ = ap.ArgumentParser(description='Fibre GUI-manager',
                             epilog='Report bugs to <r.monno@nextworks.it>',
                             formatter_class=ap.ArgumentDefaultsHelpFormatter)

    psr_.add_argument('--cm_addr', default='localhost',
                      help='core-manager address')

    psr_.add_argument('--cm_port', default='8080',
                      help='core-manager port number')

    psr_.add_argument('--ms_addr', default='localhost',
                      help='media-server address')

    psr_.add_argument('--ms_port', default='8081',
                      help='media-server port number')

    rets_ = psr_.parse_args()

    app = QtGui.QApplication(sys.argv)
    gm_ = GUIManager(rets_.cm_addr,rets_.cm_port,rets_.ms_addr,rets_.ms_port)
    app.exec_()

    return True


if __name__ == "__main__":
    sys.exit(main())
