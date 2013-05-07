#!/usr/bin/env python
# -*- coding: utf-8 -*-
# #
# # roberto monno r.monno@nextworks.it

import os
import sys
import requests
import json
import argparse as ap
from PySide import QtGui

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
        params_ = {'ip_src': self.__central.cellWidget(0, 0).text(),
                   'ip_dst': self.__central.cellWidget(0, 1).text()}

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


class GUIManager(QtGui.QMainWindow):

    def __init__(self, addr, port):
        QtGui.QMainWindow.__init__(self)
        self.__url = 'http://' + addr + ':' + port + '/'
        self.__table = None
        self.__shell = None
        self.__initUI()

        self.shell().debug("GUIManager started: %s" % str(self))

    def __str__(self):
        return self.__url

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

    def __menuBar(self):
        mb_ = self.menuBar()
        fmenu_ = mb_.addMenu('&File')
        fmenu_.addAction(self.__exitAction())

        tmenu_ = mb_.addMenu('&Topology')
        tmenu_.addAction(self.__getDpidsAction())
        tmenu_.addAction(self.__getPortsAction())
        tmenu_.addAction(self.__getLinksAction())
        tmenu_.addAction(self.__getHostsAction())

        pmenu_ = mb_.addMenu('&Provisioning')
        pmenu_.addAction(self.__pathRequestAction())
        pmenu_.addAction(self.__getPcktFlowsAction())

        smenu_ = mb_.addMenu('&Statistics')
        smenu_.addAction(self.__getPcktTableStatsAction())
        smenu_.addAction(self.__getPcktPortStatsAction())

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

    def centralWidget(self):
        return self.__table

    def shell(self):
        return self.__shell

    def critical(self, err_msg):
        QtGui.QMessageBox.critical(self, 'Exception', err_msg,
                                   QtGui.QMessageBox.Ok)

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
                self.centralWidget().setColumnCount(4)
                lbs_ = ['src_dpid', 'src_port_no', 'dst_dpid', 'dst_port_no']
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
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.critical(str(exc))

    def get_hosts(self):
        self.shell().debug("get_hosts action")
        try:
            r_ = requests.get(url=self.__url + "hosts")
            if r_.status_code != requests.codes.ok:
                self.critical(r_.text)

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

        c7_ = PathRequestButton(self.__url + 'pckt_host_path',
                                self.centralWidget(), self)
        self.centralWidget().setCellWidget(0, 0, QtGui.QLineEdit('x.x.x.x'))
        self.centralWidget().setCellWidget(0, 1, QtGui.QLineEdit('y.y.y.y'))
        self.centralWidget().setCellWidget(0, 2, QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 3, QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 4, QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 5, QtGui.QLineEdit(''))
        self.centralWidget().setCellWidget(0, 6, c7_)


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


def main(argv=None):
    psr_ = ap.ArgumentParser(description='Fibre GUI-manager',
                             epilog='Report bugs to <r.monno@nextworks.it>',
                             formatter_class=ap.ArgumentDefaultsHelpFormatter)

    psr_.add_argument('-a', '--addr',
                      default='localhost',
                      dest='addr',
                      help='core-manager address')

    psr_.add_argument('-p', '--port',
                      default='8080',
                      dest='port',
                      help='core-manager port number')

    rets_ = psr_.parse_args()

    app = QtGui.QApplication(sys.argv)
    gm_ = GUIManager(rets_.addr, rets_.port)
    app.exec_()

    return True


if __name__ == "__main__":
    sys.exit(main())
