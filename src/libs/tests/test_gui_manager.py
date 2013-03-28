#!/usr/bin/env python
# -*- coding: utf-8 -*-
# #
# # roberto monno r.monno@nextworks.it

import os
import sys
import requests
import argparse as ap
from PySide import QtGui

basepath = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
if basepath not in [ os.path.abspath(x) for x in sys.path ]:
    sys.path.insert(0, basepath)

import log

log.LOG.level_set('DEBUG')
GLOG = log.LOG


class DpidsInfoButton(QtGui.QPushButton):

    def __init__(self, url, central=None):
        QtGui.QPushButton.__init__(self, 'details')
        self.clicked.connect(self.onClick)
        self.__url = url
        self.__central = central

    def onClick(self):
        GLOG.debug("get_dpid_info action: %s", self.__url)
        try:
            r_ = requests.get(url=self.__url)
            if r_.status_code != requests.codes.ok:
                GLOG.error(r_.text)

            else:
                GLOG.debug("Response=%s" % r_.text)
                info_ = r_.json()['dpid']
                lbs_ = ['id', 'buffers', 'tables', 'ofp_capabilities',
                        'ofp_actions', 'cports']
                self.__central.setRowCount(1)
                self.__central.setColumnCount(len(lbs_))
                self.__central.setHorizontalHeaderLabels(lbs_)
                self.__central.setCellWidget(0, 0,
                            QtGui.QTextEdit(str(info_['id'])))
                self.__central.setCellWidget(0, 1,
                            QtGui.QTextEdit(str(info_['buffers'])))
                self.__central.setCellWidget(0, 2,
                            QtGui.QTextEdit(str(info_['tables'])))
                self.__central.setCellWidget(0, 3,
                            QtGui.QTextEdit(str(info_['ofp_capabilities'])))
                self.__central.setCellWidget(0, 4,
                            QtGui.QTextEdit(str(info_['ofp_actions'])))
                self.__central.setCellWidget(0, 5,
                            QtGui.QTextEdit(str(info_['cports'])))

        except requests.exceptions.RequestException as exc:
            GLOG.error(str(exc))


class GUIManager(QtGui.QMainWindow):

    def __init__(self, addr, port):
        QtGui.QMainWindow.__init__(self)
        self.__url = 'http://' + addr + ':' + port + '/'
        self.__initUI()

    def __str__(self):
        return self.__url

    def __critical(self, err_msg):
        QtGui.QMessageBox.critical(self, 'Exception', err_msg,
                                   QtGui.QMessageBox.Ok)

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

    def __menuBar(self):
        mb_ = self.menuBar()
        fmenu_ = mb_.addMenu('&File')
        fmenu_.addAction(self.__exitAction())

        tmenu_ = mb_.addMenu('&Topology')
        tmenu_.addAction(self.__getDpidsAction())
        tmenu_.addAction(self.__getPortsAction())

    def __toolBar(self):
        tb_ = self.addToolBar('gui-toolbar')
        tb_.addAction(self.__exitAction())
        tb_.addSeparator()

    def __centralTable(self):
        table_ = QtGui.QTableWidget(1,1)
        table_.setHorizontalHeaderLabels(['Results'])
        self.setCentralWidget(table_)

    def __initUI(self):
        self.resize(500, 500)
        self.__center()
        self.setWindowTitle('Fibre controller GUI')

        self.__menuBar()
        self.__toolBar()
        self.__centralTable()

        self.statusBar().showMessage('Ready')
        self.show()

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
        GLOG.debug("get_dpids action")
        try:
            r_ = requests.get(url=self.__url + "dpids")
            if r_.status_code != requests.codes.ok:
                self.__critical(r_.text)

            else:
                GLOG.debug("Response=%s" % r_.text)
                self.centralWidget().setRowCount(len(r_.json()['dpids']))
                self.centralWidget().setColumnCount(2)
                self.centralWidget().setHorizontalHeaderLabels(['dpid', ''])
                i = 0
                for id_ in r_.json()['dpids']:
                    c1_ = DpidsInfoButton(self.__url + 'dpids/' + id_['dpid'],
                                          self.centralWidget())
                    self.centralWidget().setCellWidget(i, 0,
                            QtGui.QTextEdit(str(id_['dpid'])))
                    self.centralWidget().setCellWidget(i, 1, c1_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.__critical(str(exc))

    def get_ports(self):
        GLOG.debug("get_ports action")
        try:
            r_ = requests.get(url=self.__url + "ports")
            if r_.status_code != requests.codes.ok:
                self.__critical(r_.text)

            else:
                GLOG.debug("Response=%s" % r_.text)
                return
                self.centralWidget().setRowCount(len(r_.json()['dpids']))
                self.centralWidget().setColumnCount(1)
                self.centralWidget().setHorizontalHeaderLabels(['dpid'])
                i = 0
                for id_ in r_.json()['dpids']:
                    cell_ = QtGui.QTextEdit(id_['dpid'])
                    self.centralWidget().setCellWidget(int(i), 0, cell_)
                    i = i + 1

        except requests.exceptions.RequestException as exc:
            self.__critical(str(exc))


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
    GLOG.debug("Options=%s" % str(rets_))

    app = QtGui.QApplication(sys.argv)
    gm_ = GUIManager(rets_.addr, rets_.port)
    GLOG.info("GUIManager started: %s", str(gm_))
    app.exec_()

    GLOG.info("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())
