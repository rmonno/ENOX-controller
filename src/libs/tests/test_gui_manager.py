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

    def __initUI(self):
        self.resize(500, 500)
        self.__center()
        self.setWindowTitle('Fibre controller GUI')

        self.__menuBar()
        self.__toolBar()

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
                err_ = "Bad response code: %s" % r_.status_code
                self.__critical(err_)

            GLOG.info("Response=%s" % str(r_.body))

        except requests.exceptions.RequestException as exc:
            self.__critical(str(exc))

    def get_ports(self):
        GLOG.debug("get_ports action")


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
