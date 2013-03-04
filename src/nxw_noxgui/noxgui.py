#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# roberto monno r.monno@nextworks.it

""" Nox GUI """

import os
import sys
import argparse as ap
from PySide import QtGui

basepath = os.path.dirname(os.path.abspath(sys.argv[0]))
updir = os.path.dirname(basepath)
sys.path.insert(0, updir)

idl_find_path = updir + '/nox-classic/build/src'
for (root, dirs, names) in os.walk(idl_find_path):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')

import libs as nxw_utils
import noxdbconn as ndbc
import noxlog as nl

CLOG = nxw_utils.ColorLog(nl.NOX_GUI_LOG)


class NoxGUI(QtGui.QMainWindow):
    """ NOX GUI Main Window """

    def __init__(self, addr, user, pswd, db):
        self.__db = ndbc.NoxDBConnector(addr, user, pswd, db, CLOG)
        QtGui.QMainWindow.__init__(self)
        self.__initUI()

    # private
    def __center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def __exitAction(self):
        act_ = QtGui.QAction('Exit', self)
        act_.setShortcut('Ctrl+Q')
        act_.setStatusTip('Exit application')
        act_.triggered.connect(self.close)
        return act_

    def __createAction(self):
        act_ = QtGui.QAction('Create', self)
        act_.setStatusTip('Create Topology (sync topology_ofc db)')
        act_.triggered.connect(self.createTopology)
        return act_

    def __clearAction(self):
        act_ = QtGui.QAction('Clear', self)
        act_.setStatusTip('Clear all data')
        act_.triggered.connect(self.clear)
        return act_

    def __menuBar(self):
        mb_ = self.menuBar()
        fmenu_ = mb_.addMenu('&File')
        fmenu_.addAction(self.__exitAction())

    def __toolBar(self):
        tb_ = self.addToolBar('nox-toolbar')
        tb_.addAction(self.__exitAction())
        tb_.addSeparator()
        tb_.addAction(self.__createAction())
        tb_.addSeparator()
        tb_.addAction(self.__clearAction())

    def __initUI(self):
        self.resize(500, 500)
        self.__center()
        self.setWindowTitle('Fibre Open-Flow controller GUI')

        self.__menuBar()
        self.__toolBar()

        self.statusBar().showMessage('Ready')
        self.show()

    def closeEvent(self, event):
        reply = QtGui.QMessageBox.question(self, 'Close Event',
                                           "Are you sure to quit?",
                      QtGui.QMessageBox.Yes | QtGui.QMessageBox.No,
                                           QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    def createTopology(self):
        CLOG.debug("createTopology event")
        switches = self.__db.retry_switch()
        CLOG.debug("Switches=%s" % switches)

    def clear(self):
        CLOG.debug("clear event")


def main(argv=None):
    psr_ = ap.ArgumentParser(description='Fibre NOX-GUI',
                             epilog='Report bugs to <r.monno@nextworks.it>',
                             formatter_class=ap.ArgumentDefaultsHelpFormatter)

    psr_.add_argument('-a', '--addr',
                      default='127.0.0.1',
                      dest='addr',
                      help='database address')

    psr_.add_argument('-u', '--user',
                      default='root',
                      dest='user',
                      help='database user name')

    psr_.add_argument('-p', '--passwd',
                      default='root',
                      dest='passwd',
                      help='database user password')

    psr_.add_argument('-d', '--db',
                      default='topology_ofc_db',
                      dest='db',
                      help='use database')

    rets_ = psr_.parse_args()

    CLOG.debug("Options=%s" % str(rets_))

    app = QtGui.QApplication(sys.argv)
    noxgui = NoxGUI(rets_.addr, rets_.user, rets_.passwd, rets_.db)
    app.exec_()

    CLOG.info("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())
