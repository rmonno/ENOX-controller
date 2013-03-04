#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# roberto monno r.monno@nextworks.it

""" Nox GUI Logger """

import logging, logging.handlers


class NoxGUILogger(object):
    """ NoxGui Logger object """

    def __init__(self, name, level=logging.DEBUG):
        self.__log = logging.getLogger(name)

        hdlr = logging.StreamHandler()
        fmtr = logging.Formatter('%(asctime)s: [%(levelname)s] %(message)s')
        hdlr.setFormatter(fmtr)

        self.__log.addHandler(hdlr)
        self.__log.setLevel(level)

    def debug(self, msg):
        self.__log.debug(msg)

    def info(self, msg):
        self.__log.info(msg)

    def error(self, msg):
        self.__log.error(msg)


NOX_GUI_LOG = NoxGUILogger('nxw-noxgui')
