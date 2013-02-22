# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno


import sys
import os
import logging
import ConfigParser

from color_log import *

log = ColorLog(logging.getLogger('config_parser'))


class NoxConfigParser:
    """Configuration File Parser Manager for NOX controller
    """

    def __init__(self, filename):
        self.address = None
        self.port    = None
        self.size    = None

        if self.__check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            ss = config.sections()
            for s in ss:
                if s == 'fpce':
                    self.address = config.get(s,'address')
                    self.port    = config.get(s,'port')
                    self.size    = config.get(s,'size')

        log.debug("Fpce address=%s, port=%s, size=%s",
                  self.address, self.port, self.size)

    def __check_file(self, fname):
        if not os.path.exists(fname):
            log.error("`" + fname + "' does not exist!")
            return False

        return True
