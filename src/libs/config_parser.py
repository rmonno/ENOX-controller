# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Config Parser module """

import os
import logging
import ConfigParser

import color_log as cl

LOG = cl.ColorLog(logging.getLogger('config_parser'))


def check_file(fname):
    """ check if file exists"""
    if not os.path.exists(fname):
        LOG.error("`" + fname + "' does not exist!")
        return False

    return True


class NoxConfigParser:
    """Configuration File Parser Manager for NOX controller
    """

    def __init__(self, filename):
        self.address = None
        self.port = None
        self.size = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'fpce':
                    self.address = config.get(sect, 'address')
                    self.port = config.get(sect, 'port')
                    self.size = config.get(sect, 'size')

        LOG.debug("Fpce address=%s, port=%s, size=%s",
                  self.address, self.port, self.size)


class WebServConfigParser:
    """Configuration File Parser Manager for WebServ controller
    """

    def __init__(self, filename):
        self.host = None
        self.port = None
        self.timeout = None
        self.debug = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'webserv':
                    self.host = config.get(sect, 'host')
                    self.port = config.get(sect, 'port')
                    self.timeout = config.get(sect, 'timeout')
                    self.debug = config.get(sect, 'debug')

        LOG.debug("WebServ host=%s, port=%s, timeout=%s, debug=%s",
                  self.host, self.port, self.timeout, self.debug)
