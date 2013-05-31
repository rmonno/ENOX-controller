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


class DBConfigParser:
    """Configuration File Parser Manager for DB controller
    """

    def __init__(self, filename):
        self.name = None
        self.host = None
        self.user = None
        self.pswd = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'dbinfo':
                    self.name = config.get(sect, 'name')
                    self.host = config.get(sect, 'host')
                    self.user = config.get(sect, 'user')
                    self.pswd = config.get(sect, 'pswd')

        LOG.debug("DB name=%s, host=%s, user=%s, pswd=%s",
                  self.name, self.host, self.user, self.pswd)


class DiscoveryConfigParser:
    """Configuration File Parser Manager for Discovery controller
    """

    def __init__(self, filename):
        self.packet_region = None
        self.allow_ping = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'discovery':
                    self.packet_region = config.get(sect, 'packet_region')
                    self.allow_ping = config.get(sect, 'allow_ping')

        LOG.debug("Discovery packet_region=%s, allow_ping=%s",
                  self.packet_region, self.allow_ping)


class FlowsMonitorConfigParser:
    """Configuration File Parser Manager for FlowsMonitoring controller
    """

    def __init__(self, filename):
        self.timeout = None
        self.table_timeout = None
        self.port_timeout = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'flows-monitoring':
                    self.timeout = config.get(sect, 'timeout')
                    self.table_timeout = config.get(sect,'stats_table_timeout')
                    self.port_timeout = config.get(sect, 'stats_port_timeout')

        LOG.debug("FlowsMonitor timeout=%s, table_timeout=%s, port_timeout=%s",
                  self.timeout, self.table_timeout, self.port_timeout)


class ServiceBoDConfigParser:
    """Configuration File Parser Manager for ServiceBoD controller
    """

    def __init__(self, filename):
        self.timeout = None

        if check_file(filename):
            config = ConfigParser.ConfigParser()
            config.read(filename)

            sects = config.sections()
            for sect in sects:
                if sect == 'service-bod':
                    self.timeout = config.get(sect, 'timeout')

        LOG.debug("ServiceBoD timeout=%s", self.timeout)
