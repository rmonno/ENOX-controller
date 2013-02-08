# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright XXX Fixme XXX
#
# @author: Roberto Monno

from abc import ABCMeta, abstractmethod


class DBException(Exception):
    def __init__(self, message):
        self._error = message

    def __str__(self):
        return self._error


class TopologyOFCBase(object):
    """Topology OpenFlow Controller (OFC) DB Specification
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, host, user, pswd, db, logger=None):
        """Constructor

        :param host  : address of mysql server
        :param user  : username of mysql user
        :param pswd  : password of mysql user
        :param db    : mysql database name
        :param logger: logging object
        """
        pass

    @abstractmethod
    def open_transaction(self):
        """Connect to mysql database and open a transaction

        :raises: DBException in case of any failure
        """
        pass

    @abstractmethod
    def close(self):
        """Close connection to mysql database
        """
        pass

    @abstractmethod
    def commit(self):
        """Commit changes to mysql database

        :return: True or False
        """
        pass

    @abstractmethod
    def rollback(self):
        """Rollback changes and disconnect

        :return: True or False
        """
        pass

    @abstractmethod
    def datapath_insert(self, d_id, d_name=None, caps=None,
                        actions=None, buffers=None, tables=None):
        """Insert a new entry at datapaths table

        :param d_id   : datapath identifier (primary key)
        :param d_name : datapath human name
        :param caps   : capabilities supported by the datapath
        :param actions: bitmap of actions supported by the switch
        :param buffers: max packets buffered at once
        :param tables : number of tables supported by datapath

        :raises: DBException
        """
        pass

    @abstractmethod
    def datapath_delete(self, d_id):
        """Delete an entry at datapaths table

        :param d_id: datapath identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_insert(self, d_id, port_no, hw_addr=None, name=None,
                    config=None, state=None, curr=None, advertised=None,
                    supported=None, peer=None):
        """Insert a new entry at ports table

        :param d_id      : datapath identifier (primary key)
        :param port_no   : port number (primary key)
        :param hw_addr   : mac address (typically)
        :param name      : port human name
        :param config    : spanning tree and administrative settings
        :param state     : spanning tree state
        :param curr      : current features
        :param advertised: features being advertised by the port
        :param supported : features supported by the port
        :param peer      : features advertised by peer

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_delete(self, d_id, port_no):
        """Delete an entry at ports table

        :param d_id   : datapath identifier (primary key)
        :param port_no: port number (primary key)

        :raises: DBException
        """
        pass
