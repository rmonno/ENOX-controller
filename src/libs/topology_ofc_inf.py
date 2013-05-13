# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" topology_ofc DB interface """

from abc import ABCMeta, abstractmethod


class DBException(Exception):
    """ DB Exception """

    def __init__(self, message):
        Exception.__init__(self, message)
        self._error = message

    def __str__(self):
        return self._error


class TopologyOFCBase(object):
    """ Topology OpenFlow Controller (OFC) DB Specification """

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, host, user, pswd, database, logger=None):
        """Constructor

        :param host    : address of mysql server
        :param user    : username of mysql user
        :param pswd    : password of mysql user
        :param database: mysql database name
        :param logger  : logging object
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
                        actions=None, buffers=None, tables=None,
                        cports=None):
        """Insert a new entry at datapaths table

        :param d_id   : datapath identifier (primary key)
        :param d_name : datapath human name
        :param caps   : capabilities supported by the datapath
        :param actions: bitmap of actions supported by the switch
        :param buffers: max packets buffered at once
        :param tables : number of tables supported by datapath
        :param cports : number of circuit ports

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
    def datapath_get_index(self, d_id):
        """Get unique index at datapaths table

        :param d_id: datapath identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def datapath_select(self, d_id=None):
        """Select * from datapaths table

        :param d_id: datapath identifier (optional)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_insert(self, d_id, port_no, hw_addr=None, name=None,
                    config=None, state=None, curr=None, advertised=None,
                    supported=None, peer=None, sw_tdm_gran=None,
                    sw_type=None, peer_port_no=None, peer_dpath_id=None):
        """Insert a new entry at ports table

        :param d_id         : datapath identifier (primary key)
        :param port_no      : port number (primary key)
        :param hw_addr      : mac address (typically)
        :param name         : port human name
        :param config       : spanning tree and administrative settings
        :param state        : spanning tree state
        :param curr         : current features
        :param advertised   : features being advertised by the port
        :param supported    : features supported by the port
        :param peer         : features advertised by peer
        :param sw_tdm_gran  : TDM switching granularity flags
        :param sw_type      : bitmap of switching type flags
        :param peer_port_no : discovered peer switching port number
        :param peer_dpath_id: discovered peer switching datapath identifier

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

    @abstractmethod
    def port_select(self, d_id=None, port_no=None):
        """Select * from ports table

        :param d_id: datapath identifier (optional)
        :param port_no: port number (optional)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_get_index(self, d_id, port_no):
        """Get unique index at ports table

        :param d_id   : datapath identifier (primary key)
        :param port_no: port number (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_get_curr_rate(self, d_id, port_no):
        """Get rate support at ports table

        :param d_id   : datapath identifier (primary key)
        :param port_no: port number (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_get_indexes(self, d_id):
        """Get unique indexes at ports table

        :param d_id: datapath identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def port_get_did_pno(self, node_index):
        """Get datapath identifier and port number at ports table

        :param node_index: node index

        :raises: DBException
        """
        pass

    @abstractmethod
    def link_insert(self, src_dpid, src_pno, dst_dpid, dst_pno,
                    bandwidth=None):
        """Insert a new entry at links table

        :param src_dpid : source datapath identifier (primary key)
        :param src_pno  : source port number (primary key)
        :param dst_dpid : destination datapath identifier
        :param src_pno  : destination port number
        :param bandwidth: link available bandwidth

        :raises: DBException
        """
        pass

    @abstractmethod
    def link_delete(self, src_dpid, src_pno):
        """Delete an entry at links table

        :param src_dpid : source datapath identifier (primary key)
        :param src_pno  : source port number (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def link_select(self, src_dpid=None, src_pno=None):
        """Select * from links table

        :param src_dpid : source datapath identifier (optional)
        :param src_pno  : source port number (optional)

        :raises: DBException
        """
        pass

    @abstractmethod
    def link_get_indexes(self, src_dpid):
        """Get unique indexes at links table

        :param src_dpid : source datapath identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def host_insert(self, mac_addr, dpid=None, in_port=None, ip_addr=None):
        """Insert a new entry at hosts table

        :param ip_addr  : Host IP Address
        :param mac_addr : Host MAC address
        :param dpid     : DPID of the switch host connected to
        :param in_port  : In_port of the switch host connected to
        :raises: DBException
        """
        pass

    @abstractmethod
    def host_delete(self, idd):
        """Delete an entry at hosts table

        :raises: DBException
        """
        pass

    @abstractmethod
    def host_select(self):
        """Select * from hosts table

        :raises: DBException
        """
        pass

    @abstractmethod
    def host_get_index(self, mac_addr):
        """Get unique index at hosts table

        :raises: DBException
        """
        pass

    @abstractmethod
    def host_update(self, mac_addr, ip_addr):
        """ host update """
        pass

    @abstractmethod
    def host_get_dpid(self, mac_addr):
        """ get host dpid """
        pass

    @abstractmethod
    def host_get_inport(self, mac_addr):
        """ get host inport """
        pass

    @abstractmethod
    def host_get_info(self, mac_addr):
        """ get host id, ip_addr, dpid, inport """
        pass

    @abstractmethod
    def host_get_mac_addr(self, ip_addr):
        """ get host mac address """
        pass

    @abstractmethod
    def host_get_indexes(self, d_id):
        """Get unique indexes at hosts table

        :param d_id: datapath identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def cport_bandwidth_insert(self, dpid, port_no, num_bandwidth,
                               bandwidth=None):
        """Insert a new entry at cports_bandwidth table

        :param dpid: datapath identifier (primary key)
        :param port_no: circuit switch port number (primary key)
        :param num_bandwidth: identifies number of bandwidth
                              array elements (primary key)
        :param bandwidth: bandwidth value

        :raises: DBException
        """
        pass

    @abstractmethod
    def cport_bandwidth_delete(self, dpid, port_no, num_bandwidth):
        """Delete an entry at cports_bandwidth table

        :param dpid: datapath identifier (primary key)
        :param port_no: circuit switch port number (primary key)
        :param num_bandwidth: identifies number of bandwidth
                              array elements (primary key)
        :raises: DBException
        """
        pass

    @abstractmethod
    def flow_insert(self, dpid, table_id=None, action=None, idle_timeout=None,
                    hard_timeout=None, priority=None, cookie=None,
                    dl_type=None, dl_vlan=None, dl_vlan_pcp=None, dl_src=None,
                    dl_dst=None, nw_src=None, nw_dst=None, nw_src_n_wild=None,
                    nw_dst_n_wild=None, nw_proto=None, tp_src=None,
                    tp_dst=None, in_port=None):
        """ Flow entry insert

        :param dpid:          datapath identifier
        :param table:         table identifier
        :param action:        action
        :param idle_timeout:  idle_timeout value
        :param hard_timeout:  hard_timeout value
        :param priority:      priority value
        :param cookie:        cookie value
        :param dl_type:       datalink type value
        :param dl_vlan:       datalink vlan value
        :param dl_vlan_pcp:   datalink vlan priority value
        :param dl_src:        datalink source address
        :param dl_dst:        datalink destination address
        :param nw_src:        network source address
        :param nw_dst:        network destination address
        :param nw_src_n_wild: wildcard for network source address
        :param nw_dst_n_wild: wildcard for network destination address
        :param nw_proto:      network proto value
        :param tp_src:        transport source port value
        :param tp_dst:        transport destination port value
        :param in_port:       ingress port identifier
        :raises: DBException
        """
        pass

    @abstractmethod
    def flow_delete(self, dpid):
        """ Flow entry deletion
        :param dpid: datapath identifier

        :raises: DBException
        """
        pass

    @abstractmethod
    def flow_select(self, dpid=None):
        """Select * from flow_entries table

        :raises: DBException
        """
        pass

    @abstractmethod
    def flow_get_index(self, dpid, table_id, dl_src=None, dl_dst=None,
                       nw_src=None, nw_dst=None, tp_src=None, tp_dst=None,
                       dl_vlan=None, dl_vlan_pcp=None, dl_type=None,
                       nw_proto=None, in_port=None):
        """ Get flow_entries index
        :param dpid:          datapath identifier
        :param table:         table identifier
        :param dl_src:        datalink source address
        :param dl_dst:        datalink destination address
        :param nw_src:        network source address
        :param nw_dst:        network destination address
        :param tp_src:        transport source port value
        :param tp_dst:        transport destination port value
        :param dl_vlan:       datalink vlan value
        :param dl_vlan_pcp:   datalink vlan priority value
        :param dl_type:       datalink type value
        :param nw_proto:      network proto value
        :param in_port:       ingress port identifier

        :raises: DBException
        """
        pass

    @abstractmethod
    def request_insert(self, ip_src, ip_dst, port_src, port_dst, ip_proto,
                       vlan_id, bw=None):
        """ Request entry insert

        :param ip_src:   source ip address (primary key)
        :param ip_dst:   destination ip address (primary key)
        :param port_src: sorce (tcp/udp) port number (primary key)
        :param port_dst: destination (tcp/udp) port number (primary key)
        :param ip_proto: ip protocol number (primary key)
        :param vlan_id:  vlan identifier (primary key)
        :param bw:       requested bandwidth

        :raises: DBException
        """
        pass

    @abstractmethod
    def request_get_serviceID(self, ip_src, ip_dst, port_src, port_dst,
                              ip_proto, vlan_id):
        """Get unique service ID at requests table

        :param ip_src:   source ip address (primary key)
        :param ip_dst:   destination ip address (primary key)
        :param port_src: sorce (tcp/udp) port number (primary key)
        :param port_dst: destination (tcp/udp) port number (primary key)
        :param ip_proto: ip protocol number (primary key)
        :param vlan_id:  vlan identifier (primary key)

        :raises: DBException
        """
        pass

    @abstractmethod
    def service_insert(self, service_id, dpid, port_no, bw=None):
        """ Service entry insert

        :param service_id: unique service identifier (primary key)
        :param dpid:       datapath identifier (primary key)
        :param port_no:    port number (primary key)
        :param bw:         bandwidth

        :raises: DBException
        """
        pass
