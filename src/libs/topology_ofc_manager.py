# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" topology_ofc DB manager """

import topology_ofc_inf as tofc
import MySQLdb as sql


class TopologyOFCManager(tofc.TopologyOFCBase):
    """Topology OpenFlow Controller (OFC) Manager
    """

    def __init__(self, host, user, pswd, database, logger=None):
        self._host = host
        self._user = user
        self._pswd = pswd
        self._db = database
        self._log = logger
        self._con = None

    # private
    def _debug(self, msg):
        """ debug """
        if self._log:
            self._log.debug(msg)

    def __execute(self, statement, values=None):
        """ execute """
        if not self._con:
            raise tofc.DBException("Transaction not opened yet!")

        cursor = None
        try:
            cursor = self._con.cursor()

            if values:
                self._debug(statement % values)
                cursor.execute(statement, values)
            else:
                self._debug(statement)
                cursor.execute(statement)

        except sql.Error as exe:
            message = "Error %d: %s" % (exe.args[0], exe.args[1])
            raise tofc.DBException(message)

        except Exception as exe:
            raise tofc.DBException(str(exe))

        finally:
            if cursor:
                cursor.close()

    def __execute_dict(self, statement, values=None, one=True):
        """ execute using dictionary """
        if not self._con:
            raise tofc.DBException("Transaction not opened yet!")

        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            if values:
                self._debug(statement % values)
                cursor.execute(statement, values)
            else:
                self._debug(statement)
                cursor.execute(statement)

            numrows = int(cursor.rowcount)
            if numrows:
                if one:
                    return cursor.fetchone()
                else:
                    return cursor.fetchall()

        except sql.Error as exe:
            message = "Error %d: %s" % (exe.args[0], exe.args[1])
            raise tofc.DBException(message)

        except Exception as exe:
            raise tofc.DBException(str(exe))

        finally:
            if cursor:
                cursor.close()

        raise tofc.DBException("Index not found!")

    # public
    def open_transaction(self):
        """ open transaction """
        if self._con:
            raise tofc.DBException("Transaction already opened!")

        try:
            self._debug("Try connecting to db...")
            self._con = sql.connect(host=self._host,
                                    user=self._user,
                                    passwd=self._pswd,
                                    db=self._db)
            self._debug("Connected to %s (%s)" % (self._host,
                                                  self._db))
        except sql.Error as exe:
            message = "Error %d: %s" % (exe.args[0], exe.args[1])
            raise tofc.DBException(message)

    def close(self):
        """ close transation """
        if self._con:
            self._con.close()
            self._debug("Closed connection to %s" % self._host)

        self._con = None

    def commit(self):
        """ commit transaction """
        if self._con:
            self._con.commit()
            self._debug("Committed!")
            return True

        else:
            return False

    def rollback(self):
        """ rollback transaction """
        if self._con:
            self._con.rollback()
            self._debug("RollBacked!")
            return True

        else:
            return False

    def datapath_insert(self, d_id, d_name=None, caps=None,
                        actions=None, buffers=None, tables=None,
                        cports=None):
        """ datapath insert """
        table = "datapaths"

        stat_header = "INSERT INTO " + table + "(id"
        stat_body = "VALUES (%s"
        values = (str(d_id),)

        if d_name is not None:
            stat_header += ", name"
            stat_body += ", %s"
            values = values + (str(d_name),)

        if caps is not None:
            stat_header += ", ofp_capabilities"
            stat_body += ", %s"
            values = values + (str(caps),)

        if actions is not None:
            stat_header += ", ofp_actions"
            stat_body += ", %s"
            values = values + (str(actions),)

        if buffers is not None:
            stat_header += ", buffers"
            stat_body += ", %s"
            values = values + (str(buffers),)

        if tables is not None:
            stat_header += ", tables"
            stat_body += ", %s"
            values = values + (str(tables),)

        if cports is not None:
            stat_header += ", cports"
            stat_body += ", %s"
            values = values + (str(cports),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def datapath_delete(self, d_id):
        """ datapath delete """
        table = "datapaths"

        statement = "DELETE FROM " + table + " WHERE id=" + str(d_id)
        self.__execute(statement)

    def datapath_get_index(self, d_id):
        """ get datapath index """
        table = "datapaths"

        statement = "SELECT dID FROM " + table + " WHERE id=" + str(d_id)
        ret = self.__execute_dict(statement, one=True)

        return ret["dID"]

    def datapath_select(self, d_id=None):
        """ select * from datapath """
        table = "datapaths"

        statement = "SELECT * FROM " + table
        values = ()
        if d_id is not None:
            statement += " WHERE id=%s"
            values = (str(d_id),)

        return self.__execute_dict(statement, values, one=False)

    def port_insert(self, d_id, port_no, hw_addr=None, name=None,
                    config=None, state=None, curr=None, advertised=None,
                    supported=None, peer=None, sw_tdm_gran=None,
                    sw_type=None, peer_port_no=None, peer_dpath_id=None):
        """ port insert """
        table = "ports"

        stat_header = "INSERT INTO " + table + "(datapath_id, port_no"
        stat_body = "VALUES (%s, %s"
        values = (str(d_id), str(port_no))

        if hw_addr is not None:
            stat_header += ", hw_addr"
            stat_body += ", %s"
            values = values + (str(hw_addr),)

        if name is not None:
            stat_header += ", name"
            stat_body += ", %s"
            values = values + (str(name),)

        if config is not None:
            stat_header += ", config"
            stat_body += ", %s"
            values = values + (str(config),)

        if state is not None:
            stat_header += ", state"
            stat_body += ", %s"
            values = values + (str(state),)

        if curr is not None:
            stat_header += ", curr"
            stat_body += ", %s"
            values = values + (str(curr),)

        if advertised is not None:
            stat_header += ", advertised"
            stat_body += ", %s"
            values = values + (str(advertised),)

        if supported is not None:
            stat_header += ", supported"
            stat_body += ", %s"
            values = values + (str(supported),)

        if peer is not None:
            stat_header += ", peer"
            stat_body += ", %s"
            values = values + (str(peer),)

        if sw_tdm_gran is not None:
            stat_header += ", sw_tdm_gran"
            stat_body += ", %s"
            values = values + (str(sw_tdm_gran),)

        if sw_type is not None:
            stat_header += ", sw_type"
            stat_body += ", %s"
            values = values + (str(sw_type),)

        if peer_port_no is not None:
            stat_header += ", peer_port_no"
            stat_body += ", %s"
            values = values + (str(peer_port_no),)

        if peer_dpath_id is not None:
            stat_header += ", peer_dpath_id"
            stat_body += ", %s"
            values = values + (str(peer_dpath_id),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def port_delete(self, d_id, port_no):
        """ port delete """
        table = "ports"

        statement = "DELETE FROM " + table +\
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (d_id, port_no)
        self.__execute(statement, values)

    def port_select(self, d_id=None, port_no=None):
        """ port select """
        table = "ports"

        statement = "SELECT * FROM " + table
        values = ()
        if d_id is not None and port_no is not None:
            statement += " WHERE datapath_id=%s AND port_no=%s"
            values = values + (str(d_id), str(port_no),)

        elif d_id is not None:
            statement += " WHERE datapath_id=%s"
            values = values + (str(d_id),)

        elif port_no is not None:
            statement += " WHERE port_no=%s"
            values = values + (str(port_no),)

        return self.__execute_dict(statement, values, one=False)

    def port_get_index(self, d_id, port_no):
        """ get port index """
        table = "ports"

        statement = "SELECT nodeID FROM " + table +\
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (d_id, port_no)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["nodeID"]

    def port_get_curr_rate(self, d_id, port_no):
        """ get port current rate support """
        table = "ports"

        statement = "SELECT curr FROM " + table +\
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (d_id, port_no)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["curr"]

    def port_get_indexes(self, d_id):
        """ get port indexes """
        table = "ports"

        statement = "SELECT nodeID FROM " + table +\
                    " WHERE datapath_id=%s"
        values = (d_id)
        rets = self.__execute_dict(statement, values, one=False)

        return [x["nodeID"] for x in rets]

    def port_get_macs(self):
        """ get port macs """
        table = "ports"

        statement = "SELECT hw_addr FROM " + table
        rets = self.__execute_dict(statement, one=False)

        return [x["hw_addr"] for x in rets]

    def port_get_mac_addr(self, dpid, port_no):
        """ get port mac address """
        table = "ports"

        statement = "SELECT hw_addr FROM " + table + \
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (dpid, port_no)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["hw_addr"]

    def port_get_did_pno(self, node_index):
        """ port get datapath ID and port number """
        table = "ports"

        statement = "SELECT datapath_id, port_no FROM " + table +\
                    " WHERE nodeID=%s"
        values = (node_index)
        ret = self.__execute_dict(statement, values, one=True)

        return (ret["datapath_id"], ret["port_no"])

    def link_insert(self, src_dpid, src_pno, dst_dpid, dst_pno,
                    bandwidth=None):
        """ link insert """
        table = "links"

        stat_header = "INSERT INTO " + table +\
                      "(src_dpid, src_pno, dst_dpid, dst_pno"
        stat_body = "VALUES (%s, %s, %s, %s"
        values = (str(src_dpid), str(src_pno),
                  str(dst_dpid), str(dst_pno))

        if bandwidth is not None:
            stat_header += ", available_bw"
            stat_body += ", %s"
            values = values + (str(bandwidth),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def link_delete(self, src_dpid, src_pno):
        """ link delete """
        table = "links"

        statement = "DELETE FROM " + table +\
                    " WHERE src_dpid=%s AND src_pno=%s"
        values = (src_dpid, src_pno)
        self.__execute(statement, values)

    def link_select(self, src_dpid=None, src_pno=None):
        """ link select """
        table = "links"

        statement = "SELECT * FROM " + table
        values = ()
        if src_dpid is not None and src_pno is not None:
            statement += " WHERE src_dpid=%s AND src_pno=%s"
            values = values + (str(src_dpid), str(src_pno),)

        elif src_dpid is not None:
            statement += " WHERE src_dpid=%s"
            values = values + (str(src_dpid),)

        elif src_pno is not None:
            statement += " WHERE src_pno=%s"
            values = values + (str(src_pno),)

        return self.__execute_dict(statement, values, one=False)

    def link_get_indexes(self, src_dpid):
        """ get link indexes """
        table = "links"

        statement = "SELECT src_pno, dst_dpid, dst_pno FROM " + table +\
                    " WHERE src_dpid=%s"
        values = (src_dpid)
        rets = self.__execute_dict(statement, values, one=False)

        return [(x["src_pno"], x["dst_dpid"], x["dst_pno"]) for x in rets]

    def link_get_bw(self, src_dpid, src_pno, dst_dpid, dst_pno):
        """get link bandwidth """
        table = "links"

        statement = "SELECT available_bw FROM " + table +\
                    " WHERE src_dpid=%s AND src_pno=%s" +\
                    " AND dst_dpid=%s AND dst_pno=%s"
        values = (src_dpid, src_pno, dst_dpid, dst_pno)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["available_bw"]

    def link_update_bw(self, src_dpid, src_pno, dst_dpid, dst_pno, bandwidth):
        """update link bandwidth """
        table = "links"

        statement = "UPDATE " + table + " set available_bw=%s" +\
                    " WHERE src_dpid=%s AND src_pno=%s" +\
                    " AND dst_dpid=%s AND dst_pno=%s"
        values = (bandwidth, src_dpid, src_pno, dst_dpid, dst_pno)
        self.__execute(statement, values)

    def host_insert(self, mac_addr, dpid=None, in_port=None, ip_addr=None):
        """ host insert """
        table = "hosts"

        stat_header = "INSERT INTO " + table + "(mac_addr"
        stat_body = "VALUES (%s"
        values = (str(mac_addr),)

        if ip_addr is not None:
            stat_header += ", ip_addr"
            stat_body += ", %s"
            values = values + (str(ip_addr),)

        if dpid is not None:
            stat_header += ", dpid"
            stat_body += ", %s"
            values = values + (str(dpid),)

        if in_port is not None:
            stat_header += ", in_port"
            stat_body += ", %s"
            values = values + (str(in_port),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def host_delete(self, idd):
        """ host delete """
        table = "hosts"

        statement = "DELETE FROM " + table + " WHERE hostID=" + str(idd)
        self.__execute(statement)

    def host_select(self):
        """ host select """
        table = "hosts"

        statement = "SELECT * FROM " + table
        return self.__execute_dict(statement, one=False)

    def host_update(self, mac_addr, ip_addr):
        """ host update """
        table = "hosts"

        statement = "UPDATE " + table + \
                    " set ip_addr='%s'" % str(ip_addr) + \
                    " WHERE mac_addr='%s'" % str(mac_addr)
        self.__execute(statement)

    def host_get_index(self, mac_addr):
        """ get host index """
        table = "hosts"

        statement = "SELECT hostID FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["hostID"]

    def host_get_dpid(self, mac_addr):
        """ get host datapath ID """
        table = "hosts"

        statement = "SELECT dpid FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["dpid"]

    def host_get_inport(self, mac_addr):
        """ get host inport """
        table = "hosts"

        statement = "SELECT in_port FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["in_port"]

    def host_get_info(self, mac_addr):
        """ get host id, ip_addr, dpid, inport """
        table = "hosts"

        statement = "SELECT hostID, ip_addr, dpid, in_port FROM " + table +\
                    " WHERE mac_addr=%s"
        values = (mac_addr)
        ret = self.__execute_dict(statement, values, one=True)

        return (ret["hostID"], ret["ip_addr"], ret["dpid"], ret["in_port"])

    def host_get_ipaddr(self, mac_addr):
        """ get host ip address """
        table = "hosts"

        statement = "SELECT ip_addr FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["ip_addr"]

    def host_get_mac_addr(self, ip_addr):
        """ get host mac address """
        table = "hosts"

        statement = "SELECT mac_addr FROM %s WHERE ip_addr='%s'" % \
                    (str(table), str(ip_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["mac_addr"]

    def host_get_indexes(self, d_id):
        """ get host indexes """
        table = "hosts"

        statement = "SELECT in_port, ip_addr FROM " + table +\
                    " WHERE dpid=%s"
        values = (d_id)
        rets = self.__execute_dict(statement, values, one=False)

        return [(x["in_port"], x["ip_addr"]) for x in rets]

    def cport_bandwidth_insert(self, dpid, port_no, num_bandwidth,
                               bandwidth=None):
        """ cports_bandwidth insert """
        table = "cports_bandwidth"

        stat_header = "INSERT INTO " + table + "(dpid, port_no, num_bandwidth"
        stat_body = "VALUES (%s, %s, %s"
        values = (str(dpid), str(port_no), str(num_bandwidth))

        if bandwidth is not None:
            stat_header += ", bandwidth"
            stat_body += ", %s"
            values = values + (str(bandwidth),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def cport_bandwidth_delete(self, dpid, port_no, num_bandwidth):
        """ cports_bandwidth delete """
        table = "cports_bandwidth"

        statement = "DELETE FROM " + table +\
                    " WHERE dpid=%s AND port_no=%s AND num_bandwidth=%s"
        values = (dpid, port_no, num_bandwidth)
        self.__execute(statement, values)

    def flow_insert(self, dpid, table_id=None, action=None, idle_timeout=None,
                    hard_timeout=None, priority=None, cookie=None,
                    dl_type=None, dl_vlan=None, dl_vlan_pcp=None, dl_src=None,
                    dl_dst=None, nw_src=None, nw_dst=None, nw_src_n_wild=None,
                    nw_dst_n_wild=None, nw_proto=None, tp_src=None,
                    tp_dst=None, in_port=None):
        """ Flow entry insert """
        table = "flow_entries"

        stat_header = "INSERT INTO " + table + "(dpid"
        stat_body = "VALUES (%s"
        values = (str(dpid),)

        if table_id is not None:
            stat_header += ", table_id"
            stat_body += ", %s"
            values = values + (str(table_id),)

        if action is not None:
            stat_header += ", action"
            stat_body += ", %s"
            values = values + (str(action),)

        if idle_timeout is not None:
            stat_header += ", idle_timeout"
            stat_body += ", %s"
            values = values + (str(idle_timeout),)

        if hard_timeout is not None:
            stat_header += ", hard_timeout"
            stat_body += ", %s"
            values = values + (str(hard_timeout),)

        if priority is not None:
            stat_header += ", priority"
            stat_body += ", %s"
            values = values + (str(priority),)

        if cookie is not None:
            stat_header += ", cookie"
            stat_body += ", %s"
            values = values + (str(cookie),)

        if dl_type is not None:
            stat_header += ", dl_type"
            stat_body += ", %s"
            values = values + (str(dl_type),)

        if dl_vlan is not None:
            stat_header += ", dl_vlan"
            stat_body += ", %s"
            values = values + (str(dl_vlan),)

        if dl_vlan_pcp is not None:
            stat_header += ", dl_vlan_pcp"
            stat_body += ", %s"
            values = values + (str(dl_vlan_pcp),)

        if dl_src is not None:
            stat_header += ", dl_src"
            stat_body += ", %s"
            values = values + (str(dl_src),)

        if dl_dst is not None:
            stat_header += ", dl_dst"
            stat_body += ", %s"
            values = values + (str(dl_dst),)

        if nw_src is not None:
            stat_header += ", nw_src"
            stat_body += ", %s"
            values = values + (str(nw_src),)

        if nw_src_n_wild is not None:
            stat_header += ", nw_src_n_wild"
            stat_body += ", %s"
            values = values + (str(nw_src_n_wild),)

        if nw_dst is not None:
            stat_header += ", nw_dst"
            stat_body += ", %s"
            values = values + (str(nw_dst),)

        if nw_proto is not None:
            stat_header += ", nw_proto"
            stat_body += ", %s"
            values = values + (str(nw_proto),)

        if nw_dst_n_wild is not None:
            stat_header += ", nw_dst_n_wild"
            stat_body += ", %s"
            values = values + (str(nw_dst_n_wild),)

        if tp_src is not None:
            stat_header += ", tp_src"
            stat_body += ", %s"
            values = values + (str(tp_src),)

        if tp_dst is not None:
            stat_header += ", tp_dst"
            stat_body += ", %s"
            values = values + (str(tp_dst),)

        if in_port is not None:
            stat_header += ", in_port"
            stat_body += ", %s"
            values = values + (str(in_port),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def flow_delete(self, dpid):
        """ Flow entry delete """
        table = "flow_entries"

        statement = "DELETE FROM " + table + " WHERE dpid=" + str(dpid)
        self.__execute(statement)

    def flow_select(self, dpid=None):
        """ flow_entries select """
        table = "flow_entries"

        statement = "SELECT * FROM " + table
        values = ()
        if dpid is not None:
            statement += " WHERE dpid=%s"
            values = values + (str(dpid),)

        return self.__execute_dict(statement, values, one=False)

    def flow_get_index(self, dpid, table_id=None, dl_src=None, dl_dst=None,
                       nw_src=None, nw_dst=None, tp_src=None, tp_dst=None,
                       dl_vlan=None, dl_vlan_pcp=None, dl_type=None,
                       nw_proto=None, in_port=None):
        """ Get flow_entries index """
        table = "flow_entries"

        stat_header = "SELECT flow_id FROM " + table
        stat_body   = " WHERE dpid=%s"

        values = (str(dpid),)

        if table_id is not None:
            stat_body += " AND table_id=%s"
            values = values + (str(table_id),)
        else:
            stat_body += " AND table_id is NULL"

        if dl_src is not None:
            stat_body += " AND dl_src=%s"
            values = values + (str(dl_src),)
        else:
            stat_body += " AND dl_src is NULL"

        if dl_dst is not None:
            stat_body += " AND dl_dst=%s"
            values = values + (str(dl_dst),)
        else:
            stat_body += " AND dl_dst is NULL"

        if dl_type is not None:
            stat_body += " AND dl_type=%s"
            values = values + (str(dl_type),)
        else:
            stat_body += " AND dl_type is NULL"

        if dl_vlan is not None:
            stat_body += " AND dl_vlan=%s"
            values = values + (str(dl_vlan),)
        else:
            stat_body += " AND dl_vlan is NULL"

        if dl_vlan_pcp is not None:
            stat_body += " AND dl_vlan_pcp=%s"
            values = values + (str(dl_vlan_pcp),)
        else:
            stat_body += " AND dl_vlan_pcp is NULL"

        if nw_src is not None:
            stat_body += " AND nw_src=%s"
            values = values + (str(nw_src),)
        else:
            stat_body += " AND nw_src is NULL"

        if nw_dst is not None:
            stat_body += " AND nw_dst=%s"
            values = values + (str(nw_dst),)
        else:
            stat_body += " AND nw_dst is NULL"

        if nw_proto is not None:
            stat_body += " AND nw_proto=%s"
            values = values + (str(nw_proto),)
        else:
            stat_body += " AND nw_proto is NULL"

        if tp_src is not None:
            stat_body += " AND tp_src=%s"
            values = values + (str(tp_src),)
        else:
            stat_body += " AND tp_src is NULL"

        if tp_dst is not None:
            stat_body += " AND tp_dst=%s"
            values = values + (str(tp_dst),)
        else:
            stat_body += " AND tp_dst is NULL"

        if in_port is not None:
            stat_body += " AND in_port=%s"
            values = values + (str(in_port),)
        else:
            stat_body += " AND in_port is NULL"

        statement = stat_header + stat_body
        ret = self.__execute_dict(statement, values, one=True)

        return ret["flow_id"]

    def port_stats_insert(self, dpid, port_no,
                          rx_pkts=None, tx_pkts=None,
                          rx_bytes=None, tx_bytes=None,
                          rx_dropped=None, tx_dropped=None,
                          rx_errors=None, tx_errors=None,
                          rx_frame_err=None,
                          rx_over_err=None,
                          rx_crc_err=None,
                          collisions=None):
        """ port_stats insert """
        table = "port_stats"

        stat_header = "INSERT INTO " + table + "(datapath_id, port_no"
        stat_body = "VALUES (%s, %s"
        values = (str(dpid), str(port_no),)

        if rx_pkts is not None:
            stat_header += ", rx_pkts"
            stat_body += ", %s"
            values = values + (str(rx_pkts),)

        if tx_pkts is not None:
            stat_header += ", tx_pkts"
            stat_body += ", %s"
            values = values + (str(tx_pkts),)

        if rx_bytes is not None:
            stat_header += ", rx_bytes"
            stat_body += ", %s"
            values = values + (str(rx_bytes),)

        if tx_bytes is not None:
            stat_header += ", tx_bytes"
            stat_body += ", %s"
            values = values + (str(tx_bytes),)

        if rx_dropped is not None:
            stat_header += ", rx_dropped"
            stat_body += ", %s"
            values = values + (str(rx_dropped),)

        if tx_dropped is not None:
            stat_header += ", tx_dropped"
            stat_body += ", %s"
            values = values + (str(tx_dropped),)

        if rx_errors is not None:
            stat_header += ", rx_errors"
            stat_body += ", %s"
            values = values + (str(rx_errors),)

        if tx_errors is not None:
            stat_header += ", tx_errors"
            stat_body += ", %s"
            values = values + (str(tx_errors),)

        if rx_frame_err is not None:
            stat_header += ", rx_frame_err"
            stat_body += ", %s"
            values = values + (str(rx_frame_err),)

        if rx_over_err is not None:
            stat_header += ", rx_over_err"
            stat_body += ", %s"
            values = values + (str(rx_over_err),)

        if rx_crc_err is not None:
            stat_header += ", rx_crc_err"
            stat_body += ", %s"
            values = values + (str(rx_crc_err),)

        if collisions is not None:
            stat_header += ", collisions"
            stat_body += ", %s"
            values = values + (str(collisions),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def port_stats_update(self, dpid, port_no,
                          rx_pkts=None, tx_pkts=None,
                          rx_bytes=None, tx_bytes=None,
                          rx_dropped=None, tx_dropped=None,
                          rx_errors=None, tx_errors=None,
                          rx_frame_err=None,
                          rx_over_err=None,
                          rx_crc_err=None,
                          collisions=None):
        """ port_stats update """
        table = "port_stats"

        stat_header = "UPDATE " + table + " SET "
#        stat_body = "VALUES (%s, %s"
#        values = (str(dpid), str(port_no),)

        if rx_pkts is not None:
            stat_header += " rx_pkts=%s," % str(rx_pkts)

        if tx_pkts is not None:
            stat_header += " tx_pkts=%s," % str(tx_pkts)

        if rx_bytes is not None:
            stat_header += " rx_bytes=%s," % str(rx_bytes)

        if tx_bytes is not None:
            stat_header += " tx_bytes=%s," % str(tx_bytes)

        if rx_dropped is not None:
            stat_header += " rx_dropped=%s," % str(rx_dropped)

        if tx_dropped is not None:
            stat_header += " tx_dropped=%s," % str(tx_dropped)

        if rx_errors is not None:
            stat_header += " rx_errors=%s," % str(rx_errors)

        if tx_errors is not None:
            stat_header += " tx_errors=%s," % str(tx_errors)

        if rx_frame_err is not None:
            stat_header += " rx_frame_err=%s," % str(rx_frame_err)

        if rx_over_err is not None:
            stat_header += " rx_over_err=%s," % str(rx_over_err)

        if rx_crc_err is not None:
            stat_header += " rx_crc_err=%s," % str(rx_crc_err)

        if collisions is not None:
            stat_header += " collisions=%s" % str(collisions)

        statement = stat_header + " WHERE datapath_id=%s AND port_no=%s"
        values = (dpid, port_no)
        self.__execute(statement, values)

    def port_stats_delete(self, dpid, port_no):
        """ port_stats delete """
        table = "port_stats"

        statement = "DELETE FROM " + table + \
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (dpid, port_no)
        self.__execute(statement, values)

    def port_stats_select(self, dpid=None, port_no=None):
        """ select * from datapath """
        table = "port_stats"

        statement = "SELECT * FROM " + table
        values = ()

        if dpid is not None and port_no is not None:
            statement += " WHERE datapath_id=%s AND port_no=%s"
            values = values + (str(dpid), str(port_no),)

        elif dpid is not None:
            statement += " WHERE datapath_id=%s"
            values = values + (str(dpid),)

        elif port_no is not None:
            statement += " WHERE port_no=%s"
            values = values + (str(port_no),)

        return self.__execute_dict(statement, values, one=False)

    def table_stats_insert(self, dpid, table_id,
                            max_entries=None, active_count=None,
                            lookup_count=None, matched_count=None):
        """ table_stats insert """
        table = "table_stats"

        stat_header = "INSERT INTO " + table + "(datapath_id, table_id"
        stat_body = "VALUES (%s, %s"
        values = (str(dpid), str(table_id),)

        if max_entries is not None:
            stat_header += ", max_entries"
            stat_body += ", %s"
            values = values + (str(max_entries),)

        if active_count is not None:
            stat_header += ", active_count"
            stat_body += ", %s"
            values = values + (str(active_count),)

        if lookup_count is not None:
            stat_header += ", lookup_count"
            stat_body += ", %s"
            values = values + (str(lookup_count),)

        if matched_count is not None:
            stat_header += ", matched_count"
            stat_body += ", %s"
            values = values + (str(matched_count),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def table_stats_delete(self, dpid):
        """ table stats delete """
        table = "table_stats"

        statement = "DELETE FROM " + table + " WHERE datapath_id=" + str(dpid)
        self.__execute(statement)

    def table_stats_select(self, dpid=None, table_id=None):
        """ select * from datapath """
        table = "table_stats"

        statement = "SELECT * FROM " + table
        values = ()

        if dpid is not None and table_id is not None:
            statement += " WHERE datapath_id=%s AND table_id=%s"
            values = values + (str(dpid), str(table_id),)

        elif dpid is not None:
            statement += " WHERE datapath_id=%s"
            values = values + (str(dpid),)

        elif table_id is not None:
            statement += " WHERE table_id=%s"
            values = values + (str(table_id),)

        return self.__execute_dict(statement, values, one=False)

    def table_stats_update(self, dpid, table_id,
                           max_entries=None,
                           active_count=None,
                           lookup_count=None,
                           matched_count=None):
        """ table_stats update """
        table = "table_stats"

        stat_header = "UPDATE " + table + " SET "

        if max_entries is not None:
            stat_header += " max_entries=%s," % str(max_entries)

        if active_count is not None:
            stat_header += " active_count=%s," % str(active_count)

        if lookup_count is not None:
            stat_header += " lookup_count=%s," % str(lookup_count)

        if matched_count is not None:
            stat_header += " matched_count=%s" % str(matched_count)

        statement = stat_header + " WHERE datapath_id=%s AND table_id=%s"
        values = (dpid, table_id)
        self.__execute(statement, values)

    def request_insert(self, ip_src, ip_dst, port_src, port_dst, ip_proto,
                       vlan_id, bw=None, status=None, comments=None,
                       start_time=None, end_time=None):
        """ Requests entry insert """
        table = "requests"

        stat_header = "INSERT INTO " + table + "(ip_src, ip_dst, port_src," +\
                      " port_dst, ip_proto, vlan_id"
        stat_body = "VALUES (%s, %s, %s, %s, %s, %s"
        values = (str(ip_src), str(ip_dst), str(port_src),
                  str(port_dst), str(ip_proto), str(vlan_id),)

        if bw is not None:
            stat_header += ", bw"
            stat_body += ", %s"
            values = values + (str(bw),)

        if status is not None:
            stat_header += ", status"
            stat_body += ", %s"
            values = values + (str(status),)

        if comments is not None:
            stat_header += ", comments"
            stat_body += ", %s"
            values = values + (str(comments),)

        if start_time is not None and end_time is not None:
            stat_header += ", start_time, end_time"
            stat_body += ", FROM_UNIXTIME(%s), FROM_UNIXTIME(%s)"
            values = values + (str(start_time), str(end_time),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def request_get_serviceID(self, ip_src, ip_dst, port_src, port_dst,
                              ip_proto, vlan_id):
        """Get unique service ID at requests table """
        table = "requests"

        statement = "SELECT serviceID FROM " + table +\
                    " WHERE ip_src=%s AND ip_dst=%s AND port_src=%s" +\
                    " AND port_dst=%s AND ip_proto=%s AND vlan_id=%s"
        values = (ip_src, ip_dst, port_src, port_dst, ip_proto, vlan_id)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["serviceID"]

    def request_get_key(self, service_id):
        """Get key at requests table using service ID as unique parameter """
        table = "requests"

        statement = "SELECT ip_src, ip_dst, port_src, port_dst, ip_proto" +\
                    ", vlan_id FROM " + table + " WHERE serviceID=%s"
        values = (service_id)
        return self.__execute_dict(statement, values, one=True)

    def request_select(self):
        """ requests select """
        table = "requests"

        statement = "SELECT * FROM " + table
        return self.__execute_dict(statement, one=False)

    def request_delete(self, service_id):
        """ Request entry deletion """
        table = "requests"

        statement = "DELETE FROM " + table +\
                    " WHERE serviceID=" + str(service_id)
        self.__execute(statement)

    def service_insert(self, service_id, src_dpid, src_portno,
                       dst_dpid, dst_portno, bw=None):
        """ Service entry insert """
        table = "services"

        stat_header = "INSERT INTO " + table + "(serviceID, src_dpid, " +\
                      " src_portno, dst_dpid, dst_portno"
        stat_body = "VALUES (%s, %s, %s, %s, %s"
        values = (str(service_id), str(src_dpid), str(src_portno),
                  str(dst_dpid), str(dst_portno),)

        if bw is not None:
            stat_header += ", bw"
            stat_body += ", %s"
            values = values + (str(bw),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def service_select(self, service_id=None):
        """Select * from services table """
        table = "services"

        statement = "SELECT * FROM " + table
        values = ()

        if service_id is not None:
            statement += " WHERE serviceID=%s"
            values = values + (str(service_id),)

        statement += " order by sequenceID"
        return self.__execute_dict(statement, values, one=False)
