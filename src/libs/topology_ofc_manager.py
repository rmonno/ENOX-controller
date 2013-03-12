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

    def link_insert(self, src_dpid, src_pno, dst_dpid, dst_pno):
        """ link insert """
        table = "links"

        stat_header = "INSERT INTO " + table +\
                      "(src_dpid, src_pno, dst_dpid, dst_pno"
        stat_body = "VALUES (%s, %s, %s, %s"
        values = (str(src_dpid), str(src_pno),
                  str(dst_dpid), str(dst_pno))

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

    def flow_delete(self, idd):
        """ Flow entry delete """
        table = "flow_entries"

        statement = "DELETE FROM " + table + " WHERE flow_id=" + str(idd)
        self.__execute(statement)

    def flow_get_index(self, dpid, table_id, dl_src=None, dl_dst=None,
                       nw_src=None, nw_dst=None, tp_src=None, tp_dst=None,
                       dl_vlan=None, dl_vlan_pcp=None, dl_type=None,
                       nw_proto=None, in_port=None):
        """ Get flow_entries index """
        table = "flow_entries"

       # statement = "SELECT flow_id FROM " + table +\
       #             " WHERE datapath_id=%s AND port_no=%s"

        stat_header = "SELECT flow_id FROM " + table
        stat_body   = " WHERE dpid=%s AND table_id=%s"

        values = (str(dpid),str(table_id),)

        if dl_src is not None:
            stat_body += " AND dl_src=%s"
            values = values + (str(dl_src),)

        if dl_dst is not None:
            stat_body += " AND dl_dst=%s"
            values = values + (str(dl_dst),)

        if dl_type is not None:
            stat_body += " AND dl_type=%s"
            values = values + (str(dl_type),)

        if dl_vlan is not None:
            stat_body += " AND dl_vlan=%s"
            values = values + (str(dl_vlan),)

        if dl_vlan_pcp is not None:
            stat_body += " AND dl_vlan_pcp=%s"
            values = values + (str(dl_vlan_pcp),)

        if nw_src is not None:
            stat_body += " AND nw_src=%s"
            values = values + (str(nw_src),)

        if nw_dst is not None:
            stat_body += " AND nw_dst=%s"
            values = values + (str(nw_dst),)

        if nw_proto is not None:
            stat_body += " AND nw_proto=%s"
            values = values + (str(nw_proto),)

        if tp_src is not None:
            stat_body += " AND tp_src=%s"
            values = values + (str(tp_src),)

        if tp_dst is not None:
            stat_body += " AND tp_dst=%s"
            values = values + (str(tp_dst),)

        if in_port is not None:
            stat_body += " AND in_port=%s"
            values = values + (str(in_port),)

        statement = stat_header + stat_body
        ret = self.__execute_dict(statement, values, one=True)

        return ret["flow_id"]
