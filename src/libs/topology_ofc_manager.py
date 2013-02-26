# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright XXX Fixme XXX
#
# @author: Roberto Monno

from topology_ofc_inf import *

import MySQLdb as sql


class TopologyOFCManager(TopologyOFCBase):
    """Topology OpenFlow Controller (OFC) Manager
    """

    def __init__(self, host, user, pswd, db, logger=None):
        self._host = host
        self._user = user
        self._pswd = pswd
        self._db   = db
        self._log  = logger
        self._con  = None

    # private
    def _debug(self, msg):
        if self._log:
            self._log.debug(msg)

    def __execute(self, statement, values=None):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        cursor = None
        try:
            cursor = self._con.cursor()

            if values:
                self._debug(statement % values)
                cursor.execute(statement, values)
            else:
                self._debug(statement)
                cursor.execute(statement)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def __execute_dict(self, statement, values=None, one=True):
        if not self._con:
            raise DBException("Transaction not opened yet!")

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

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    # public
    def open_transaction(self):
        if self._con:
            raise DBException("Transaction already opened!")

        try:
            self._con = sql.connect(host=self._host,
                                    user=self._user,
                                    passwd=self._pswd,
                                    db=self._db)
            self._debug("Connected to %s (%s)" % (self._host,
                                                  self._db))
        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

    def close(self):
        if self._con:
            self._con.close()
            self._debug("Closed connection to %s" % self._host)

        self._con = None

    def commit(self):
        if self._con:
            self._con.commit()
            self._debug("Committed!")
            return True

        else:
            return False

    def rollback(self):
        if self._con:
            self._con.rollback()
            self._debug("RollBacked!")
            return True

        else:
            return False

    def datapath_insert(self, d_id, d_name=None, caps=None,
                        actions=None, buffers=None, tables=None):
        table = "datapaths"

        stat_header = "INSERT INTO " + table + "(id"
        stat_body   = "VALUES (%s"
        values      = (str(d_id),)

        if d_name is not None:
            stat_header += ", name"
            stat_body   += ", %s"
            values      = values + (str(d_name),)

        if caps is not None:
            stat_header += ", ofp_capabilities"
            stat_body   += ", %s"
            values      = values + (str(caps),)

        if actions is not None:
            stat_header += ", ofp_actions"
            stat_body   += ", %s"
            values      = values + (str(actions),)

        if buffers is not None:
            stat_header += ", buffers"
            stat_body   += ", %s"
            values      = values + (str(buffers),)

        if tables is not None:
            stat_header += ", tables"
            stat_body   += ", %s"
            values      = values + (str(tables),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def datapath_delete(self, d_id):
        table = "datapaths"

        statement = "DELETE FROM " + table + " WHERE id=" + str(d_id)
        self.__execute(statement)

    def datapath_get_index(self, d_id):
        table = "datapaths"

        statement = "SELECT dID FROM " + table + " WHERE id=" + str(d_id)
        ret = self.__execute_dict(statement, one=True)

        return ret["dID"]

    def port_insert(self, d_id, port_no, hw_addr=None, name=None,
                    config=None, state=None, curr=None, advertised=None,
                    supported=None, peer=None):
        table = "ports"

        stat_header = "INSERT INTO " + table + "(datapath_id, port_no"
        stat_body   = "VALUES (%s, %s"
        values      = (str(d_id), str(port_no))

        if hw_addr is not None:
            stat_header += ", hw_addr"
            stat_body   += ", %s"
            values      = values + (str(hw_addr),)

        if name is not None:
            stat_header += ", name"
            stat_body   += ", %s"
            values      = values + (str(name),)

        if config is not None:
            stat_header += ", config"
            stat_body   += ", %s"
            values      = values + (str(config),)

        if state is not None:
            stat_header += ", state"
            stat_body   += ", %s"
            values      = values + (str(state),)

        if curr is not None:
            stat_header += ", curr"
            stat_body   += ", %s"
            values      = values + (str(curr),)

        if advertised is not None:
            stat_header += ", advertised"
            stat_body   += ", %s"
            values      = values + (str(advertised),)

        if supported is not None:
            stat_header += ", supported"
            stat_body   += ", %s"
            values      = values + (str(supported),)

        if peer is not None:
            stat_header += ", peer"
            stat_body   += ", %s"
            values      = values + (str(peer),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def port_delete(self, d_id, port_no):
        table = "ports"

        statement = "DELETE FROM " + table +\
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (d_id, port_no)
        self.__execute(statement, values)

    def port_get_index(self, d_id, port_no):
        table = "ports"

        statement = "SELECT nodeID FROM " + table +\
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (d_id, port_no)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["nodeID"]

    def port_get_indexes(self, d_id):
        table = "ports"

        statement = "SELECT nodeID FROM " + table +\
                    " WHERE datapath_id=%s"
        values = (d_id)
        rets = self.__execute_dict(statement, values, one=False)

        return [x["nodeID"] for x in rets]

    def port_get_macs(self):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT hw_addr FROM " + table
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return [x["hw_addr"] for x in cursor.fetchall()]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("No hw_addr found!")

    def port_get_mac_addr(self, dpid, port_no):
        table = "ports"

        statement = "SELECT hw_addr FROM " + table + \
                    " WHERE datapath_id=%s AND port_no=%s"
        values = (dpid, port_no)
        ret = self.__execute_dict(statement, values, one=True)

        return ret["hw_addr"]

    def port_get_did_pno(self, node_index):
        table = "ports"

        statement = "SELECT datapath_id, port_no FROM " + table +\
                    " WHERE nodeID=%s"
        values = (node_index)
        ret = self.__execute_dict(statement, values, one=True)

        return (ret["datapath_id"], ret["port_no"])

    def link_insert(self, src_dpid, src_pno, dst_dpid, dst_pno):
        table = "links"

        stat_header = "INSERT INTO " + table +\
                      "(src_dpid, src_pno, dst_dpid, dst_pno"
        stat_body   = "VALUES (%s, %s, %s, %s"
        values      = (str(src_dpid), str(src_pno),
                       str(dst_dpid), str(dst_pno))

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def link_delete(self, src_dpid, src_pno):
        table = "links"

        statement = "DELETE FROM " + table +\
                    " WHERE src_dpid=%s AND src_pno=%s"
        values = (src_dpid, src_pno)
        self.__execute(statement, values)

    def link_get_indexes(self, src_dpid):
        table = "links"

        statement = "SELECT src_pno, dst_dpid, dst_pno FROM " + table +\
                    " WHERE src_dpid=%s"
        values = (src_dpid)
        rets = self.__execute_dict(statement, values, one=False)

        return [(x["src_pno"], x["dst_dpid"], x["dst_pno"]) for x in rets]

    def host_insert(self, mac_addr, dpid=None, in_port=None, ip_addr=None):
        table = "hosts"

        stat_header = "INSERT INTO " + table + "(mac_addr"
        stat_body   = "VALUES (%s"
        values      = (str(mac_addr),)

        if ip_addr is not None:
            stat_header += ", ip_addr"
            stat_body   += ", %s"
            values      = values + (str(ip_addr),)

        if dpid is not None:
            stat_header += ", dpid"
            stat_body   += ", %s"
            values      = values + (str(dpid),)

        if in_port is not None:
            stat_header += ", in_port"
            stat_body   += ", %s"
            values      = values + (str(in_port),)

        statement = stat_header + ") " + stat_body + ")"
        self.__execute(statement, values)

    def host_delete(self, idd):
        table = "hosts"

        statement = "DELETE FROM " + table + " WHERE hostID=" + str(idd)
        self.__execute(statement)

    def host_update(self, mac_addr, ip_addr):
        table = "hosts"

        statement = "UPDATE " + table + \
                    " set ip_addr='%s'" % str(ip_addr) + \
                    " WHERE mac_addr='%s'" % str(mac_addr)
        self.__execute(statement)

    def host_get_index(self, mac_addr):
        table = "hosts"

        statement = "SELECT hostID FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["hostID"]

    def host_get_dpid(self, mac_addr):
        table = "hosts"

        statement = "SELECT dpid FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["dpid"]

    def host_get_inport(self, mac_addr):
        table = "hosts"

        statement = "SELECT in_port FROM %s WHERE mac_addr='%s'" % \
                    (str(table), str(mac_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["in_port"]

    def host_get_mac_addr(self, ip_addr):
        table = "hosts"

        statement = "SELECT mac_addr FROM %s WHERE ip_addr='%s'" % \
                    (str(table), str(ip_addr))
        ret = self.__execute_dict(statement, one=True)

        return ret["mac_addr"]

    def host_get_indexes(self, d_id):
        table = "hosts"

        statement = "SELECT in_port, ip_addr FROM " + table +\
                    " WHERE dpid=%s"
        values = (d_id)
        rets = self.__execute_dict(statement, values, one=False)

        return [(x["in_port"], x["ip_addr"]) for x in rets]
