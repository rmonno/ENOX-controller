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
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "datapaths"
        cursor = None
        try:
            cursor = self._con.cursor()

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
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def datapath_delete(self, d_id):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "datapaths"
        cursor = None
        try:
            cursor = self._con.cursor()

            statement = "DELETE FROM " + table + " WHERE id=" + str(d_id)
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

    def datapath_get_index(self, d_id):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "datapaths"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT dID FROM " + table + " WHERE id=" + str(d_id)
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["dID"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    def port_insert(self, d_id, port_no, hw_addr=None, name=None,
                    config=None, state=None, curr=None, advertised=None,
                    supported=None, peer=None):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor()

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
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def port_delete(self, d_id, port_no):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor()

            statement = "DELETE FROM " + table +\
                        " WHERE datapath_id=%s AND port_no=%s"
            values = (d_id, port_no)
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def port_get_index(self, d_id, port_no):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT nodeID FROM " + table +\
                        " WHERE datapath_id=%s AND port_no=%s"
            values = (d_id, port_no)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["nodeID"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    def port_get_indexes(self, d_id):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT nodeID FROM " + table +\
                        " WHERE datapath_id=%s"
            values = (d_id)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                return [x["nodeID"] for x in cursor.fetchall()]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    def port_get_mac_addr(self, dpid, port_no):
        assert(dpid    is not None)
        assert(port_no is not None)
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT hw_addr FROM " + table + \
                        " WHERE datapath_id=%s AND port_no=%s"
            values = (dpid, port_no)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["hw_addr"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Mac_address not found!")

    def port_get_did_pno(self, node_index):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "ports"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT datapath_id, port_no FROM " + table +\
                        " WHERE nodeID=%s"
            values = (node_index)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                row = cursor.fetchone()
                return (row["datapath_id"], row["port_no"])

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    def link_insert(self, src_dpid, src_pno, dst_dpid, dst_pno):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "links"
        cursor = None
        try:
            cursor = self._con.cursor()

            stat_header = "INSERT INTO " + table +\
                          "(src_dpid, src_pno, dst_dpid, dst_pno"
            stat_body   = "VALUES (%s, %s, %s, %s"
            values      = (str(src_dpid), str(src_pno),
                           str(dst_dpid), str(dst_pno))

            statement = stat_header + ") " + stat_body + ")"
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def link_delete(self, src_dpid, src_pno):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "links"
        cursor = None
        try:
            cursor = self._con.cursor()

            statement = "DELETE FROM " + table +\
                        " WHERE src_dpid=%s AND src_pno=%s"
            values = (src_dpid, src_pno)
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def link_get_indexes(self, src_dpid):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "links"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT src_pno, dst_dpid, dst_pno FROM " + table +\
                        " WHERE src_dpid=%s"
            values = (src_dpid)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                return [(x["src_pno"], x["dst_dpid"], x["dst_pno"])
                        for x in cursor.fetchall()]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")

    def host_insert(self, mac_addr, dpid=None, in_port=None, ip_addr=None):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor()

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
            self._debug(statement % values)

            cursor.execute(statement, values)

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

    def host_delete(self, idd):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor()

            statement = "DELETE FROM " + table + " WHERE hostID=" + str(idd)
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

    def host_update(self, mac_addr, ip_addr):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor()

            statement = "UPDATE " + table + \
                        " set ip_addr='%s'" % str(ip_addr) + \
                        " WHERE mac_addr='%s'" % str(mac_addr)
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

    def host_get_index(self, mac_addr):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT hostID FROM %s WHERE mac_addr='%s'" % \
                         (str(table), str(mac_addr))
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["hostID"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()
        raise DBException("Index not found!")

    def host_get_dpid(self, mac_addr):
        if not self._con:
            raise DBException("Transaction not opened yet!")
        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT dpid FROM %s WHERE mac_addr='%s'" % \
                         (str(table), str(mac_addr))
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["dpid"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("DPID not found!")

    def host_get_inport(self, mac_addr):
        if not self._con:
            raise DBException("Transaction not opened yet!")
        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT in_port FROM %s WHERE mac_addr='%s'" % \
                         (str(table), str(mac_addr))
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["in_port"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()
        raise DBException("in_port not found!")

    def host_get_mac_addr(self, ip_addr):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT mac_addr FROM %s WHERE ip_addr='%s'" % \
                         (str(table), str(ip_addr))
            self._debug(statement)

            cursor.execute(statement)
            numrows = int(cursor.rowcount)
            if numrows:
                return cursor.fetchone()["mac_addr"]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("mac_address not found!")

    def host_get_indexes(self, d_id):
        if not self._con:
            raise DBException("Transaction not opened yet!")

        table = "hosts"
        cursor = None
        try:
            cursor = self._con.cursor(sql.cursors.DictCursor)

            statement = "SELECT in_port, ip_addr FROM " + table +\
                        " WHERE dpid=%s"
            values = (d_id)
            self._debug(statement % values)

            cursor.execute(statement, values)
            numrows = int(cursor.rowcount)
            if numrows:
                return [(x["in_port"], x["ip_addr"])
                        for x in cursor.fetchall()]

        except sql.Error as e:
            message = "Error %d: %s" % (e.args[0], e.args[1])
            raise DBException(message)

        except Exception as e:
            raise DBException(str(e))

        finally:
            if cursor:
                cursor.close()

        raise DBException("Index not found!")
