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

            if d_name:
                stat_header += ", name"
                stat_body   += ", %s"
                values      = values + (str(d_name),)

            if caps:
                stat_header += ", ofp_capabilities"
                stat_body   += ", %s"
                values      = values + (str(caps),)

            if actions:
                stat_header += ", ofp_actions"
                stat_body   += ", %s"
                values      = values + (str(actions),)

            if buffers:
                stat_header += ", buffers"
                stat_body   += ", %s"
                values      = values + (str(buffers),)

            if tables:
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
