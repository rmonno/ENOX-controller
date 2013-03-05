#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# roberto monno r.monno@nextworks.it

""" Nox DB Connector """

import libs as nxw_utils


class NoxDBConnector(nxw_utils.TopologyOFCManager):
    """ Nox DB Connector object """

    def __init__(self, host, user, pswd, db, logger):
        nxw_utils.TopologyOFCManager.__init__(self, host, user,
                                              pswd, db, logger)
        self.__log = logger

    def retry_switches(self):
        try:
            self.open_transaction()
            return [1, 2, 3, 4, 5]

        except DBException as exe:
            self.__log(str(exe))

        finally:
            self.close()

    def retry_hosts(self):
        try:
            self.open_transaction()
            return [1, 3, 5]

        except DBException as exe:
            self.__log(str(exe))

        finally:
            self.close()
