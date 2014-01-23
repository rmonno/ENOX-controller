#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Alessandro Canessa    <a DOT canessa AT nextworks DOT it>
#             Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
#

""" Logger module """

import logging


class Logger(object):
    """ Logger object """

    def __init__(self):
        self.__logger = logging.getLogger("root")
        self.__logger.setLevel(logging.INFO)

        self.__handler = logging.StreamHandler()
        self.__handler.setLevel(logging.DEBUG)

        self.__level = None
        self.__format = None

        self.format_set("%(asctime)s - %(levelname)s: %(message)s")

    def level_set(self, level):
        """ level set """
        assert(level is not None)

        lup = level.upper()
        try:
            if lup != "VERBOSE":
                lup = "logging.%s" % lup
                lup = eval(lup)
        except Exception, exe:
            self.__logger.error("Cannot set level " + str(lup) +
                                "'" + level + "' (" + str(exe) + ")")

        try:
            self.__handler.setLevel(lup)
        except Exception, exe:
            self.__logger.error("Cannot set log handler level " + str(lup) +
                                "'" + level + "' (" + str(exe) + ")")

        try:
            self.__logger.setLevel(lup)
        except Exception, exe:
            self.__logger.error("Cannot set log level " + str(lup) +
                                "'" + level + "' " + str(exe) + ")")

        self.__level = lup

    def level_get(self):
        """ get level """
        return str(self.__level)

    def format_set(self, fmt):
        """ set formatter """
        assert(fmt is not None)

        formatter = logging.Formatter(fmt)
        self.__handler.setFormatter(formatter)
        self.__logger.addHandler(self.__handler)
        self.__format = fmt

    def format_get(self):
        """ get formatter """
        return str(self.__format)

    def debug(self, msg, *args):
        """ debug """
        self.__logger.log(logging.DEBUG, msg, *args)

    def info(self, msg, *args):
        """ info """
        self.__logger.log(logging.INFO, msg, *args)

    def warning(self, msg, *args):
        """ warning """
        self.__logger.log(logging.WARNING, msg, *args)

    def error(self, msg, *args):
        """ error """
        self.__logger.log(logging.ERROR, msg, *args)

    def critical(self, msg, *args):
        """ critical """
        self.__logger.log(logging.CRITICAL, msg, *args)


LOG = Logger()


if __name__ == '__main__':
    MY_LOG = Logger()
