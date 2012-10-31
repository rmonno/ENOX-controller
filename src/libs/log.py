#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Alessandro Canessa    <a DOT canessa AT nextworks DOT it>
#             Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
#

import logging

class Logger(object):
  def __init__(self):
    self.__logger = logging.getLogger("root")
    self.__logger.setLevel(logging.INFO)

    self.__handler = logging.StreamHandler()
    self.__handler.setLevel(logging.DEBUG)

    self.format_set("%(asctime)s - %(levelname)s: %(message)s")

  def level_set(self, level):
    assert(level is not None)

    l = level.upper()
    try :
      if l != "VERBOSE" :
        l = "logging.%s" % l
        l = eval(l)
    except Exception, e:
      self.__logger.error("Cannot set level " + str(l) +
                          "'" + level + "' (" + str(e) +")")

    try:
      self.__handler.setLevel(l)
    except Exception, e:
      self.__logger.error("Cannot set log handler level " + str(l) +
                          "'" + level + "' (" + str(e) +")")

    try:
      self.__logger.setLevel(l)
    except Exception, e:
      self.__logger.error("Cannot set log level " + str(l) +
                          "'" + level + "' " + str(e) +")")

      self.__level = l

  def level_get(self):
    return str(self.__level)

  def format_set(self, fmt):
    assert(fmt is not None)

    formatter = logging.Formatter(fmt)
    self.__handler.setFormatter(formatter)
    self.__logger.addHandler(self.__handler)
    self.__format = fmt

  def format_get(self):
    return str(self.__format)

  def debug(self, msg, *args):
    self.__logger.log(logging.DEBUG, msg, *args)

  def info(self, msg, *args):
    self.__logger.log(logging.INFO, msg, *args)

  def warning(self, msg, *args):
    self.__logger.log(logging.WARNING, msg, *args)

  def error(self, msg, *args):
    self.__logger.log(logging.ERROR, msg, *args)

  def critical(self, msg, *args):
    self.__logger.log(logging.CRITICAL, msg, *args)

log = Logger()

if __name__ == '__main__':
  l = Logger()
