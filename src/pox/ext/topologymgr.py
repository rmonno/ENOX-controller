#!/usr/bin/env python
# -*- python -*-

#
# topologymgr
#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Alessandro Canessa    <a DOT canessa AT nextworks DOT it>
#

name_module = "topologymgr"

import sys
import os
import getopt
import inspect
import shlex
import connections
import logging as log
log.basicConfig(level=log.DEBUG)

class BaseError(Exception):
    def __init__(self, m = None):
        self.message = m

    def __str__(self):
        return self.message

class CommandError(BaseError):
    def __init__(self, message):
        super(CommandError, self).__init__(message)

class WrongParametersCount(CommandError):
    def __init__(self, message):
        super(WrongParametersCount, self).__init__(message)

class WrongParameterType(CommandError):
    def __init__(self, message):
        super(WrongParameterType, self).__init__(message)

class UnknownMessage(BaseError):
    def __init__(self, message):
        super(UnknownMessage, self).__init__(message)

class Controller(object):
    def __init__(self, address, port):
        assert(address is not None)
        assert(port    is not None)
        self.__address = address
        self.__port    = port
        self.default   = False

    def address_get(self):
        return self.__address

    def address_set(self, address):
        assert(address is not None)
        self.__address = address
        self.default   = True

    def port_get(self):
        return self.__port

    def port_set(self, port):
        assert(port is not None)
        self.__port  = port
        self.default = True

    def __str__(self):
        ret = "%s:%d" % (str(self.__address), int(self.__port))
        return ret

def check_args_count(args, min_count, max_count):
    assert(args is not None)
    assert(min_count is not None)
    assert(max_count is None or min_count <= max_count)

    if len(args) < min_count:
        tmp = "Too few arguments for command, minimum " \
            "%d arguments required" % min_count
        raise WrongParametersCount(tmp)

    if max_count is not None:
        if len(args) > max_count:
            tmp = "Too many arguments for command, " \
                " maximum %d allowed" % max_count
            raise WrongParametersCount(tmp)

def send_handler(client, msg):
    assert(client is not None)
    assert(msg    is not None)

    try:
        client.connect()
        if client.connected:
            log.debug("Client connected...")
    except Exception, e:
        log.error("Cannot connect to POX ('%s')" % str(e))

    try:
        connections.message_send(client.socket, msg)
    except Exception, e:
        log.error("Cannot send the message ('%s')" % str(e))

    try:
        return connections.msg_receive(client.socket)
    except Exception, e:
        log.error("Cannot receive message from controller ('%s')" % str(e))

def command_exit(parms):
    """Exit from CLI"""
    check_args_count(parms, 0, 0)

    log.info("Explicit exit ...")
    sys.exit(0)

def command_set_controller(parms):
    """Set controller params"""
    check_args_count(parms, 2, 2)
    global controller

    address    = str(parms[0])
    port       = int(parms[1])
    controller = Controller(address, port)
    log.debug("Set controller with the following params: %s" % str(controller))

def command_show_info(parms):
    """Get generic information from controller (debugging purposes)"""
    check_args_count(parms, 0, 0)
    if not controller.default:
        log.debug("Controller is not configured yet. The following params " + \
                  "will be used: %s" % str(controller))
    channel_2pox = connections.Client("sock-client",
                                       controller.address_get(),
                                       controller.port_get())
    log.debug("Trying to connect to controller %s:%d" % \
              (str(controller.address_get()), int(controller.port_get())))

    # XXX FIXME: Send proper message
    msg = "GET_INFO"
    response = send_handler(channel_2pox, msg)
    log.debug("Received the following response: %s" % str(response))

def command_show_topology(parms):
    """Get topology information from controller"""
    check_args_count(parms, 0, 0)

    # XXX FIXME: Fill with proper values
    if not controller.default:
        log.debug("Controller is not configured yet. The following params " + \
                  "will be used: %s" % str(controller))

    channel_2pox = connections.Client("sock-client",
                                       controller.address_get(),
                                       controller.port_get())
    log.debug("Trying to connect to controller %s:%d" % \
              (str(controller.address_get()), int(controller.port_get())))

    # XXX FIXME: Send proper message
    msg = "GET_TOPOLOGY"
    response = send_handler(channel_2pox, msg)
    log.debug("Received the following response: %s" % str(response))

def command_help(parms):
    """Print this help"""
    check_args_count(parms, 0, 0)

    commands = command_handlers.keys()
    commands.sort()

    maxl = 0
    for k in commands:
        maxl = max(maxl, len(k))

    for k in commands:
        h = inspect.getdoc(command_handlers[k])
        if h is None:
            h = ""
        log.info(("  %-" + str(maxl) + "s    %s") % (k, h))

command_handlers = {
    'exit'           : command_exit,
    'help'           : command_help,
    '?'              : command_help,

    'set-controller' : command_set_controller,
    'show-topology'  : command_show_topology,
    'show-info'      : command_show_info,
}

def dump_help():
    log.info(me + " [OPTIONS]")
    log.info("")
    log.info("Options:")
    log.info("    -d, --debug      set log level to debug")
    log.info("    -h, --help       print this help, then exit")
    log.info("        --version    print version, then exit")
    log.info("")

def version():
    log.info("VERSION:")

def dump_version():
    log.info(me + " (" + version() + ")")

variables = { }

configuration = [ ]
default_controller_address = "localhost"
default_controller_port    = 9001
controller                 = Controller(default_controller_address,
                                        default_controller_port)
try:
    optlist, args = getopt.getopt(sys.argv[1:],
                                  'c:hVd',
                                   [ "config",
                                   "help",
                                   "version",
                                   "debug"])

    for opt, arg in optlist:
        if opt in ("-h", "--help"):
            dump_help()
        elif opt in ("-V", "--version"):
            dump_version()
        elif opt in ("-d", "--debug"):
            log.debug("Debug mode...")
        elif opt in ("-c", "--config"):
            try:
                f = file(arg, 'U')
                configuration = f.readlines()
                f.close()
            except:
                log.debug("Cannot open file '%s'" % arg)
                sys.exit(1)

except getopt.GetoptError, err:
    dump_help()
except Exception, e:
    message = "Got unhandled exception "
    if (e is not None) :
        message = message + "(" + str(e) + ")"
    log.error(message)

log.debug(version())
try:
    log.debug("Running....")
except KeyboardInterrupt, e:
    raise e

while True:
    try:
        log.info("Accepting new line")
        if len(configuration) == 0:
            prompt = name_module + "> "
            line = raw_input(prompt)
        else:
            line = configuration.pop(0)
    except EOFError, e:
        log.debug("")
        continue
    line = line.strip()
    if len(line) == 0:
        continue

    tokens    = shlex.split(line)
    command   = tokens[0]
    arguments = tokens[1:]

    if command[0] == '#':
        continue

    log.debug("Command   = '%s'" % command)
    log.debug("Arguments = '%s'" % str(arguments))

    handler = None

    if not command in command_handlers.keys():
        log.error("Unknown command '%s'" % command)
        continue

    handler = command_handlers[command]
    assert(handler is not None)
    log.debug("Handler for command '%s' is '%s'" % (command, handler))

    try:
        log.debug("Gonna call handler '%s'" % str(handler))
        handler(arguments)
        log.debug("Handler '%s' has been called" % str(handler))
    except Exception, e:
        log.error("%s" % str(e))
        continue
