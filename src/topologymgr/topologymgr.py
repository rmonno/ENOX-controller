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
import logging as log
# XXX FIXME: Move connections module into proper placeholder
import connections
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

def command_exit(parms):
    """Exit from CLI"""
    check_args_count(parms, 0, 0)

    log.info("Explicit exit ...")
    sys.exit(0)

def command_show_topology(parms):
    """Show DB"""
    check_args_count(parms, 0, 0)

    # XXX FIXME: Fill with proper values
    log.debug("In show topology command...")
    pox_ip       = "localhost"
    pox_port     = 9001
    channel_2pox = connections.Client("sock-client", pox_ip, pox_port)
    log.debug("Trying to connect to POX...")
    # XXX FIXME: Send proper message
    msg = "GET_TOPOLOGY"
    send_handler(channel_2pox, msg)

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
    'exit'          : command_exit,
    'help'          : command_help,
    '?'             : command_help,

    'show-topology' : command_show_topology,
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
