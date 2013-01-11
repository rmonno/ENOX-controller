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
import socket
log.basicConfig(level=log.DEBUG)

class Channel(object):
    def __init__(self, source_ip = None, source_port = None):
        self.source_ip   = source_ip
        self.source_port = source_port
        self.connected   = False
        self.sock        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.setblocking(0)

    def connect(self):
        try:
            self.sock.connect((self.source_ip, self.source_port))
            self.connected = True
        except Exception, e:
            log.error("Cannot connect to POX ('%s')" % str(e))

    def send(self, msg):
        if not self.connected:
            log.error("Not connected to POX...")
        log.info("Sending the following message: '%s'" % msg)
        try:
            self.sock.send(msg)
        except Exception, e:
            log.error("Cannot send message to POX ('%s')" % str(e))

        try:
            reply = self.recv()
            return reply
        except Exception, e:
            log.error(e)

    def recv(self):
        if not self.connected:
            log.error("Not connected to POX...")
        try:
            buff = self.sock.recv(2, socket.MSG_DONTWAIT)
            return reply
        except Exception, e:
            log.error("Cannot receive response from POX ('%s')" % str(e))

    def shutdown(self):
        self.sock.shutdown(1)
        self.sock.close()

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
    pox_ip   = "localhost"
    pox_port = 7790
    channel_2pox = Channel(pox_ip, pox_port)
    log.debug("Trying to connect to POX...")
    channel_2pox.connect()
    log.info("Connected to POX")
    # XXX FIXME: Send proper message
    reply = channel_2pox.send("{\"start\":\"get_topology\"}")
    log.info("Received the following response %s" % str(reply))

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
