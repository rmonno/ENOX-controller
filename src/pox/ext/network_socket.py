#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Francesco  Salvestrini <f DOT salvestrini AT nextworks DOT it>
#             Alessandro Canessa     <a DOT canessa AT nextworks DOT it>
#

import time
import socket
import threading
import struct

default_server_retry_time  = 5
default_server_listen      = 10
default_server_bind_addr   = "127.0.0.1"
default_server_bind_port   = 60000

# XXX FIXME: Change each print command with proper logging

class Client(object):
    def __init__(self, name, host, port, timeout):
        assert(name is not None)
        assert(host is not None)
        assert(port is not None)

        print("Socket client initializing '%s' (%s, %s, %s)" %
                  (name, host, port, timeout))

        self.__name      = name
        self.__host      = host
        self.__port      = int(port)
        self.__timeout   = int(timeout)
        self.___socket   = None
        self.__connected = False
        self.__socket    = None

        self.__create()

    def __socket_set(self, value):
        if self.___socket != value:
            m      = "Socket '%s' has been " % self.__name
            if value is None:
                m = m + "destroyed"
            else:
                m = m + "created"
            print(m)
        self.___socket = value

    def __socket_get(self):
        return self.___socket

    __socket = property(__socket_get, __socket_set)

    def connected(self):
        return self.__connected

    def __str__(self):
        return "(%s, %s, %d, %s)" % (self.__name,
                                     self.__host,
                                     self.__port,
                                     self.__timeout)

    def __sleep(self, timeout):
        print("Socket '%s' sleeping for %d second(s)" %
                     (self.__name, timeout))
        time.sleep(timeout)

    def __create(self):
        if self.__socket is None:
            print("Socket '%s' is not available" % self.__name)

            self.__connected = False
            self.__socket    = socket.socket(socket.AF_INET,
                                             socket.SOCK_STREAM)
            assert(self.__socket is not None)
            self.__socket.settimeout(None)
        else:
            print("Socket '%s' already created" % self.__name)

    def destroy(self):
        self.__socket    = None
        self.__connected = False

        assert(self.__socket is None)

    def connect(self):
        if self.__socket is None:
            self.__create()

        if self.__connected:
            print("Socket already connected")
            return

        print("Socket '%s' connecting to %s:%d)" %
                  (self.__name, self.__host, self.__port))
        self.__socket.connect((self.__host, self.__port))
        print("Socket '%s' is now connected" % self.__name)
        self.__connected = True

    def socket(self):
        return self.__socket

class Server(threading.Thread):
    def __init__(self,
                 name,
                 retry_time,
                 listen_backlog,
                 bind_addr,
                 bind_port,
                 handlers_factory):

        self.__name             = name
        self.__retry_time       = int(retry_time)
        self.__listen_backlog   = int(listen_backlog)
        self.__bind_addr        = bind_addr
        self.__bind_port        = int(bind_port)
        self.__handlers_factory = handlers_factory

        assert(self.__name             is not None)
        assert(self.__handlers_factory is not None)
        assert(self.__retry_time       >= 1)
        assert(self.__listen_backlog   >= 0)
        assert(self.__bind_port        >= 0)

        print("Socket server '%s' initializing ..." % self.__name)

        self.__server_sock = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        assert(self.__server_sock is not None)
        self.__server_sock.setsockopt(socket.SOL_SOCKET,
                                      socket.SO_REUSEADDR,
                                      1)
        print("Socket server '%s' binding to %s:%d" %
                  (self.__name, self.__bind_addr, self.__bind_port))
        self.__server_sock.bind((self.__bind_addr, self.__bind_port))

        super(Server, self).__init__()
        super(Server, self).setDaemon(True)
        super(Server, self).start()

    def bound_address(self):
        return self.__bind_addr

    def bound_port(self):
        return self.__bind_port

    def __del__(self):
        self.__server_sock.close()
        self.__server_sock = None

    def __str__(self):
        return "(%s)" % self.__name

    def run(self):
        handlers = []
        while True:
            print("Running body for socket server '%s'" % self.__name)

            #try:
            self.__server_sock.listen(self.__listen_backlog)

            while True:
                print("Socket server '%s' is waiting for connection" %
                          self.__name)

                (sock, addr) = self.__server_sock.accept()
                client_address = addr[0]
                client_port    = int(addr[1])
                endpoint       = "%s:%d" % (client_address, client_port)
                print("Socket server got connection from '%s'" %
                          endpoint)

                name = self.__name + "-" + endpoint
                print("Creating handler '%s'" % name)
                handlers.append(self.__handlers_factory.create(name, sock))
                print("Handler '%s' created" % name)

        print("Socket server '%s' execution completed" % self.__name)

def message_receive_LV(sock):
    assert(sock is not None)
    length = len(struct.pack("@I", 0))

    try:
        buff = sock.recv(length)
    except Exception:
        print("Error in receiving message form socket...")

    message = ''
    if len(buff) == 0:
        return message

    message_length = int(struct.unpack("@I", buff)[0])
    print("message_length   = '%d'" % message_length)

    if message_length < 0:
        raise RuntimeError("Got wrong message (length = %d" % message_length)
    if message_length == 0:
        print("Message length is 0, skipping body")
        return message

    print("Receiving V")

    while len(message) < message_length:
        chunk = sock.recv(message_length - len(message))
        print("Got a chunk (%d byte(s))" % len(chunk))
        if chunk == '':
            raise RuntimeError("Broken connection")
        message = message + chunk

    print("Message received (%d byte(s))" % len(message))
    return message

def message_send_LV(sock, message):
    print("Sending LV message '%s'" % str(message))
    totalsent = 0

    message_length = len(message)

    print("Sending header")
    tempsent = 0
    buff     = struct.pack("@I", message_length)
    while tempsent < len(buff):
        sent = sock.send(buff[tempsent:])
        print("%d byte(s) sent" % sent)
        if sent < 0:
            raise RuntimeError("Broken connection")
        tempsent = tempsent + sent
    totalsent = totalsent + tempsent

    if message_length == 0:
        print("Message length is 0, skipping body")
        return

    print("Sending body '%s'" % str(message))
    tempsent = 0
    buff     = message
    while tempsent < len(buff):
        sent = sock.send(buff[tempsent:])
        print("%d byte(s) sent" % sent)
        if sent < 0:
            raise RuntimeError("Broken connection")
        tempsent = tempsent + sent
    totalsent = totalsent + tempsent

    print("Message sent (%d byte(s))" % totalsent)

def message_receive(sock):
    assert(sock is not None)
    #print("Receiving message")
    return message_receive_LV(sock)

def message_send(sock, message):
    assert(sock    is not None)
    assert(message is not None)

    print("Sending message '%s'" % message)
    message_send_LV(sock, message)

if __name__ == '__main__':
    pass
