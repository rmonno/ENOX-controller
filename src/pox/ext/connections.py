
import time
import socket
import threading
import struct

import logging as log
log.basicConfig(level=log.DEBUG)

class Client(object):
    def __init__(self, name, host, port, timeout = 5):
        assert(name is not None)
        assert(host is not None)
        assert(port is not None)

        log.debug("Socket client initializing '%s' (%s, %s, %s)" %
                  (name, host, port, timeout))

        self.name      = name
        self.host      = host
        self.port      = int(port)
        self.timeout   = int(timeout)
        self.socket    = None
        self.connected = False

        self.__create()

    def connected(self):
        return self.connected

    def __create(self):
        if self.socket is None:
            log.debug("Socket '%s' is not available" % self.name)

            self.connected = False
            self.socket    = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
            assert(self.socket is not None)
            self.socket.settimeout(None)
        else:
            log.debug("Socket '%s' already created" % self.name)

    def destroy(self):
        self.socket    = None
        self.connected = False

    def connect(self):
        if self.socket is None:
            self.create()

        if self.connected:
            log.debug("Socket already connected")
            return

        log.debug("Socket '%s' connecting to %s:%d" %
                  (self.name, self.host, self.port))
        self.socket.connect((self.host, self.port))
        log.debug("Socket '%s' is now connected" % self.name)
        self.connected = True

    def socket(self):
        return self.socket

class Server(threading.Thread):
    def __init__(self,
                 name,
                 address,
                 port,
                 conns,
                 handler):
        self.__name    = name
        self.__address = address
        self.__port    = int(port)
        self.__conns   = int(conns)
        self.__sock    = None
        self.__handler = handler

        assert(self.__name    is not None)
        assert(self.__address is not None)
        assert(self.__port    >= 0)
        assert(self.__conns   >= 0)

        log.debug("Socket server '%s' initializing ..." % self.__name)

        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert(self.__sock is not None)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log.debug("Socket server '%s' binding to %s:%d" % (self.__name,
                                                           self.__address,
                                                           self.__port))
        self.__sock.bind((self.__address, self.__port))

        super(Server, self).__init__()
        super(Server, self).setDaemon(True)
        super(Server, self).start()

    def address_get(self):
        return self.__address

    def port_get(self):
        return self.__port

    def socket_get(self):
        return self.__sock

    def run(self):
        while True:
            log.debug("Running body for socket server '%s'" % self.__name)
            self.__sock.listen(self.__conns)

            while True:
                log.debug("Socket server '%s' is waiting for connection" %
                          self.__name)

                (sock, addr)   = self.__sock.accept()
                client_address = addr[0]
                client_port    = int(addr[1])
                endpoint       = "%s:%d" % (client_address, client_port)
                log.debug("Socket server got connection from '%s'" %
                          endpoint)
                # XXX FIXME: Fill with proper handler name
                self.__handler.create("test", sock)
        log.debug("Socket server '%s' execution completed" % self.__name)

def msg_receive(sock):
    assert(sock is not None)
    msg  = ''
    buff = sock.recv(len(struct.pack("@I", 0)))
    if buff:
        if len(buff) == 0:
            return msg

    msg_length = int(struct.unpack("@I", buff)[0])
    log.debug("Received a message whose length is: %d" % msg_length)
    while len(msg) < msg_length:
        temp = sock.recv(msg_length - len(msg))
        msg += temp

    log.debug("Received the following message(%d bytes): %s" % (len(msg),
                                                                str(msg)))
    return msg

def message_send(sock, msg):
    assert(sock is not None)
    assert(msg  is not None)

    log.debug("Sending the following message: '%s'" % str(msg))
    buff     = struct.pack("@I", len(msg))
    log.debug("Sending message length ('%s') as message header" % buff)
    header_sent = 0
    while header_sent < len(buff):
        sent = sock.send(buff[header_sent:])
        header_sent += sent

    body_sent = 0
    while body_sent < len(msg):
        sent = sock.send(msg[body_sent:])
        body_sent += sent

    total_sent = header_sent + body_sent
    log.debug("Sent the following message (%d bytes): '%s'" % (total_sent,
                                                               str(msg)))
