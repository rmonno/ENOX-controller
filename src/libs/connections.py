""" Connection module """

import socket
import threading
import struct
import logging

import color_log as cl

LOG = cl.ColorLog(logging.getLogger('connections'))


class Client(object):
    """ Client object """

    def __init__(self, name, host, port, timeout=5):
        assert(name is not None)
        assert(host is not None)
        assert(port is not None)

        LOG.debug("Socket client initializing '%s' (%s, %s, %s)" %
                  (name, host, port, timeout))

        self.name = name
        self.host = host
        self.port = int(port)
        self.timeout = int(timeout)
        self.sock = None
        self.conn = False

        self.__create()

    def connected(self):
        """ connected method """
        return self.conn

    def __create(self):
        """ create method """
        if self.sock is None:
            LOG.debug("Socket '%s' is not available" % self.name)

            self.conn = False
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            assert(self.sock is not None)
            self.sock.settimeout(None)
        else:
            LOG.debug("Socket '%s' already created" % self.name)

    def destroy(self):
        """ destroy method """
        self.sock = None
        self.conn = False

    def connect(self):
        """ connect method """
        if self.sock is None:
            self.__create()

        if self.conn:
            LOG.debug("Socket already connected")
            return

        LOG.debug("Socket '%s' connecting to %s:%d" %
                  (self.name, self.host, self.port))
        self.sock.connect((self.host, self.port))
        LOG.debug("Socket '%s' is now connected" % self.name)
        self.conn = True

    def socket_get(self):
        """ get socket member """
        return self.sock


class Server(threading.Thread):
    """ Server object """

    def __init__(self, name, address, port, conns, handler):
        self.__name = name
        self.__address = address
        self.__port = int(port)
        self.__conns = int(conns)
        self.__sock = None
        self.__handler = handler

        assert(self.__name is not None)
        assert(self.__address is not None)
        assert(self.__port >= 0)
        assert(self.__conns >= 0)

        LOG.debug("Socket server '%s' initializing ..." % self.__name)

        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert(self.__sock is not None)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        LOG.debug("Socket server '%s' binding to %s:%d" % (self.__name,
                                                           self.__address,
                                                           self.__port))
        self.__sock.bind((self.__address, self.__port))

        super(Server, self).__init__()
        super(Server, self).setDaemon(True)
        super(Server, self).start()

    def address_get(self):
        """ get address member """
        return self.__address

    def port_get(self):
        """ get port member """
        return self.__port

    def socket_get(self):
        """ get socket member """
        return self.__sock

    def run(self):
        """ run thread cycle """
        while True:
            LOG.debug("Running body for socket server '%s'" % self.__name)
            self.__sock.listen(self.__conns)

            while True:
                LOG.debug("Socket server '%s' is waiting for connection" %
                          self.__name)

                (sock, addr) = self.__sock.accept()
                client_address = addr[0]
                client_port = int(addr[1])
                endpoint = "%s:%d" % (client_address, client_port)
                LOG.debug("Socket server got connection from '%s'" %
                          endpoint)
                self.__handler.create(self.__name, sock)
        LOG.debug("Socket server '%s' execution completed" % self.__name)


def msg_receive(sock):
    """ message receive """
    assert(sock is not None)
    msg = ''
    buff = sock.recv(len(struct.pack("@I", 0)))
    if buff:
        if len(buff) == 0:
            return msg

    msg_length = int(struct.unpack("@I", buff)[0])
    LOG.debug("Received a message whose length is: %d" % msg_length)
    while len(msg) < msg_length:
        temp = sock.recv(msg_length - len(msg))
        msg += temp

    LOG.debug("Received the following message(%d bytes): %s" % (len(msg),
                                                                str(msg)))
    return msg


def message_send(sock, msg):
    """ message send """
    assert(sock is not None)
    assert(msg  is not None)

    LOG.debug("Sending the following message: '%s'" % str(msg))
    buff = struct.pack("@I", len(msg))
    LOG.debug("Sending message length ('%s') as message header" % buff)
    header_sent = 0
    while header_sent < len(buff):
        sent = sock.send(buff[header_sent:])
        header_sent += sent

    body_sent = 0
    while body_sent < len(msg):
        sent = sock.send(msg[body_sent:])
        body_sent += sent

    total_sent = header_sent + body_sent
    LOG.debug("Sent the following message (%d bytes): '%s'" % (total_sent,
                                                               str(msg)))
