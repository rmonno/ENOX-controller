import sys
import logging, logging.handlers
from socket import *
import time

class PCE_Client:
    def __init__(self, pce_addr, pce_port, tcp_size = 1024):
        assert(pce_addr is not None)
        assert(pce_port is not None)
        self.pce_addr = str(pce_addr)
        self.pce_port = int(pce_port)
        self.tcp_size = tcp_size

    def create(self):
        assert(self.pce_addr is not None)
        assert(self.pce_port is not None)
        self.csock = socket.socket (AF_INET, SOCK_STREAM)
        self.csock.setsockopt(SOL_TCP, TCP_NODELAY, 1)
        self.csock.connect((self.pce_addr, self.pce_port))


    def format_request(self, i):
        if i == 0:
            message = "@@@request_type:get_req|ior_key:pcera_topology###"
        else:
            message = "@@@request_type:get_req|ior_key:pcera_routing###"
        return message


    def send_msg(self):
        i = 0
        while True:
            req = self.format_request(i % 2)
            logger.info("Sent = " + req)
            bnum = self.csock.send(req)
            if bnum == 0:
                break
            resp = self.csock.recv(self.tcp_size)
            log.info("Recv = " + resp)
            time.sleep(10)
            i += 1

        self.csock.close()

