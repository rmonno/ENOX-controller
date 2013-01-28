import sys
import logging, logging.handlers
from socket import *
import time
log = logging.getLogger('pce_conn')

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

    def format_request(self, typee):
        if typee == "topology":
            message = "@@@request_type:get_req|ior_key:pcera_topology###"
        elif typee == "routing":
            message = "@@@request_type:get_req|ior_key:pcera_routing###"
        else:
            message = None
        return message

    def send_msg(self, req_type):
        req = self.format_request(req_type)
        if req is None:
            log.error("Request type '%s' is not supported" % str(req_type))
            return req
        bnum = self.csock.send(req)
        log.info("Sent = " + req)
        resp = self.csock.recv(self.tcp_size)
        log.info("Recv = " + resp)
        return resp
