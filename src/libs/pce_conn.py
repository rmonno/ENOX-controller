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
        self.messages = {'request_type': "get_resp"}

    def create(self):
        assert(self.pce_addr is not None)
        assert(self.pce_port is not None)
        try:
            self.csock = socket(AF_INET, SOCK_STREAM)
            self.csock.setsockopt(SOL_TCP, TCP_NODELAY, 1)
            self.csock.settimeout(3)
            self.csock.connect((self.pce_addr, self.pce_port))
        except Exception, e:
            log.error("Cannot create socket ('%s')" % str(e))
            return

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

        log.debug("Sending the following message: '%s'" % str(req))
        byte_sent = 0
        log.debug(len(req))
        while byte_sent < len(req):
            log.debug(byte_sent)
            sent = self.csock.send(req[byte_sent:])
            byte_sent += sent

        log.debug("Sent the following message (%d bytes): '%s'" % (byte_sent,
                                                                   str(req)))
        resp = self.csock.recv(self.tcp_size)
        log.info("Recv = " + resp)
        return resp

    def decode_requests(self, message):
        cmds = message.strip('@').strip('#')
        log.debug("Commands: " + cmds)

        cmds = cmds.split('|')
        response = ""

        # Check for response type
        log.debug("Checking for response type...")
        check_type = self.analyze_type(cmds[0])
        if not check_type:
            log.error("Received an unsupported response type...")
            return None
        ior = self.extract_ior(cmds[2])
        if not ior:
            log.error("Received a response having unsupported format...")
            return None
        response = self.extract_ior(cmds[2])
        return response

    def analyze_type(self, typee):
        assert(typee is not None)
        check = False
        (key, sep, value) = typee.partition(':')
        if self.messages.has_key(key):
            if self.messages[key] == value:
                check = True
        return check

    def extract_ior(self, cmd):
        assert(cmd is not None)
        (key, sep, value) = cmd.partition(':')
        if key != "ior_value":
            return None
        else:
            return value
