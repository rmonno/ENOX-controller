""" Flow PCE connection module """

import logging
import socket as sk
import color_log as cl

LOG = cl.ColorLog(logging.getLogger('pce_conn'))


class PCEClient:
    """ PCE client object """

    def __init__(self, pce_addr, pce_port, tcp_size=1024):
        assert(pce_addr is not None)
        assert(pce_port is not None)
        self.pce_addr = str(pce_addr)
        self.pce_port = int(pce_port)
        self.tcp_size = tcp_size
        self.messages = {'request_type': "get_resp"}
        self.csock = None

    def create(self):
        """ create a socket """
        assert(self.pce_addr is not None)
        assert(self.pce_port is not None)
        try:
            self.csock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            self.csock.setsockopt(sk.SOL_TCP, sk.TCP_NODELAY, 1)
            self.csock.settimeout(3)
            self.csock.connect((self.pce_addr, self.pce_port))
        except Exception, exe:
            LOG.error("Cannot create socket ('%s')" % str(exe))
            return

    def format_request(self, typee):
        """ format request """
        if typee == "topology":
            message = "@@@request_type:get_req|ior_key:pcera_topology###"
        elif typee == "routing":
            message = "@@@request_type:get_req|ior_key:pcera_routing###"
        else:
            message = None
        return message

    def send_msg(self, req_type):
        """ send a message """
        req = self.format_request(req_type)
        if req is None:
            LOG.error("Request type '%s' is not supported" % str(req_type))
            return req

        LOG.debug("Sending the following message: '%s'" % str(req))
        byte_sent = 0
        LOG.debug(len(req))
        while byte_sent < len(req):
            LOG.debug(byte_sent)
            sent = self.csock.send(req[byte_sent:])
            byte_sent += sent

        LOG.debug("Sent the following message (%d bytes): '%s'" % (byte_sent,
                                                                   str(req)))
        resp = self.csock.recv(self.tcp_size)
        LOG.info("Recv = " + resp)
        return resp

    def decode_requests(self, message):
        """ decode a request """
        cmds = message.strip('@').strip('#')
        LOG.debug("Commands: " + cmds)

        cmds = cmds.split('|')
        response = ""

        # Check for response type
        LOG.debug("Checking for response type...")
        check_type = self.analyze_type(cmds[0])
        if not check_type:
            LOG.error("Received an unsupported response type...")
            return None
        ior = self.extract_ior(cmds[2])
        if not ior:
            LOG.error("Received a response having unsupported format...")
            return None
        response = self.extract_ior(cmds[2])
        return response

    def analyze_type(self, typee):
        """ analyze request """
        assert(typee is not None)
        (key, _sep, value) = typee.partition(':')
        if key in self.messages.keys():
            if self.messages[key] == value:
                return True
        return False

    def extract_ior(self, cmd):
        """ extract ior """
        assert(cmd is not None)
        (key, _sep, value) = cmd.partition(':')
        if key != "ior_value":
            return None
        else:
            return value
