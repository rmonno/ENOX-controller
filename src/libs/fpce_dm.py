""" Flow PCE module """

import logging
import sys

from omniORB import CORBA
import TOPOLOGY
import PCERA
import _GlobalIDL as GLOB

import color_log as cl
from conversion import indexfromUpperLower
from pce_conn import PCEClient

LOG = cl.ColorLog(logging.getLogger('fpce-dm'))


def convert_ipv4_to_int(n_str):
    """Convert dotted IPv4 address to integer."""
    return reduce(lambda a, b: a << 8 | b, [int(x) for x in n_str.split(".")])


def convert_ipv4_to_str(n_int):
    """Convert 32-bit integer to dotted IPv4 address."""
    return ".".join([str(n_int >> n & 0xFF) for n in [24, 16, 8, 0]])


class Node(object):
    """ Node object """

    def __init__(self, idd, typee):
        assert(idd is not None)
        assert(typee is not None)
        self.idd = idd
        self.typee = typee

    def id_get(self):
        """ get id method """
        return self.idd

    def to_orb(self):
        """ trasform ident to orb """
        node_id = int(self.idd)
        node_type = GLOB.gmplsTypes.NODETYPE_UNKNOWN
        if type(self.typee) == str:
            node_type = GLOB.gmplsTypes.NODETYPE_NETWORK

        node_orb = GLOB.gmplsTypes.nodeIdent(node_id, node_type)
        return node_orb


class NetNode(object):
    """ Net-Node object """

    def __init__(self, node_str):
        self.nid = convert_ipv4_to_int(node_str)
        self.ident = GLOB.gmplsTypes.nodeIdent(self.nid,
                                              GLOB.gmplsTypes.NODETYPE_NETWORK)

    def __str__(self):
        return str(self.ident)

    def net_params(self):
        """ get net parameters """
        states = GLOB.gmplsTypes.statesBundle(GLOB.gmplsTypes.OPERSTATE_UP,
                                            GLOB.gmplsTypes.ADMINSTATE_ENABLED)
        return GLOB.gmplsTypes.netNodeParams(False, states, 0, [], 0)


class NetLink(object):
    """ Net-Link object """
    maxBW = 1318388473

    def __init__(self, a_str, b_str):
        lnid = convert_ipv4_to_int(a_str)
        lid = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, lnid)
        rnid = convert_ipv4_to_int(b_str)
        rid = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, rnid)
        rcid = convert_ipv4_to_int("0.0.0.0")

        self.ident = GLOB.gmplsTypes.teLinkIdent(lnid, lid, rnid, rid,
                                        GLOB.gmplsTypes.LINKMODE_P2P_NUMBERED,
                                                 rcid, rcid)

    def __str__(self):
        return str(self.ident)

    def com_params(self, available_bw=None):
        """ Common parameters """
        mbw = NetLink.maxBW if not available_bw else (available_bw * 1000)
        return GLOB.gmplsTypes.teLinkComParams(10, 1, 0, chr(0),
                                               mbw, mbw, 0, [])

    def avail_bw(self, available_bw=None):
        """ available bandwidth """
        mbw = NetLink.maxBW if not available_bw else (available_bw * 1000)
        return [mbw] * 8

    def isc_gen(self, available_bw=None):
        """ ISC generic parameters """
        ipgen = GLOB.gmplsTypes.iscParamsGen(GLOB.gmplsTypes.SWITCHINGCAP_LSC,
                                           GLOB.gmplsTypes.ENCODINGTYPE_LAMBDA,
                                           self.avail_bw(available_bw))
        return [GLOB.gmplsTypes.isc(GLOB.gmplsTypes.SWITCHINGCAP_LSC, ipgen)]

    def states(self):
        """ get states """
        states = GLOB.gmplsTypes.statesBundle(GLOB.gmplsTypes.OPERSTATE_UP,
                                          GLOB.gmplsTypes.ADMINSTATE_ENABLED)
        return states


class ConnectionEP(object):
    """ Connection End-Point object """

    def __init__(self, ep_str):
        nid = convert_ipv4_to_int(ep_str)
        tid = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, nid)
        did = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, 0)
        lid = GLOB.gmplsTypes.labelId(GLOB.gmplsTypes.LABELTYPE_L32, 0)

        self.ident = GLOB.gmplsTypes.connEndPoint(nid, tid, did, lid)

    def __str__(self):
        return str(self.ident)


class CallID(object):
    """ Call Ident object """

    def __init__(self, source):
        sid = convert_ipv4_to_int(source)
        sip = GLOB.gmplsTypes.sourceId(GLOB.gmplsTypes.SOURCEIDTYPE_IPV4, sid)
        tip = GLOB.gmplsTypes.CALLIDTYPE_OPSPEC

        self.ident = GLOB.gmplsTypes.callIdent(tip, sip, sid)


class LspParams(object):
    """ LSP parameters object """

    def __init__(self, bandwidth=None):
        tlsp = GLOB.gmplsTypes.LSPTYPE_SPC
        rlsp = GLOB.gmplsTypes.LSPROLE_UNDEFINED
        sw_cap = GLOB.gmplsTypes.SWITCHINGCAP_UNKNOWN
        enc = GLOB.gmplsTypes.ENCODINGTYPE_UNKNOWN
        gpid = GLOB.gmplsTypes.GPID_UNKNOWN
        ptype = GLOB.gmplsTypes.PROTTYPE_NONE
        act = GLOB.gmplsTypes.LSPRESOURCEACTION_XCONNECT
        tinfo = GLOB.gmplsTypes.timeInfo(0, 0)
        qos = GLOB.gmplsTypes.qosParams(0, 0, 0)
        bw = 0 if not bandwidth else (bandwidth * 1000)

        self.ident = GLOB.gmplsTypes.lspParams(tlsp, rlsp, sw_cap, enc, gpid,
                                               bw, 0, 0, 0, 0, 0,
                                               ptype, act, tinfo, [], qos)


class OFSwitch(Node):
    """ OpenFlow Switch """

    def __init__(self, idd, stats):
        assert(idd   is not None)
        assert(stats is not None)
        super(OFSwitch, self).__init__(idd, typee="OFSwitch")
        self.stats = stats
        self.ports = []
        self.tables = None
        self.buffers = None
        self.actions = None
        self.caps = None


class Port(object):
    """ Port object """

    def __init__(self, number):
        assert(number is not None)
        self.number = number
        self.hw_addr = None
        self.name = None
        self.config = None
        self.state = None
        self.curr = None
        self.advertised = None
        self.supported = None
        self.peer = None

        self.links = []
        self.speed = None

    def link_add(self, link):
        """ get link add """
        assert(link is not None)
        if link.__class__.__name__ != "Link":
            LOG.error("Cannot add link...")
        else:
            self.links.append(link)


class Link(object):
    """ Link object """

    def __init__(self, idd, src_dpid, dst_dpid):
        assert(idd is not None)
        self.idd = idd
        self.src_dpid = src_dpid
        self.dst_dpid = dst_dpid
        self.ports_bind = {}

    def adjacency_add(self, from_port, dest_port):
        """ add adjancency """
        assert(from_port is not None)
        assert(dest_port is not None)

        self.ports_bind[from_port] = dest_port

    def adjacency_del(self, from_port, dest_port):
        """ delete adjacency """
        assert(from_port is not None)
        assert(dest_port is not None)

        self.ports_bind.pop(from_port)

    def __str__(self):
        ret = "Link '%s'(drc_dpid='%s', dst_dpid='%s', adj: %s)" % \
                (str(self.idd),
                 str(self.src_dpid),
                 str(self.dst_dpid),
                 str(self.ports_bind.items()))
        return ret

class Host(object):
    def __init__(self, mac_addr, ip_addr = None):
        self.mac_addr = mac_addr
        self.ip_addr  = ip_addr
        self.rem_dpid = None
        self.rem_port = None

    def __str__(self):
        ret = "Host(mac_addr='%s', ip_addr='%s', r_dpid='%s', r_port='%s')" % \
               (str(self.mac_addr), str(self.ip_addr),
                str(self.rem_dpid), str(self.rem_port))
        return ret

class FPCE(object):
    """ Flow PCE object """

    def __init__(self):
        self.nodes = {}
        self.links = {}
        self.info = None
        self.routing = None
        self.orb = CORBA.ORB_init(sys.argv, CORBA.ORB_ID)

    def ior_topology_add(self, ior):
        """ add topology ior """
        assert(ior is not None)
        LOG.debug("Update IOR with the following value: %s" % str(ior))

        obj = self.orb.string_to_object(ior)
        self.info = obj._narrow(TOPOLOGY.Info)
        if self.info is None:
            LOG.error("Object reference is not an TOPOLOGY::Info")

        LOG.debug("Created a topology-info object")

    def ior_routing_add(self, ior):
        """ add routing ior """
        assert(ior is not None)
        LOG.debug("Update IOR with the following value: %s" % str(ior))

        obj = self.orb.string_to_object(ior)
        self.routing = obj._narrow(PCERA.RoutingServices)
        if self.routing is None:
            LOG.error("Object reference is not an PCERA::ROUTINGSERVICES")

        LOG.debug("Created a pcera-routingservices object")

    def ior_del(self):
        """ delete ior """
        # FIX-ME: you should deactivate objects
        LOG.warning("Is it really needed?")

    def decode_ero_item(self, ero_item):
        """ decode ERO item """
        if ero_item._d != GLOB.gmplsTypes.EROSUBOBJTYPE_PUBLIC:
            LOG.warning("Not managed ERO-TYPE!")
            return (None, None)

        nid = convert_ipv4_to_str(ero_item.hop.node).split('.')
        dpid = indexfromUpperLower(nid[0], nid[1])
        portno = indexfromUpperLower(nid[2], nid[3])
        return (dpid, portno)

    def add_node_from_string(self, node):
        """ add node from string """
        assert(node is not None)
        LOG.info("Try to add node=%s" % node)

        try:
            net = NetNode(node)
            self.info.nodeAdd(net.ident)
            # update net-params (enabled + up)
            self.info.netNodeUpdate(net.nid, net.net_params())
            LOG.debug("Successfully added node: %s", str(net))

        except TOPOLOGY.NodeAlreadyExists, exe:
            LOG.error("NodeAlreadyExists exception: %s", str(exe))
        except TOPOLOGY.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except TOPOLOGY.InvocationNotAllowed, exe:
            LOG.error("InvocationNotAllowed exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

    def add_link_from_strings(self, node_a, node_b, available_bw=None):
        """ add link from string """
        assert(node_a is not None)
        assert(node_b is not None)
        LOG.info("Try to add link=%s -> %s, BW=%s",
                 node_a, node_b, str(available_bw))
        try:
            lnk = NetLink(node_a, node_b)
            self.info.linkAdd(lnk.ident)
            # update common link-params
            self.info.teLinkUpdateCom(lnk.ident, lnk.com_params(available_bw))
            # update available bandwidth
            self.info.teLinkUpdateGenBw(lnk.ident, lnk.avail_bw(available_bw))
            # append isc gen
            self.info.teLinkAppendIsc(lnk.ident, lnk.isc_gen(available_bw))
            # update states
            self.info.teLinkUpdateStates(lnk.ident, lnk.states())
            LOG.debug("Successfully added link: %s", str(lnk))

        except TOPOLOGY.CannotFetchNode, exe:
            LOG.error("CannotFetchNode exception: %s", str(exe))
        except TOPOLOGY.CannotFetchLink, exe:
            LOG.error("CannotFetchLink exception: %s", str(exe))
        except TOPOLOGY.LinkAlreadyExists, exe:
            LOG.error("LinkAlreadyExists exception: %s", str(exe))
        except TOPOLOGY.LinkParamsMismatch, exe:
            LOG.error("LinkParamsMismatch exception: %s", str(exe))
        except TOPOLOGY.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except TOPOLOGY.InvocationNotAllowed, exe:
            LOG.error("InvocationNotAllowed exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

    def del_node_from_string(self, node):
        """ delete node from string """
        assert(node is not None)
        LOG.info("Try to del node=%s" % node)

        try:
            net = NetNode(node)
            self.info.nodeDel(net.ident)
            LOG.debug("Successfully deleted node: %s", str(net))

        except TOPOLOGY.CannotFetchNode, exe:
            LOG.error("CannotFetchNode exception: %s", str(exe))
        except TOPOLOGY.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except TOPOLOGY.InvocationNotAllowed, exe:
            LOG.error("InvocationNotAllowed exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

    def del_link_from_strings(self, node_a, node_b):
        """ delete link from string """
        assert(node_a is not None)
        assert(node_b is not None)
        LOG.info("Try to del link=%s -> %s", node_a, node_b)

        try:
            lnk = NetLink(node_a, node_b)
            self.info.linkDel(lnk.ident)
            LOG.debug("Successfully deleted link: %s", str(lnk))

        except TOPOLOGY.CannotFetchNode, exe:
            LOG.error("CannotFetchNode exception: %s", str(exe))
        except TOPOLOGY.CannotFetchLink, exe:
            LOG.error("CannotFetchLink exception: %s", str(exe))
        except TOPOLOGY.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except TOPOLOGY.InvocationNotAllowed, exe:
            LOG.error("InvocationNotAllowed exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

    def update_link_bw_from_strings(self, node_a, node_b, bw):
        """ update link bandwidth from string """
        assert(node_a is not None)
        assert(node_b is not None)
        LOG.info("Try to update link=%s -> %s, BW=%s", node_a, node_b, bw)

        try:
            lnk = NetLink(node_a, node_b)
            # update common link-params
            self.info.teLinkUpdateCom(lnk.ident, lnk.com_params(bw))
            # update available bandwidth
            self.info.teLinkUpdateGenBw(lnk.ident, lnk.avail_bw(bw))
            LOG.debug("Successfully updated link: %s", str(lnk))

        except TOPOLOGY.CannotFetchNode, exe:
            LOG.error("CannotFetchNode exception: %s", str(exe))
        except TOPOLOGY.CannotFetchLink, exe:
            LOG.error("CannotFetchLink exception: %s", str(exe))
        except TOPOLOGY.LinkParamsMismatch, exe:
            LOG.error("LinkParamsMismatch exception: %s", str(exe))
        except TOPOLOGY.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except TOPOLOGY.InvocationNotAllowed, exe:
            LOG.error("InvocationNotAllowed exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

    def connection_route_from_hosts(self, ingr, egr):
        """ invoke connection-route to FLOW PCE """
        assert(ingr is not None)
        assert(egr  is not None)
        LOG.info("Try to connection-route %s -> %s", ingr, egr)

        call_id = CallID(ingr)
        try:
            cep_src = ConnectionEP(ingr)
            cep_dst = ConnectionEP(egr)
            lsp = LspParams()

            (wero, pero) = self.routing.connectionRoute(cep_src.ident,
                                                        cep_dst.ident,
                                                        call_id.ident,
                                                        lsp.ident,
                                                        [])
            # in any case flush the call
            self.routing.callFlush(call_id.ident)

            return (wero, pero)

        except PCERA.CannotFetchConnEndPoint, exe:
            LOG.error("CannotFetchConnEndPoint exception: %s", str(exe))
        except PCERA.ConnectionParamsMismatch, exe:
            LOG.error("ConnectionParamsMismatch exception: %s", str(exe))
        except PCERA.ConnectionEroMismatch, exe:
            LOG.error("ConnectionEroMismatch exception: %s", str(exe))
        except PCERA.ConnectionEroMismatch, exe:
            LOG.error("ConnectionEroMismatch exception: %s", str(exe))
        except PCERA.NoRoute, exe:
            LOG.error("NoRoute exception: %s", str(exe))
        except PCERA.CannotFetchCall, exe:
            LOG.error("CannotFetchCall exception: %s", str(exe))
        except PCERA.InternalProblems, exe:
            LOG.error("InternalProblems exception: %s", str(exe))
        except Exception, exe:
            LOG.error("Generic exception: %s", str(exe))

        return (None, None)

    def connection_route_from_hosts_bw(self, ingr, egr, bw):
        """ invoke connection-route to FLOW PCE with bandwidth constraint """
        assert(ingr is not None)
        assert(egr  is not None)
        assert(bw is not None)
        LOG.info("Try to connection-route %s -> %s with constraint bw=%s",
                 ingr, egr, bw)

        fault = 'ok'
        call_id = CallID(ingr)
        try:
            cep_src = ConnectionEP(ingr)
            cep_dst = ConnectionEP(egr)
            lsp = LspParams(bw)

            (wero, pero) = self.routing.connectionRoute(cep_src.ident,
                                                        cep_dst.ident,
                                                        call_id.ident,
                                                        lsp.ident,
                                                        [])
            # in any case flush the call
            self.routing.callFlush(call_id.ident)

            return (wero, pero, fault)

        except PCERA.CannotFetchConnEndPoint, exe:
            fault = self.__convert_error('CannotFetchConnEndPoint', exe)
        except PCERA.ConnectionParamsMismatch, exe:
            fault = self.__convert_error('ConnectionParamsMismatch', exe)
        except PCERA.ConnectionEroMismatch, exe:
            fault = self.__convert_error('ConnectionEroMismatch', exe)
        except PCERA.ConnectionEroMismatch, exe:
            fault = self.__convert_error('ConnectionEroMismatch', exe)
        except PCERA.NoRoute, exe:
            fault = self.__convert_error('NoRoute', exe)
        except PCERA.CannotFetchCall, exe:
            fault = self.__convert_error('CannotFetchCall', exe)
        except PCERA.InternalProblems, exe:
            fault = self.__convert_error('InternalProblems', exe)
        except Exception, exe:
            fault = self.__convert_error('Generic', exe)

        return (None, None, fault)

    def __convert_error(self, name, exe):
        LOG.error("%s exception: %s" % (name, exe.what))
        return exe.what


class FPCEManager(FPCE):
    def __init__(self, addr, port, size=1024):
        super(FPCEManager, self).__init__()
        self._ior_manager=PCEClient(pce_addr=addr,pce_port=port,tcp_size=size)
        self._ior_manager.create()
        self._ior_topo = False
        self._ior_rout = False

    def topology_enable(self):
        (self._ior_topo, ior) = self.__interface_enable('topology')
        if self._ior_topo:
            self.ior_topology_add(ior)

        return self._ior_topo

    def routing_enable(self):
        (self._ior_rout, ior) = self.__interface_enable('routing')
        if self._ior_rout:
            self.ior_routing_add(ior)

        return self._ior_rout

    def check(self, interface):
        if interface == 'topology':
            if not self._ior_topo and not self.topology_enable():
                return False

        elif interface == 'routing':
            if not self._ior_rout and not self.routing_enable():
                return False

        return True

    def disable(self, interface):
        if interface == 'topology':
            self._ior_topo = False

        elif interface == 'routing':
            self._ior_rout = False

    def __interface_enable(self, interface):
        LOG.debug("Retrieving IOR for %s requests" % interface)
        try:
            r_ = self._ior_manager.send_msg(interface)
            if r_ is None:
                return (False, None)

            LOG.debug("Received the following response: %s", str(r_))
            pr_ = self._ior_manager.decode_requests(r_)
            if not pr_:
                LOG.error("Got an error in response parsing...")
                return (False, None)

            LOG.info("Received the following IOR: '%s'", str(pr_))
            return (True, pr_)

        except Exception as err:
            LOG.error("FPCE Manager Failure: %s", str(err))
            return (False, None)
