""" Flow PCE module """

import logging
import sys

from omniORB import CORBA
import TOPOLOGY
import PCERA
import _GlobalIDL as GLOB

import color_log as cl

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

    def com_params(self):
        """ Common parameters """
        mbw = NetLink.maxBW
        return GLOB.gmplsTypes.teLinkComParams(10, 1, 0, chr(0),
                                               mbw, mbw, 0, [])

    def avail_bw(self):
        """ available bandwidth """
        return [NetLink.maxBW] * 8

    def isc_gen(self):
        """ ISC generic parameters """
        ipgen = GLOB.gmplsTypes.iscParamsGen(GLOB.gmplsTypes.SWITCHINGCAP_LSC,
                                           GLOB.gmplsTypes.ENCODINGTYPE_LAMBDA,
                                           [NetLink.maxBW] * 8)
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

    def __init__(self):
        tlsp = GLOB.gmplsTypes.LSPTYPE_SPC
        rlsp = GLOB.gmplsTypes.LSPROLE_UNDEFINED
        sw_cap = GLOB.gmplsTypes.SWITCHINGCAP_UNKNOWN
        enc = GLOB.gmplsTypes.ENCODINGTYPE_UNKNOWN
        gpid = GLOB.gmplsTypes.GPID_UNKNOWN
        ptype = GLOB.gmplsTypes.PROTTYPE_NONE
        act = GLOB.gmplsTypes.LSPRESOURCEACTION_XCONNECT
        tinfo = GLOB.gmplsTypes.timeInfo(0, 0)
        qos = GLOB.gmplsTypes.qosParams(0, 0, 0)

        self.ident = GLOB.gmplsTypes.lspParams(tlsp, rlsp, sw_cap, enc, gpid,
                                               0, 0, 0, 0, 0, 0,
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
        return (nid[1], nid[3])

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

    def add_link_from_strings(self, node_a, node_b):
        """ add link from string """
        assert(node_a is not None)
        assert(node_b is not None)
        LOG.info("Try to add link=%s -> %s", node_a, node_b)

        try:
            lnk = NetLink(node_a, node_b)
            self.info.linkAdd(lnk.ident)
            # update common link-params
            self.info.teLinkUpdateCom(lnk.ident, lnk.com_params())
            # update available bandwidth
            self.info.teLinkUpdateGenBw(lnk.ident, lnk.avail_bw())
            # append isc gen
            self.info.teLinkAppendIsc(lnk.ident, lnk.isc_gen())
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
