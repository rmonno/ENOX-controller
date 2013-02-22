import logging
import sys

from omniORB import CORBA
import TOPOLOGY
import PCERA
import _GlobalIDL as GLOB

log = logging.getLogger('fpce-dm')


def convert_ipv4_to_int(node_str):
    "Convert dotted IPv4 address to integer."
    return reduce(lambda a,b: a<<8 | b, map(int, node_str.split(".")))

def convert_ipv4_to_str(node_int):
    "Convert 32-bit integer to dotted IPv4 address."
    return ".".join(map(lambda n: str(node_int>>n & 0xFF), [24,16,8,0]))


class Node(object):
    def __init__(self, idd, typee):
        assert(idd   is not None)
        assert(typee is not None)
        self.idd   = idd
        self.typee = typee

    def id_get(self):
        return self.idd

    def toOrb(self):
        nodeId   = int(self.idd)
        nodeType = GLOB.gmplsTypes.NODETYPE_UNKNOWN
        if type(self.typee) == str:
            nodeType = GLOB.gmplsTypes.NODETYPE_NETWORK

        node_orb = GLOB.gmplsTypes.nodeIdent(nodeId,nodeType)
        return node_orb

class NetNode(object):
    def __init__(self, node_str):
        self.nid   = convert_ipv4_to_int(node_str)
        self.ident = GLOB.gmplsTypes.nodeIdent(self.nid,
                                            GLOB.gmplsTypes.NODETYPE_NETWORK)
    def __str__(self):
        return str(self.ident)

    def netParams(self):
        ss = GLOB.gmplsTypes.statesBundle(GLOB.gmplsTypes.OPERSTATE_UP,
                                          GLOB.gmplsTypes.ADMINSTATE_ENABLED)
        return GLOB.gmplsTypes.netNodeParams(False, ss, 0, [], 0)

class NetLink(object):
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

    def comParams(self):
        m = NetLink.maxBW
        return GLOB.gmplsTypes.teLinkComParams(10, 1, 0, chr(0), m, m, 0, [])

    def availBW(self):
        return [NetLink.maxBW]*8

    def iscGen(self):
        i = GLOB.gmplsTypes.iscParamsGen(GLOB.gmplsTypes.SWITCHINGCAP_LSC,
                                         GLOB.gmplsTypes.ENCODINGTYPE_LAMBDA,
                                         [NetLink.maxBW]*8)
        return [GLOB.gmplsTypes.isc(GLOB.gmplsTypes.SWITCHINGCAP_LSC, i)]

    def states(self):
        ss = GLOB.gmplsTypes.statesBundle(GLOB.gmplsTypes.OPERSTATE_UP,
                                          GLOB.gmplsTypes.ADMINSTATE_ENABLED)
        return ss

class ConnectionEP(object):
    def __init__(self, ep_str):
        nid = convert_ipv4_to_int(ep_str)
        tid = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, nid)
        did = GLOB.gmplsTypes.linkId(GLOB.gmplsTypes.LINKIDTYPE_IPV4, 0)
        lid = GLOB.gmplsTypes.labelId(GLOB.gmplsTypes.LABELTYPE_L32, 0)

        self.ident = GLOB.gmplsTypes.connEndPoint(nid, tid, did, lid)

    def __str__(self):
        return str(self.ident)

class CallID(object):
    def __init__(self, source):
        sid = convert_ipv4_to_int(source)
        s = GLOB.gmplsTypes.sourceId(GLOB.gmplsTypes.SOURCEIDTYPE_IPV4, sid)
        t = GLOB.gmplsTypes.CALLIDTYPE_OPSPEC

        self.ident = GLOB.gmplsTypes.callIdent(t, s, sid)

class LspParams(object):
    def __init__(self):
        t      = GLOB.gmplsTypes.LSPTYPE_SPC
        r      = GLOB.gmplsTypes.LSPROLE_UNDEFINED
        sw_cap = GLOB.gmplsTypes.SWITCHINGCAP_UNKNOWN
        enc    = GLOB.gmplsTypes.ENCODINGTYPE_UNKNOWN
        gpid   = GLOB.gmplsTypes.GPID_UNKNOWN
        ptype  = GLOB.gmplsTypes.PROTTYPE_NONE
        act    = GLOB.gmplsTypes.LSPRESOURCEACTION_XCONNECT
        tinfo  = GLOB.gmplsTypes.timeInfo(0 ,0)
        qos    = GLOB.gmplsTypes.qosParams(0, 0, 0)

        self.ident = GLOB.gmplsTypes.lspParams(t, r, sw_cap, enc, gpid,
                                               0, 0, 0, 0, 0, 0,
                                               ptype, act, tinfo, [], qos)

class OFSwitch(Node):
    def __init__(self, idd, stats):
        assert(idd   is not None)
        assert(stats is not None)
        super(OFSwitch, self).__init__(idd,
                                       typee = "OFSwitch")
        self.stats   = stats
        self.ports   = [ ]
        self.tables  = None
        self.buffers = None
        self.actions = None
        self.caps    = None

class Host(Node):
    def __init__(self,
                 idd,
                 mac_addr = None,
                 ip_addr  = None,
                 dpid     = None,
                 port     = None):
        assert(idd is not None)
        super(Host, self).__init__(idd,
                                   typee = "Host")
        self.mac_addr = mac_addr
        self.ip_addr  = ip_addr
        self.dpid     = dpid
        self.port     = port

    def __str__(self):
        s = "Host(id='%s', type='%s' mac='%s', ip='%s', dpid='%s', port='%s')" % \
             (str(self.idd),
              str(self.typee),
              str(self.mac_addr),
              str(self.ip_addr),
              str(self.dpid),
              str(self.port))
        return s

class Port(object):
    def __init__(self, number):
        assert(number is not None)
        self.number     = number
        self.hw_addr    = None
        self.name       = None
        self.config     = None
        self.state      = None
        self.curr       = None
        self.advertised = None
        self.supported  = None
        self.peer       = None

        self.links      = [ ]
        self.speed      = None

    def link_add(self, link):
        assert(link is not None)
        if link.__class__.__name__ != "Link":
            log.error("Cannot add link...")
        else:
            self.links.append(link)

class Link(object):
    def __init__(self,
                 idd,
                 src_dpid,
                 dst_dpid):
        assert(idd is not None)
        self.idd        = idd
        self.src_dpid   = src_dpid
        self.dst_dpid   = dst_dpid
        self.ports_bind = { }

    def adjacency_add(self, from_port, dest_port):
        assert(from_port is not None)
        assert(dest_port is not None)

        self.ports_bind[from_port] = dest_port

    def adjacency_del(self, from_port, dest_port):
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
    def __init__(self):
        self.nodes = { }
        self.links = { }
        self.info    = None
        self.routing = None
        self.orb     = CORBA.ORB_init(sys.argv, CORBA.ORB_ID)

    def ior_topology_add(self, ior):
        assert(ior is not None)
        log.debug("Update IOR with the following value: %s" % str(ior))

        obj       = self.orb.string_to_object(ior)
        self.info = obj._narrow(TOPOLOGY.Info)
        if self.info is None:
            log.error("Object reference is not an TOPOLOGY::Info")

        log.debug("Created a topology-info object")

    def ior_routing_add(self, ior):
        assert(ior is not None)
        log.debug("Update IOR with the following value: %s" % str(ior))

        obj          = self.orb.string_to_object(ior)
        self.routing = obj._narrow(PCERA.RoutingServices)
        if self.routing is None:
            log.error("Object reference is not an PCERA::ROUTINGSERVICES")

        log.debug("Created a pcera-routingservices object")

    def ior_del(self):
        # FIX-ME: you should deactivate objects
        log.warning("Is it really needed?")

    def decode_ero_item(self, ero_item):
        if ero_item._d != GLOB.gmplsTypes.EROSUBOBJTYPE_PUBLIC:
            log.warning("Not managed ERO-TYPE!")
            return (None, None)

        nid = convert_ipv4_to_str(ero_item.hop.node).split('.')
        return (nid[1], nid[3])

    def add_node_from_string(self, node):
        assert(node is not None)
        log.info("Try to add node=%s" % node)

        try:
            n = NetNode(node)
            self.info.nodeAdd(n.ident)
            # update net-params (enabled + up)
            self.info.netNodeUpdate(n.nid, n.netParams())
            log.debug("Successfully added node: %s", str(n))

        except TOPOLOGY.NodeAlreadyExists, e:
            log.error("NodeAlreadyExists exception: %s", str(e))
        except TOPOLOGY.InternalProblems, e:
            log.error("InternalProblems exception: %s", str(e))
        except TOPOLOGY.InvocationNotAllowed, e:
            log.error("InvocationNotAllowed exception: %s", str(e))
        except Exception, e:
            log.error("Generic exception: %s", str(e))

    def add_link_from_strings(self, node_a, node_b):
        assert(node_a is not None)
        assert(node_b is not None)
        log.info("Try to add link=%s -> %s", node_a, node_b)

        try:
            l = NetLink(node_a, node_b)
            self.info.linkAdd(l.ident)
            # update common link-params
            self.info.teLinkUpdateCom(l.ident, l.comParams())
            # update available bandwidth
            self.info.teLinkUpdateGenBw(l.ident, l.availBW())
            # append isc gen
            self.info.teLinkAppendIsc(l.ident, l.iscGen())
            # update states
            self.info.teLinkUpdateStates(l.ident, l.states())
            log.debug("Successfully added link: %s", str(l))

        except TOPOLOGY.CannotFetchNode, e:
            log.error("CannotFetchNode exception: %s", str(e))
        except TOPOLOGY.CannotFetchLink, e:
            log.error("CannotFetchLink exception: %s", str(e))
        except TOPOLOGY.LinkAlreadyExists, e:
            log.error("LinkAlreadyExists exception: %s", str(e))
        except TOPOLOGY.LinkParamsMismatch, e:
            log.error("LinkParamsMismatch exception: %s", str(e))
        except TOPOLOGY.InternalProblems, e:
            log.error("InternalProblems exception: %s", str(e))
        except TOPOLOGY.InvocationNotAllowed, e:
            log.error("InvocationNotAllowed exception: %s", str(e))
        except Exception, e:
            log.error("Generic exception: %s", str(e))

    def del_node_from_string(self, node):
        assert(node is not None)
        log.info("Try to del node=%s" % node)

        try:
            n = NetNode(node)
            self.info.nodeDel(n.ident)
            log.debug("Successfully deleted node: %s", str(n))

        except TOPOLOGY.CannotFetchNode, e:
            log.error("CannotFetchNode exception: %s", str(e))
        except TOPOLOGY.InternalProblems, e:
            log.error("InternalProblems exception: %s", str(e))
        except TOPOLOGY.InvocationNotAllowed, e:
            log.error("InvocationNotAllowed exception: %s", str(e))
        except Exception, e:
            log.error("Generic exception: %s", str(e))

    def del_link_from_strings(self, node_a, node_b):
        assert(node_a is not None)
        assert(node_b is not None)
        log.info("Try to del link=%s -> %s", node_a, node_b)

        try:
            l = NetLink(node_a, node_b)
            self.info.linkDel(l.ident)
            log.debug("Successfully deleted link: %s", str(l))

        except TOPOLOGY.CannotFetchNode, e:
            log.error("CannotFetchNode exception: %s", str(e))
        except TOPOLOGY.CannotFetchLink, e:
            log.error("CannotFetchLink exception: %s", str(e))
        except TOPOLOGY.InternalProblems, e:
            log.error("InternalProblems exception: %s", str(e))
        except TOPOLOGY.InvocationNotAllowed, e:
            log.error("InvocationNotAllowed exception: %s", str(e))
        except Exception, e:
            log.error("Generic exception: %s", str(e))

    def connection_route_from_hosts(self, ingr, egr):
        assert(ingr is not None)
        assert(egr  is not None)
        log.info("Try to connection-route %s -> %s", ingr, egr)

        call_id = CallID(ingr)
        try:
            cep_src = ConnectionEP(ingr)
            cep_dst = ConnectionEP(egr)
            lsp     = LspParams()

            (wEro, pEro) = self.routing.connectionRoute(cep_src.ident,
                                                        cep_dst.ident,
                                                        call_id.ident,
                                                        lsp.ident,
                                                        [])
            # in any case flush the call
            self.routing.callFlush(call_id.ident)

            return (wEro, pEro)

        except PCERA.CannotFetchConnEndPoint, e:
            log.error("CannotFetchConnEndPoint exception: %s", str(e))
        except PCERA.ConnectionParamsMismatch, e:
            log.error("ConnectionParamsMismatch exception: %s", str(e))
        except PCERA.ConnectionEroMismatch, e:
            log.error("ConnectionEroMismatch exception: %s", str(e))
        except PCERA.ConnectionEroMismatch, e:
            log.error("ConnectionEroMismatch exception: %s", str(e))
        except PCERA.NoRoute, e:
            log.error("NoRoute exception: %s", str(e))
        except PCERA.CannotFetchCall, e:
            log.error("CannotFetchCall exception: %s", str(e))
        except PCERA.InternalProblems, e:
            log.error("InternalProblems exception: %s", str(e))
        except Exception, e:
            log.error("Generic exception: %s", str(e))

        return (None, None)
