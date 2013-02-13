import logging
import sys

from omniORB import CORBA
import TOPOLOGY
import _GlobalIDL as GLOB

log = logging.getLogger('fpce-dm')

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

class OFSwitch(Node):
    def __init__(self, idd, stats):
        assert(idd   is not None)
        assert(stats is not None)
        super(Node, self).__init__(idd,
                                   typee = "OFSwitch")
        self.stats   = stats
        self.ports   = [ ]
        self.tables  = None
        self.buffers = None
        self.actions = None
        self.caps    = None

class Host(Node):
    def __init__(self, idd):
        assert(idd is not None)
        super(Node, self).__init__(idd,
                                   typee = "Host")

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
            self.append(link)

class Link(object):
    def __init__(self,
                 idd,
                 from_port = None,
                 dest_port = None):
        assert(idd is not None)
        self.idd        = idd
        if from_port:
            self.ports_bind = { from_port : dest_port}
        else:
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
        ret = "Link '%s' (Adjacencies: %s)" % (str(self.idd),
                                               str(self.ports_bind.items()))
        return ret

class FPCE(object):
    def __init__(self):
        self.nodes = { }
        self.links = { }
        self.ior   = None
        self.info  = None
        self.orb   = CORBA.ORB_init(sys.argv, CORBA.ORB_ID)

    def ior_add(self, ior):
        assert(ior is not None)
        if self.ior:
            log.debug("Updating IOR...")
        self.ior = ior
        log.debug("Update IOR with the following value: %s" % str(self.ior))

        obj       = self.orb.string_to_object(self.ior)
        self.info = obj._narrow(TOPOLOGY.Info)
        if self.info is None:
            log.error("Object reference is not an TOPOLOGY::Info")
            return
        else:
            print("HEREEEEE")

    def ior_del(self):
        if self.ior is None:
            log.error("Cannot delete IOR (no stored IOR)")
        else:
            self.ior  = None
            self.info = None


    def node_add(self, node):
        assert(node is not None)
        try:
            if self.ior is None:
                # XXX FIXME: Insert code to retrieve IOR...
                log.error("IOR has not already been received...")
                return
            self.info.nodeAdd(node.toOrb())
            log.info("Added the node with ID '%s'" % str(node.id_get()))

        except TOPOLOGY.NodeAlreadyExists, e:
            log.error("Got exception ('%s')" % str(e))
        except TOPOLOGY.InternalProblems, e:
            log.error("Got exception ('%s')" % str(e))
        except TOPOLOGY.InvocationNotAllowed, e:
            log.error("Got exception ('%s')" % str(e))
        except Exception, e:
            log.error("Got generic exception ('%s')" % str(e))

