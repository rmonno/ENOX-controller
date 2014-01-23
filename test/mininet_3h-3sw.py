""" Custom topology example

    Three directly connected switches plus a host for each switch:

    Adding the 'topos' dict with a key/value pair to generate our newly defined
    topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class Topo3sw3h(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # hosts
        h_1 = self.addHost('h1')
        h_2 = self.addHost('h2')
        h_3 = self.addHost('h3')

        # switch
        s_1 = self.addSwitch('s1')
        s_2 = self.addSwitch('s2')
        s_3 = self.addSwitch('s3')

        # ports
        self.addPort(s_1, s_2, 1, 4)
        self.addPort(s_1, s_3, 2, 1)
        self.addPort(s_1, h_1, 4)
        self.addPort(s_2, h_2, 1)
        self.addPort(s_3, h_3, 4)

        # links
        (ps, pd) = self.port(s_1, h_1)
        self.addLink(s_1, h_1, ps, pd)

        (ps, pd) = self.port(s_2, h_2)
        self.addLink(s_2, h_2, ps, pd)

        (ps, pd) = self.port(s_3, h_3)
        self.addLink(s_3, h_3, ps, pd)

        (ps, pd) = self.port(s_1, s_2)
        self.addLink(s_1, s_2, ps, pd)

        (ps, pd) = self.port(s_1, s_3)
        self.addLink(s_1, s_3, ps, pd)


topos = {'topo_3sw-3h': (lambda: Topo3sw3h())}
