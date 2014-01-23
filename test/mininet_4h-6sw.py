""" Custom topology example

    Six connected switches plus four hosts:

    Adding the 'topos' dict with a key/value pair to generate our newly defined
    topology enables one to pass in '--topo=topo_2islands' from the command line.
"""

from mininet.topo import Topo


class Topo2islands(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # hosts
        h_1 = self.addHost('h1')
        h_3 = self.addHost('h3')
        h_5 = self.addHost('h5')
        h_6 = self.addHost('h6')

        # switch
        s_1 = self.addSwitch('s1')
        s_2 = self.addSwitch('s2')
        s_3 = self.addSwitch('s3')
        s_4 = self.addSwitch('s4')
        s_5 = self.addSwitch('s5')
        s_6 = self.addSwitch('s6')

        # ports: src, dst, src_port, dst_port
        self.addPort(s_1, s_2, 2, 1)
        self.addPort(s_2, s_3, 2, 1)
        self.addPort(s_2, s_4, 3, 1)
        self.addPort(s_4, s_5, 3, 1)
        self.addPort(s_4, s_6, 2, 1)

        self.addPort(s_1, h_1, 1)
        self.addPort(s_3, h_3, 2)
        self.addPort(s_5, h_5, 2)
        self.addPort(s_6, h_6, 2)

        # links
        (ps, pd) = self.port(s_1, h_1)
        self.addLink(s_1, h_1, ps, pd)

        (ps, pd) = self.port(s_3, h_3)
        self.addLink(s_3, h_3, ps, pd)

        (ps, pd) = self.port(s_5, h_5)
        self.addLink(s_5, h_5, ps, pd)

        (ps, pd) = self.port(s_6, h_6)
        self.addLink(s_6, h_6, ps, pd)

        (ps, pd) = self.port(s_1, s_2)
        self.addLink(s_1, s_2, ps, pd)

        (ps, pd) = self.port(s_2, s_3)
        self.addLink(s_2, s_3, ps, pd)

        (ps, pd) = self.port(s_2, s_4)
        self.addLink(s_2, s_4, ps, pd)

        (ps, pd) = self.port(s_4, s_5)
        self.addLink(s_4, s_5, ps, pd)

        (ps, pd) = self.port(s_4, s_6)
        self.addLink(s_4, s_6, ps, pd)


topos = {'topo_2islands': (lambda: Topo2islands())}
