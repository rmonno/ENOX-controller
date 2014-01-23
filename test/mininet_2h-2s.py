""" Custom topology example

    Two directly connected switches plus a host for each switch:

    host1 <---> switch1       switch2 <---> host2
                    |            |
                switch3 <---> switch4

    Adding the 'topos' dict with a key/value pair to generate our newly defined
    topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h_1 = self.addHost('h1')
        h_2 = self.addHost('h2')

        s_1 = self.addSwitch('s1')
        s_2 = self.addSwitch('s2')
        s_3 = self.addSwitch('s3')
        s_4 = self.addSwitch('s4')

        # Add links
        self.addLink(h_1, s_1)
        self.addLink(s_1, s_3)
        self.addLink(s_3, s_4)
        self.addLink(s_4, s_2)
        self.addLink(s_2, h_2)

topos = {'mytopo': (lambda: MyTopo())}
