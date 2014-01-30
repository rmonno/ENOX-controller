"""topology cpqd - i2cat
"""

from mininet.topo import Topo

class CpQD_i2CAT(Topo):
    def __init__( self ):
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch6 = self.addSwitch('s6')

        # Add links
        self.addLink(h1, switch2, 1, 2)
        self.addLink(h2, switch6, 1, 2)

        self.addLink(switch2, h1, 2, 1)
        self.addLink(switch2, switch1, 1, 2)
        self.addLink(switch2, switch3, 3, 2)

        self.addLink(switch3, switch2, 2, 3)
        self.addLink(switch3, switch1, 1, 3)

        self.addLink(switch1, switch2, 2, 1)
        self.addLink(switch1, switch3, 3, 1)
        self.addLink(switch1, switch4, 1, 1)

        self.addLink(switch4, switch1, 1, 1)
        self.addLink(switch4, switch6, 2, 1)

        self.addLink(switch6, switch4, 1, 2)
        self.addLink(switch6, h2, 2, 1)

topos = {'uc3': (lambda: CpQD_i2CAT())}
