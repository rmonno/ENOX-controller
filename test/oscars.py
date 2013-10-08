"""Custom topology example

Two directly connected switches plus a host for each switch:

             
   host1 --- switch1 --- switch2 --- host2
               \            /
                \          /
                 \        /
              	  switch 3       

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1')
        h2 = self.addHost( 'h2') 
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( h1, switch1, 1, 1)
        self.addLink( h2, switch2, 2, 2)
        self.addLink( switch1, switch3, 3, 1)
        self.addLink( switch1, switch2, 2, 1)
        self.addLink( switch2, switch3, 3, 2)
        
topos = { 'oscars': ( lambda: MyTopo() ) }
