"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from functools import partial
from mininet.node import RemoteController, Controller, OVSSwitch

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost1 = self.addHost( 'h1' )
        leftHost2 = self.addHost( 'h2' )
        rightHost = self.addHost( 'h3' )
        leftSwitch = self.addSwitch( 's1' )
        rightSwitch = self.addSwitch( 's2' )
        middleSwitch = self.addSwitch('s3')

        # Add links
        self.addLink( leftHost1, leftSwitch )
        self.addLink( leftHost2, leftSwitch )
        self.addLink( leftSwitch, middleSwitch )
        self.addLink( rightSwitch, middleSwitch )
        self.addLink( rightHost, rightSwitch )


c0 = RemoteController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 )
c1 = RemoteController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6644 )
cmap = { 's1': c0, 's2': c1, 's3': c1 }


class MultiSwitch( OVSSwitch ):
    "Custom Switch() subclass that connects to different controllers"
    def start( self, controllers ):
        return OVSSwitch.start( self, [ cmap[ self.name ] ] )

net = Mininet( topo=MyTopo(), controller=None, switch=MultiSwitch, build=False )
for c in [c0, c1]:
  net.addController(c)
# net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 )
net.build()
net.start()
CLI( net )
net.stop()
# topos = { 'mytopo': ( lambda: MyTopo() ) }
