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
    host1 = self.addHost( 'h1' )
    host2 = self.addHost( 'h2' )
    host3 = self.addHost( 'h3' )
    host4 = self.addHost( 'h4' )
    host5 = self.addHost( 'h5' )
    edge_switch1 = self.addSwitch( 'es1' )
    edge_switch2 = self.addSwitch( 'es2' )
    core_switch1 = self.addSwitch('cs1')
    core_switch2 = self.addSwitch('cs2')
    core_switch3 = self.addSwitch('cs3')

    # Add links
    self.addLink( host1, edge_switch1 )
    self.addLink( host2, edge_switch1 )
    self.addLink( edge_switch1, core_switch1 )
    self.addLink( core_switch1, core_switch2 )
    self.addLink( core_switch2, edge_switch2 )
    self.addLink( host3, edge_switch2 )
    self.addLink( core_switch3, core_switch2 )
    self.addLink( host4, core_switch3)
    self.addLink( host5, core_switch3)

c0 = RemoteController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6644 )
c1 = RemoteController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6655 )
c2 = RemoteController( 'c2', controller=RemoteController, ip='127.0.0.1', port=6633)
cmap = { 'es1': c0, 'es2': c0, 'cs1': c1, 'cs2': c1, 'cs3': c2 }


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
