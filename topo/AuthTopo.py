"""

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.



"""

from mininet.topo import Topo

class CustomTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        Host1 = self.addHost( 'h1' )
        Host2 = self.addHost( 'h2' )
        Host3 = self.addHost( 'h3' )
        Host4 = self.addHost( 'h4' )


        """
        may need to implement nat and firewall as hosts
        Nat = self.addHost( 'nat' )
        FW = self.addHost( 'fw' )
        """

        Nat = self.addSwitch( 's7' )
        FW = self.addSwitch( 's8' )

        Switch1 = self.addSwitch( 's1' )
        Switch2 = self.addSwitch( 's2' )
        Switch3 = self.addSwitch( 's3' )
        Switch4 = self.addSwitch( 's4' )
        Switch5 = self.addSwitch( 's5' )
        Switch6 = self.addSwitch( 's6' )



        # Add links
        self.addLink( Host1, Nat )
        self.addLink( Host2, Nat )


        self.addLink( Switch1, FW )
        self.addLink( Switch1, Nat )
        self.addLink( Switch4, Switch1 )


        self.addLink( FW, Switch2 )
        self.addLink( FW, Switch3 )


        self.addLink( Switch4, Switch5 )
        self.addLink( Switch4, Switch6 )
        self.addLink( Switch6, Host4 )


        self.addLink( Switch5, Host4 )
        self.addLink( Switch3, Host3 )
        self.addLink( Switch2, Host3 )


topos = { 'authhead': ( lambda: CustomTopo() ) }