# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
from pox.openflow.of_json import *
from datetime import datetime
from pox.lib.util import dpid_to_str
import pox.log.color
pox.log.color.launch()
import pox.log
pox.log.launch(format="[@@@bold@@@level%(name)-20s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
log = core.getLogger()
log.setLevel("DEBUG")



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  # Block IP pairs
  # src -> dst
  ip_block = {}
  # ip_block[IPAddr("10.0.0.2")] = IPAddr("10.0.0.3")
  # ip_block[IPAddr("10.0.0.3")] = IPAddr("10.0.0.2")


  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_switch (self, packet, packet_in, dpid):
    """
    Implement switch-like behavior.
    1. Implementing a "simple" learning switch.
    """

    log.debug(" => SWITCH[{2}]: Rcv {0} , packet_in: {1}".format(packet, packet_in, dpid))

    log.debug(" ==> Pkt Data:{0}".format(packet.dump()))
    p = packet
    if p.find('ipv4'):
      while p:
        if isinstance(p, basestring):
          log.debug( "[%s bytes]={%s}" % (len(p),p) )
          break
        log.debug("[%s]=%s" % (p.__class__.__name__, p))
        p = p.next

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    # log.debug(" ==> MAC: {0}->{1}".format(packet.src, packet.dst))
    self.mac_to_port[str(packet.src)] = packet_in.in_port

    # log.debug(" ==> MAC2PORT: {0}".format(self.mac_to_port))
    port_out = self.mac_to_port.get(str(packet.dst))
    if port_out:
      # Send packet out the associated port
      # self.resend_packet(packet_in, self.mac_to_port.get(str(packet.dst)))

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()

      ## Set fields to match received packet
      # Exact match
      msg.match = of.ofp_match.from_packet(packet_in)
      msg.idle_timeout = 60
      # msg.hard_timeout = 60 # for debugging purpose
      msg.buffer_id = packet_in.buffer_id
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(port=port_out))

      # log.debug(" ==> Msg: {0}".format(msg))
      # Send msg to swtich
      self.connection.send(msg)

    else:
      log.debug(" ==> Unknowd {0} -- Flood all".format(packet.dst))
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)


    log.debug("------------------------------")

  def act_like_firewall_drop (self, packet, packet_in):
    """
    Implement switch-like behavior.
    1. Implementing a "simple" learning switch.
    """

    log.debug("Installing dropping flow...")
    # Maybe the log statement should have source/destination/port?

    msg = of.ofp_flow_mod()

    ## Set fields to match received packet
    # Exact match
    msg.match = of.ofp_match.from_packet(packet_in)
    msg.idle_timeout = 30
    # msg.hard_timeout = 60 # for debugging purpose
    msg.buffer_id = packet_in.buffer_id
    msg.data = packet_in
    # No action for dropped packet
    # msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

    # Send msg to swtich
    self.connection.send(msg)

    # else:
    #   log.debug(" ==> Unknowd {0} -- Flood all".format(packet.dst))
    #   # Flood the packet out everything but the input port
    #   # This part looks familiar, right?
    #   self.resend_packet(packet_in, of.OFPP_ALL)


    log.debug("------------------------------")
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    dpid = dpid_to_str(event.dpid) # unique switch dpid
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    if self.is_ip_blocked(packet):
      # event.halt = True
      self.act_like_firewall_drop(packet, packet_in)
    else:
      self.act_like_switch(packet, packet_in, dpid)

  def is_ip_blocked(self, packet):
    """
    Handle IP packet
    2. Modify the above simple learning switch to include the logic blocking IP 
    traffic between host 2 and host 3.
    """
    ip = packet.find("ipv4")
    # log.debug("  => IP:{0}".format(ip))
    if ip is not None and Tutorial.ip_block.get(ip.srcip) == ip.dstip:
      log.debug("  ==> IP is blocked from {0} to {1}".format(ip.srcip, ip.dstip))
      return True

    return False

def show_stats(event):

  """
  Create stats on h1 incoming/outoging traffic
  3. Extend this program to count all traffic going to or leaving host 1
  """
  normal_flows    = 0
  normal_packets  = 0
  normal_bytes    = 0

  for flow in event.stats:
    # Check if ip addresses match the blocks
    normal_flows   += 1
    normal_packets += flow.packet_count
    normal_bytes   += flow.byte_count

  log.info("  ==> {4} ALL TRAFFIC [dpid={0}]: {1} bytes / {2} packets / {3} flows".format(
    dpidToStr(event.connection.dpid),
    normal_bytes, normal_packets, normal_flows,
    str(datetime.now())
    ))

def handle_flow_stats(event):
  # log.debug(" ==> stat: {0}".format(event.stats))
  # stats = flow_stats_to_list(event.stats)

  # Make stats on h1
  show_stats(event)

def handle_port_stats(event):
  # log.debug(" ==> stat: {0}".format(event.stats))
  stats = flow_stats_to_list(event.stats)

def send_stats_requests():
  """
  Send stats request to the connecting switch
  """
  for connection in core.openflow._connections.values():
    connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

  log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)

  # Register all required events
  core.openflow.addListenerByName("ConnectionUp", start_switch)
  # core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
  # core.openflow.addListenerByName("PortStatsReceived", handle_port_stats)
  #
  # # Send stats request every 5 second
  # Timer(5, send_stats_requests, recurring=True)


