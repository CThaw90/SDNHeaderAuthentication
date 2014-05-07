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
# Modified by: 	Justin Satterfield jsatterf@andrew.cmu.edu
#               Christopher  Thaw  cthaw@andrew.cmu.edu
# Date:	  	April  25, 2014
#
# References:
#		OpenFlow Tutorial http://archive.openflow.org/wk/index.php/OpenFlow_Tutorial
#		POX Wiki https://openflow.stanford.edu/display/ONL/POX+Wiki
#       PyCrypto Toolkit  https://www.dlitz.net/software/pycrypto/




from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import time
import os
import struct
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from os import listdir


log = core.getLogger()



class Controller (object):




  def __init__ (self, connection, keydir=None):

    self.connection = connection
    # The host dictionary associates the ip address with the host id, for
    #identification in the controller validation
    self.hosts= {"10.0.0.1":"h1","10.0.0.2":"h2","10.0.0.3":"h3","10.0.0.4":"h4"}

    # The secure path list contains a secure route between all of the hosts in the
    #system to demonstrate the ability to only traverse secure paths when the
    #Authentication Header is present
    self.secure_path = [["h1","h4","s7","s1","s4","s5"],
["h2","h3","s7","s1","s8","s2"],["h4","h1","s6","s4","s1","s7"],["h1","h3","s7","s1","s8","s3"],
["h3","h2","s2","s8","s1","s7"],["h3","h1","s7","s1","s8","s3"],["h3","h4","s2","s8","s1","s4","s5"],
["h2","h4","s7","s1","s4","s6"],["h4","h3","s6","s4","s1","s8","s3"],["h4","h2","s6","s4","s1","s7"]]

    # This binds our PacketIn event listener
    connection.addListeners(self)


    # Priority variable used to set the priority of the secure route rules
    # to successively higher values when new rules are installed
    self.priority=20
    self.verified=False
    self.key_directory = keydir


    self.digest = self.importDigest("Message")

    self.private_key = None
    self.public_key = None
    self.host_keys = {}

    if not self.key_directory == None:
		self.load_host_keys()

    self.load_controller_keys()

    default_rule = of.ofp_flow_mod()
    default_rule.priority = 1
    default_rule.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(default_rule)


  def resend_packet (self, packet_in, out_port):

    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)




  def act_like_switch (self, packet, packet_in):
    #data retrieved from packet to be used in protocol to create flow rules
    data=packet.raw[54:]

    ip=packet.find('ipv4')
    tcp=packet.find('tcp')
    index=0

    flood=True

    # Check to seee if packet is ip packet and retrieve source and destination
    #if so
    if ip is not None:

        src_id=""
        dst_id=""
        for key in self.hosts:

              if str(ip.srcip)==key:
    			src_id=self.hosts[key]

              if str(ip.dstip)==key:
    			dst_id=self.hosts[key]

        if src_id!="" and dst_id!="":
    		  index=-1



        public_key=self.find_host_key(["host"+src_id[1]])
        if self.priority==2000:
    	   self.priority=20

        # If header is present and the encrypted value has been verified than
        #protocol is carried out
        if data[:2]==b"\x39\xE1" and data[4:5]==b"\x10" and self.verified==True:

            # Retrieve length of value from Authentication Header
            length= struct.unpack('>H',data[2:4])

            value=0
            enc_value=0
            enc_str=0
            hash_array=[]
            value=0

            # Determine the secure path that this IP packet must traverse
            for i in range(0,len(self.secure_path)):
                if self.secure_path[i][0]==src_id and self.secure_path[i][1]==dst_id:

                    index=i

            if index !=-1:
                #Use data value as a part of generated hashes

                value=data[5:5+length[0]]
                rand_val =src_id+dst_id

                enc_str=str(rand_val)+str(value)
                enc_val=self.importDigest(enc_str)
                con_enc = PKCS1_v1_5.new(self.private_key)

                enc_val=con_enc.sign(enc_val)

                digest = SHA256.new()

                # Create hashes for each switch along the secure route from the
                #encrypted value above
                for i in range(0,(len(self.secure_path[index])-2)):

               	    data = b64encode(str(enc_val))
                    digest.update(b64decode(data))
                    enc_val=digest.hexdigest()
                    hash_array.append(EthAddr(self.createMAC(enc_val)))

                sw="s"+dpid_to_str(self.connection.dpid)[16:17]
                #print sw
                try:

                        i=self.secure_path[index].index(sw)

                except ValueError:
                        i=-1

                # If the current switch is a member of the route than
                #protocol executes
                if i==-1:

                 drop_rule = of.ofp_flow_mod()
                 drop_rule.priority =20
                 drop_rule.hard_timeout=of.OFP_FLOW_PERMANENT
                 drop_rule.idle_timeout=of.OFP_FLOW_PERMANENT
                 #print "Dropped"
                 drop_rule.match.tp_dst=tcp.dstport
                 drop_rule.match.nw_dst=ip.dstip
                 drop_rule.match.nw_src=ip.srcip
                 drop_rule.match.dl_type=0x0800
                 drop_rule.match.nw_proto=6
                 drop_rule.actions=[]
                 self.connection.send(drop_rule)
                 flood=False

                else:

                    sw = self.secure_path[index][i]
                    sw = "00-00-00-00-00-0"+sw[1]

                    if dpid_to_str(self.connection.dpid)==sw:


                            rule = of.ofp_flow_mod()
                            rule.priority =20
                            rule.hard_timeout=0
                            rule.idle_timeout=0


                            # If the switch is the first switch in the route
                            # then the expected MAC address should be from that
                            # of the host otherwise the expected MAC is the next
                            # value in the reversed hash chain sequence
                            if i == 2:

                                rule.match.tp_dst=tcp.dstport
                                rule.match.nw_dst=ip.dstip
                                rule.match.nw_src=ip.srcip
                                rule.match.dl_type=0x0800
                                rule.match.dl_src=packet.src
                                rule.match.in_port=packet_in.in_port

                            else:
                                rule.match.tp_dst=tcp.dstport
                                rule.match.nw_dst=ip.dstip
                                rule.match.nw_src=ip.srcip
                                rule.match.dl_type=0x0800
                                rule.match.dl_src=hash_array[len(self.secure_path[index])-i]



                            rule.actions.append(of.ofp_action_dl_addr.set_src(hash_array[len(self.secure_path[index])-1-i]))
                            rule.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                            self.connection.send(rule)
                            #print "Path rule added"


                self.priority+=10

            enc_value=0
            enc_str=0
            hash_array=[]
            value=0



    if flood==True:
      self.resend_packet(packet_in, of.OFPP_ALL)

    self.verified=False


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.

    # Check to see if packet is IP packet and retrieve signed values
    if packet.type == pkt.ethernet.IP_TYPE:
        ipv4_packet = event.parsed.find("ipv4")
        ciphertext = ipv4_packet.raw[5:].split('%', 1)
        parsed_data = None
        public_key=None

        if len(ciphertext) == 2:
            try:
                ciphertext = eval(ciphertext[1])
                plaintext = self.private_key.decrypt(ciphertext)
                parsed_data = self.parse_pkt_data(plaintext)
                self.digest = self.importDigest(parsed_data[0])
                public_key = self.find_host_key(parsed_data)


            except:
                self.verified=False

        if not type(public_key) == type(None) and self.verify_signature(public_key, parsed_data[1]):
            #print ("Machine {0} verified!".format(parsed_data[0]))
            self.verified =True


    packet_in = event.ofp
    self.act_like_switch(packet, packet_in)


  #Parse the plaintext of the message
  def parse_pkt_data(self, raw_data):

	delim = str("%")
	parsed_data = raw_data.split(delim, 2)
	return parsed_data

  #Function to figure out which key to use in decryption
  def find_host_key(self, parsed_data=[]):
    if len(parsed_data) != 2:
		return None
    return (self.host_keys[parsed_data[0]] if self.host_keys.__contains__(parsed_data[0]) else None)

  #Function constructs the MAC address for use in the flow rule creation
  def createMAC(self,str_arg):
    eth_str=str_arg[0:1]+":"+str_arg[1:2]+":"+str_arg[2:3]+":"+str_arg[3:4]+":"+str_arg[4:5]+":"+str_arg[5:6]

    return str(eth_str)

  #Creates a message digest from the provided message
  def importDigest(self,message):

	digest = SHA256.new()
	data = b64encode(message)
	digest.update(b64decode(data))
	return digest

  #Loads in all key values for each host in the topology
  def load_host_keys(self):
	file_list = listdir(self.key_directory)
	for filename in file_list:
		parseFilename = filename.rsplit("_", 1)
		if len(parseFilename) == 2 and len(parseFilename[1].split(".")) == 2:
			if parseFilename[1].split(".")[0] == str("pub"):
				current_key = open(self.key_directory + '/' + filename, 'r').read()
				self.host_keys[parseFilename[0]] = RSA.importKey(current_key)

  #Loads in the keys for the controller
  def load_controller_keys(self):
	private_keydata = open(self.key_directory + 'controller_private.pem', 'r').read()
	public_keydata = open(self.key_directory + 'controller_public.pem', 'r').read()

	self.private_key = RSA.importKey(private_keydata)
	self.public_key = RSA.importKey(public_keydata)



  def verify_signature(self, public_key, ciphertext):

    signer = PKCS1_v1_5.new(public_key)

    result = signer.verify(self.digest, b64decode(ciphertext))
    return result


def launch (keydir=None):

  from pox.lib.recoco import Timer

  core.openflow.miss_send_len = 0xffff
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controller(event.connection,keydir)


  core.openflow.addListenerByName("ConnectionUp", start_switch)
