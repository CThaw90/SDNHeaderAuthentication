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
# Date:	  	February 25, 2014
#
# References:	Flow_Stat https://github.com/hip2b2/poxstuff/blob/master/flow_stats.py
#		OpenFlow Tutorial http://archive.openflow.org/wk/index.php/OpenFlow_Tutorial
#		POX Wiki https://openflow.stanford.edu/display/ONL/POX+Wiki



"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""


from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as packet
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
    self.hosts= {"10.0.0.1":"h1","10.0.0.2":"h2","10.0.0.3":"h3","10.0.0.4":"h4","10.0.1.0":"h1"}

    self.secure_path = [["h1","h4","s7","s1","s4","s5"],
["h2","h3","s7","s1","s8","s2"],["h4","h1","s6","s4","s1","s7"],["h1","h3","s7","s1","s8","s3"],
["h3","h2","s3","s8","s1","s7"],["h3","h1","s7","s1","s8","s3"],["h3","h4","s2","s8","s1","s4","s5"],
["h2","h4","s7","s1","s4","s6"],["h4","h3","s6","s4","s1","s8","s3"],["h4","h2","s6","s4","s1","s7"]]

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.ip_to_port = {}
    self.priority=20

    self.key_directory = keydir


    self.digest = self.importDigest("Message")

    self.private_key = None
    self.public_key = None
    self.host_keys = {}

    if not self.key_directory == None:
		self.load_host_keys()

    self.load_controller_keys()


    #code for simple NAT behavior not performing as expected
    """
    if dpid_to_str(connection.dpid)=="7":
	msg1 = of.ofp_flow_mod()
    	msg2 = of.ofp_flow_mod()
    	msg1.priority = msg2.priority = 200
    	msg1.match.nw_src=IPAddr("10.0.0.1")
    	msg2.match.nw_src=IPAddr("10.0.0.2")

    	msg1.actions.append(of.ofp_action_nw_addr.set("10.0.1.0"))
    	msg2.actions.append(of.ofp_action_nw_addr.set("10.0.1.0"))
	msg1.actions.append(of.ofp_action_output(port = out_port))
    	msg2.actions.append(of.ofp_action_output(port = out_port))
    	self.connection.send(msg1)
    	self.connection.send(msg2)

  	msg3 = of.ofp_flow_mod()
    	msg4 = of.ofp_flow_mod()
    	msg3.priority = msg4.priority = 2000
    	msg3.match.nw_dst=IPAddr("10.0.0.1")
    	msg4.match.nw_dst=IPAddr("10.0.0.2")


    	self.connection.send(msg3)
    	self.connection.send(msg4)


    if dpid_to_str(connection.dpid)=="8":
    	#Setting up rules for blocking ip traffic from h1 or h2  to h3
    	msg1 = of.ofp_flow_mod()
    	msg2 = of.ofp_flow_mod()
    	msg1.priority = msg2.priority = 2000
    	msg1.match.nw_src=IPAddr("10.0.0.1")
    	msg2.match.nw_src=IPAddr("10.0.0.2")


    	self.connection.send(msg13)
    	self.connection.send(msg31)
    """


  def resend_packet (self, packet_in, out_port):

    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)




  def act_like_switch (self, packet, packet_in):

    #print "*rawdata string:*"+str(packet.raw[53:])+"*:end of string"
    data=packet.raw[54:]

    ip=packet.find('ipv4')
    tcp=packet.find('tcp')



    if ip is not None:
        #print tcp.srcport#tip.dstip#print ip.srcip.toStr()


        #seen=False
        #if len(self.mac_to_port) and str(packet.src) in self.mac_to_port:
    	#seen=True

        src_id=""
        dst_id=""
        for key in self.hosts:

              if str(ip.srcip)==key:
    			src_id=self.hosts[key]

              if str(ip.dstip)==key:
    			dst_id=self.hosts[key]

        if src_id!="" and dst_id!="":
    		  index=-1


        #data= self.parse_pkt_data(ip.raw)
        public_key=self.find_host_key(["host"+src_id[1]])
        if self.priority==2000:
    	   self.priority=20

        print "Data: "+":".join("{:02x}".format(ord(c)) for c in data)
        if data[:2]==b"\x39\xE1" and data[4:5]==b"\x10":
            length= struct.unpack('>H',data[2:4]) #check endianness
            #print "Length: "+str(length[0])

            #validate the host

            value=data[5:5+length[0]]
            rand_val = os.urandom(4)

            enc_str=str(rand_val)+str(value)
            enc_val=self.importDigest(enc_str)
            con_enc = PKCS1_v1_5.new(self.private_key)

            enc_val=con_enc.sign(enc_val)

            #print "Encryption Length "+str(len(str(enc_val)))#512

            hash_array=[]



            for i in range(0,len(self.secure_path)):
                if self.secure_path[i][0]==src_id and self.secure_path[i][1]==dst_id:
                    print "Path Found"
                    index=i

            if index !=-1:
                for i in range(0,(len(self.secure_path[index])-2)):
                    hash_array.append(enc_val) #hash value encrypted
                    enc_val=self.importDigest(str(enc_val)) #need to hash value again



                for i in range(1,len(self.secure_path[index])-1):
                    sw = self.secure_path[index][len(self.secure_path[index])-i]
                    print sw +" "+sw[1]+" "+dpid_to_str(self.connection.dpid)
                    if dpid_to_str(self.connection.dpid)==sw[1]:

                            rule = of.ofp_flow_mod()
                            rule.priority =self.priority+1

                            if i == len(self.secure_path[index])-2:
                                rule.match=of.ofp_match(dl_src=packet.src, dl_dst=packet.dst, nw_src=ip.srcip, nw_dst=ip.dstip, tp_src=tcp.srcport, tp_dst=tcp.dstport)
                            else:
        					   rule.match=of.ofp_match(dl_src=EthAddr(hash_array[i][0:47]), dl_dst=packet.dst, nw_src=ip.srcip, nw_dst=ip.dstip, tp_src=tcp.srcport, tp_dst=tcp.dstport)

                            rule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(hash_array[i-1][0:47])))     #!!!!!!!!hashed value from array may need to convert to MAC and split formate 00:00:00:00:00:00))
                            rule.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                            self.connection.send(rule)


                drop_rule = of.ofp_flow_mod()
                drop_rule.priority =self.priority
                drop_rule.match=of.ofp_match(dl_dst=packet.dst, nw_src=ip.srcip, nw_dst=ip.dstip, tp_src=tcp.srcport, tp_dst=tcp.dstport)
                self.connection.send(drop_rule)


            enc_value=0
            enc_str=0
            hash_array=[]
            value=0


            self.priority+=2

    """
    3. If this exists can use nonce and value included to encrypt with private key of controller and
   	and generate the flow rules
    4.  do hash of value n times
    5. To first switch (switch that sent packet ) send rule that modifies the received packet with the
	metadata of nth hash
	add drop rule to all switchets for flow with less priority
    6.  in each successive switch modify the meta data with n-1, n-2 have second rule that drops flow for
	anything else
    7. store in switch keep track of current priority or some value to remove flow if update of secure path
       happens

    """

    print dpid_to_str(self.connection.dpid)+" Src: "+str(packet.src)+" Dest: "+str(packet.dst)

    dest_port=-1

    #if the port associated with the destination MAC of the packet is known:
    # Send packet out the associated port
    for key in self.mac_to_port:
        if key == str(packet.dst):
	    dest_port=self.mac_to_port[key]

            break

    if dest_port != -1:

        #Since flow has not yet been added (placed here since this is the first
	    #time the flow is seen) packet must be sent out
        self.resend_packet(packet_in,dest_port)

        fm = of.ofp_flow_mod()
    	fm.priority =10
    	fm.match.dl_dst=packet.dst
    	fm.actions.append(of.ofp_action_output(port = dest_port))
    	self.connection.send(fm)

        # Maybe the log statement should have source/destination/port?
      	print "Installing flow for dst: "+str(packet.dst)+" on port: "+str(dest_port)


    #else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?

    else:

 	  self.resend_packet(packet_in, of.OFPP_ALL)
      #print "Flooding Packet"




  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.


    self.act_like_switch(packet, packet_in)

  def parse_pkt_data(self, raw_data):

	delim = str("%")
	parsed_data = raw_data.split(delim, 2)
	garbage_data = parsed_data.pop(0)
	#print (parsed_data)
	return parsed_data

  def find_host_key(self, parsed_data=[]):
    if len(parsed_data) != 2:
		return None
    return (self.host_keys[parsed_data[0]] if self.host_keys.__contains__(parsed_data[0]) else None)

  def importDigest(self,message):

	digest = SHA256.new()
	data = b64encode(message)
	digest.update(b64decode(data))
	return digest

  def load_host_keys(self):
	file_list = listdir(self.key_directory)
	for filename in file_list:
		parseFilename = filename.rsplit("_", 1)
		if len(parseFilename) == 2 and len(parseFilename[1].split(".")) == 2:
			if parseFilename[1].split(".")[0] == str("pub"):
				#self.host_ids.append(parseFilename[0])
				current_key = open(self.key_directory + '/' + filename, 'r').read()
				#self.host_pubkeys.append(RSA.importKey(current_key))
				self.host_keys[parseFilename[0]] = RSA.importKey(current_key)

  def load_controller_keys(self):
	private_keydata = open(self.key_directory + 'controller_private.pem', 'r').read()
	public_keydata = open(self.key_directory + 'controller_public.pem', 'r').read()

	self.private_key = RSA.importKey(private_keydata)
	self.public_key = RSA.importKey(public_keydata)


  def validate_signature(self, parsed_cipher, index):
    ciphertext = parsed_cipher
    signer = PKCS1_v1_5.new(self.host_pubkeys[index])
    result = signer.verify(self.digest, b64decode(ciphertext))
    return result

  def verify_signature(self, public_key, ciphertext):
	#print ("Public Key Object={0}".format(public_key))
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
