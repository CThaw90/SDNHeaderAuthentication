# Test SDN connectivity with nping nping

from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.core import core

from os import listdir

class Module (object):

    def __init__(self, connection, keydir=None):
	self.connection = connection
	self.key_directory = keydir
	connection.addListeners(self)
	
	self.digest = self.importDigest()
	self.private_key = None
	self.public_key = None
	self.host_pubkeys = []
	self.host_ids = []
	
	if not self.key_directory == None:
		self.load_host_keys()

	self.load_controller_keys() 
    def importDigest(self):
	
	digest = SHA256.new()
	data = b64encode(str("Message"))
	digest.update(b64decode(data))
	return digest

    def load_host_keys(self):
	file_list = listdir(self.key_directory)
	for filename in file_list:
		parseFilename = filename.rsplit("_", 1)
		if len(parseFilename) == 2 and len(parseFilename[1].split(".")) == 2:
			if parseFilename[1].split(".")[0] == str("pub"):
				self.host_ids.append(parseFilename[0])
				current_key = open(self.key_directory + '/' + filename, 'r').read()
				self.host_pubkeys.append(RSA.importKey(current_key))
 				#print ("{0} -> {1}".format(parseFilename[0], parseFilename[1]))	
	#print (self.host_pubkeys)
	print (self.host_ids)

    def load_controller_keys(self):
	private_keydata = open('/home/mininet/pox/keys/controller_private.pem', 'r').read()
	public_keydata = open('/home/mininet/pox/keys/controller_public.pem', 'r').read()

	self.private_key = RSA.importKey(private_keydata)
	self.public_key = RSA.importKey(public_keydata)
	#print self.private_key.exportKey()
	#print self.public_key.exportKey()

    def resend_packet(self, packet_in, out_port):

        msg = of.ofp_packet_out()
        msg.data = packet_in

        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn (self, event):

        packet = event.parsed
	if packet.type == pkt.ethernet.IP_TYPE:
		ipv4_packet = event.parsed.find("ipv4")
		#print(dir(ipv4_packet))
		#print ("IP TYPE PACKET! -> {0}".format(ipv4_packet.payload))
		#print(ipv4_packet.raw)

		parsed_data = self.parse_pkt_data(ipv4_packet.raw)

		index = self.find_by_id(parsed_data)
		print ("Index={0}".format(index))

		if not index == -1 and self.validate_signature(parsed_data[1], index):
			print("MACHINE VERIFIED. ALLOW FLOW!!")

        self.resend_packet(event.ofp, of.OFPP_ALL)
	
    def parse_pkt_data(self, raw_data):
	
	delim = str("%")
	parsed_data = raw_data.split(delim, 2)
	garbage_data = parsed_data.pop(0)
	print (parsed_data)
	return parsed_data

    def find_by_id(self, parsed_data=[]):
	print ("Running find_by_id() method!")
	index = 0
	if len(parsed_data) == 2:
		print ("Parsed Data == 2")	
		for ids in self.host_ids:
			
			if ids == parsed_data[0]:
				print("{0} == {1}".format(parsed_data[0], ids))
				break
			else:
				print("{0} != {1}".format(parsed_data[0], ids))
				index+=1

		if index < len(self.host_ids):
			print ('Valid ID found!')

		if index >= len(self.host_ids):
			print ('No matching result for this ID')
			index = -1

	else:
		# Not a Valid Parsed Packet
		index = -1
		pass
	print ("Returning {0}".format(index))
	return index

    def validate_signature(self, parsed_cipher, index):
	ciphertext = b64encode(parsed_cipher)
	signer = PKCS1_v1_5.new(self.host_pubkeys[index])
	print ("Cipher Text: {0}".format(b64decode(ciphertext)))
	print ("VERIFICATION RETURNED {0}".format(signer.verify(self.digest, ciphertext)))
	return True

def launch(keydir=None):

    def start_switch (event):
        Module (event.connection, keydir)

    core.openflow.miss_send_len = 0xffff        
    core.openflow.addListenerByName("ConnectionUp", start_switch)
