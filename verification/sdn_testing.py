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
	
		#self.digest = self.importDigest()
		self.recv_string = None
		self.private_key = None
		self.public_key = None
		self.host_keys = {}
	
		if not self.key_directory == None:
			self.load_host_keys()

		self.load_controller_keys() 

    def importDigest(self, string):
	
		digest = SHA256.new()
		data = b64encode(str(string))
		digest.update(b64decode(data))
		return digest

    def load_host_keys(self):
		file_list = listdir(self.key_directory)
		for filename in file_list:
			parseFilename = filename.rsplit("_", 1)
			if len(parseFilename) == 2 and len(parseFilename[1].split(".")) == 2:
				if parseFilename[1].split(".")[0] == str("pub"):
					current_key = open(self.key_directory + '/' + filename, 'r').read()
					self.host_keys[parseFilename[0]] = RSA.importKey(current_key)

    def load_controller_keys(self):
		private_keydata = open(self.key_directory + 'controller_private.pem', 'r').read()
		public_keydata = open(self.key_directory + 'controller_public.pem', 'r').read()

		self.private_key = RSA.importKey(private_keydata)
		self.public_key = RSA.importKey(public_keydata)

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
			#print(ipv4_packet.raw)
			ciphertext = ipv4_packet.raw.split('%', 1)
			parsed_data = None
			if len(ciphertext) == 2:
				#print(ciphertext[1])
				ciphertext = eval(ciphertext[1])
				#parsed_data = self.parse_pkt_data(ciphertext)
				plaintext = self.private_key.decrypt(ciphertext)
				parsed_data = self.parse_pkt_data(plaintext)
				self.digest = self.importDigest(parsed_data[0])
			
		else:
			parsed_data = self.parse_pkt_data(ipv4_packet.raw)
			garbage_collector = parsed_data.pop(0)

		public_key = self.find_host_key(parsed_data)

		if not type(public_key) == type(None) and self.verify_signature(public_key, parsed_data[1]):
			print("MACHINE VERIFIED. ALLOW FLOW!!")
		else:
			print("INVALID MACHINE. BLOCK FLOW!!")

        self.resend_packet(event.ofp, of.OFPP_ALL)
	
    def parse_pkt_data(self, raw_data):
	
		delim = str("%")
		parsed_data = raw_data.split(delim, 1)
		return parsed_data

    def find_host_key(self, parsed_data=[]):
		if len(parsed_data) != 2:
			return None
		return (self.host_keys[parsed_data[0]] if self.host_keys.__contains__(parsed_data[0]) else None)

    def verify_signature(self, public_key, ciphertext):
		#print ("Public Key Object={0}".format(public_key))
		signer = PKCS1_v1_5.new(public_key)
		result = signer.verify(self.digest, b64decode(ciphertext))
		#print ("VERIFICATION RETURNED {0}".format(signer.verify(self.digest, b64decode(ciphertext))) )
		return result	

def launch(keydir=None):

    def start_switch (event):
        Module (event.connection, keydir)

    core.openflow.miss_send_len = 0xffff        
    core.openflow.addListenerByName("ConnectionUp", start_switch)
