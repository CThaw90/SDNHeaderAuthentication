'''
Python script generates cryptographic keys to be utilized by each host.

Script initiates an asymmetric cryptography session by generating
exclusive keys for each individual host machine in the network.
'''

from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import struct
import subprocess
import sys
hosts = ['host0', 'host1', 'host2', 'host3', 'host4', 'host5']
ch = 1 # current host

#Based on the host specified by variable ch, host key files are loaded from the
#key_dir directory
host_public_keyfile = str(hosts[ch] + "_pub.pem")
public_keyfile = str("controller_public.pem")
private_keyfile = str(hosts[ch] + "_pri.pem")
key_dir = str("/home/mininet/pox/pox/misc/keys/")
msg = str("Message")

private_keydata = open(key_dir + private_keyfile, 'r').read()
public_keydata = open(key_dir + public_keyfile, 'r').read()
public_key = RSA.importKey(public_keydata)
private_key = RSA.importKey(private_keydata)

host_public_key = open(key_dir + host_public_keyfile, 'r').read()
ciphertext = public_key.encrypt(msg, 9)

#Generate hash of host id , and sign with the hosts key
signer = PKCS1_v1_5.new(private_key)
digest = SHA256.new()
data = b64encode(hosts[ch])
digest.update(b64decode(data))
sign = signer.sign(digest)
sign = b64encode(sign)

#Signed id concatenated with plaintext id
data_string = str(hosts[ch] + "%" + sign)

#This string is then encrypted with the controller's public key
ciphertext ='%' + str(public_key.encrypt(data_string, 1))

#The Authentication header is then prepended to this ciphertext
c_length=struct.pack(">H",len(ciphertext))
ciphertext = b"\x39\xE1"+c_length+b"\x10"+ciphertext

#Using the nping program this ciphertext is sent to the identified destination
subprocess.call(["nping", "-c 1", "--tcp","--dest-ip",sys.argv[1], "-p "+sys.argv[2], "--data-string", ciphertext])

