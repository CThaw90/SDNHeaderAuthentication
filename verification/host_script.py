'''
Python script generates cryptographic keys to be utilized by each host.

Script initiates an asymmetric cryptography session by generating 
exclusive keys for each individual host machine in the network.
'''

from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import subprocess

host_public_keyfile = str("host4_pub.pem")
public_keyfile = str("controller_public.pem")
private_keyfile = str("host4_pri.pem")
key_dir = str("/home/mininet/pox/keys/")
msg = str("Message")

private_keydata = open(key_dir + private_keyfile, 'r').read()
public_keydata = open(key_dir + public_keyfile, 'r').read()
public_key = RSA.importKey(public_keydata)
private_key = RSA.importKey(private_keydata)
#print("Size: {0}".format(private_key.size()))
#print("Size: {0}".format(public_key.size()))
host_public_key = open(key_dir + host_public_keyfile, 'r').read()
ciphertext = public_key.encrypt(msg, 9)

signer = PKCS1_v1_5.new(private_key)
digest = SHA256.new()
data = str("Message")
data = b64encode(data)
digest.update(b64decode(data))
sign = signer.sign(digest)
sign = b64encode(sign)
#print ("SignatureLength: {0}".format(len(sign)))
#print(sign)
data_string = str("%" + "host4" + "%" + sign)
subprocess.call(["nping", "-c 1", "--tcp", "-p 80", "10.0.0.1", "--data-string", data_string])
#print(data_string)

