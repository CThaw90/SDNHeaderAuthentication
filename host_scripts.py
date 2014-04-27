'''
Python script generate cryptographic keys to be utilized by each host.

Script initiates an asymmetric cryptography session by generating
exclusive keys on each individual host machine in the network.
 
'''
from Crypto.PublicKey import RSA
#from Crypto.Signature import PKCS1_v1_5
#from Crypto.Hash import SHA256
#from base64 import b64encode, b64decode

#from Crypto.Cipher import PKCS1_OAEP

import socket

host_private_keyfile = str("host4PrivateKey.pem")
host_public_keyfile = str("host4PublicKey.pem")
public_keyfile = str("controllerPublicKey.pem")
host = str("HOST_SIGNATURE")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((socket.gethostname(), 23456))

public_keydata = open(public_keyfile, 'r').read()
public_key = RSA.importKey(public_keydata)

host_public_key = open(host_public_keyfile, 'r').read()
ciphertext = public_key.encrypt(host_public_key, 9)
#key = open("controllerPrivateKey.pem", 'r').read()
string = str(ciphertext)
#private_key = RSA.importKey(key)

#host_private_key = open(host_private_keyfile, 'r').read()
#private_key = RSA.importKey(host_private_key)

#signer = PKCS1_v1_5.new(private_key)
#digest = SHA256.new()
#data = b64encode(host)
#digest.update(b64decode(data))

#sign = signer.sign(digest)
#sign = b64encode(sign)
#print(sign)
sock.send(str.encode(string))
#sock.send(str.encode(sign))
sock.close()
