'''
Created on Apr 25, 2014

@author: cthaw
'''
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
#from Crypto.Cipher import PKCS1_OAEP

import socket

class authentication(object):
    
    """ actual constructor to be used with network authentication """
# def __inin__ (self):
#    self.host_pubkeys = []
#    self.private_key = None
#    self.public_key = None
#    self.sock=None

    """ constructor for authentication testing with Python sockets """
    def __init__(self, public_keyfile, private_keyfile):
        
        self.host_ids = ['host1', 'host2', 'host3', 'host4', 'host5']
        key = open(public_keyfile, 'r').read()
        self.public_key = RSA.importKey(key)
        
        key = open(private_keyfile, 'r').read()
        self.private_key = RSA.importKey(key)
        
        self.host_pubkeys = []
        
        self.sock = None
        
    def bindsocket (self, clientsocket):
        self.sock = clientsocket
        
    def addhostkey(self):
        encrypted_public_key = eval(self.sock.recv(4096))
       # signature = self.sock.recv(4096)
        #print(b64decode(signature))
        public_key = self.private_key.decrypt(encrypted_public_key)
        exists = False
        i=0
        
       # signer = PKCS1_v1_5.new(public_key)
       # digest = SHA256.new()
       # data = b64encode("HOST_SIGNATURE")
       # digest.update(b64decode(data))
        
       # if signer.verify(digest, b64decode(signature)):
       #     print ("Signature Passed!")
            
        while i in range(0, len(self.host_pubkeys)) and not exists:
            
            if self.host_pubkeys[i] == public_key:
                exists = True
                
            i+=1
            
        if not exists:
            self.host_pubkeys.append(public_key)

if __name__ == '__main__':
    private_keyfile = str("controllerPrivateKey.pem")
    public_keyfile = str("controllerPublicKey.pem")
    
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssocket.bind((socket.gethostname(), 23456))
    auth = authentication(public_keyfile, private_keyfile)
    ssocket.listen(5)
    c = True
    
    while c:
        (clientsocket, address) = ssocket.accept()
        auth.bindsocket(clientsocket)
        auth.addhostkey()
        clientsocket.close
        print(auth.host_pubkeys)
        
        x = raw_input("Continue? press y: ")
        c = True if x == 'y' else False
        
        if not c:
            ssocket.close