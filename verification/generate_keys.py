from Crypto.PublicKey import RSA

key_dir = str("/home/mininet/pox/keys/")
host_id = str("host4")
private_keyfile = str(host_id + "_pri.pem")
public_keyfile = str(host_id + "_pub.pem")

key = RSA.generate(4096)

public_key = key.publickey().exportKey('PEM')
private_key = key.exportKey('PEM')

open(key_dir + private_keyfile, 'w').write(private_key)
open(key_dir + public_keyfile, 'w').write(public_key)

