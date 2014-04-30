#usr/bin/python/generateKeys.py
"""
This program generates keys that are binded to a certain host id

Usage: python generateKeys.py -keydir <path_to_keys> -host_id <args of host_id>

<path_to_keys> is the directory in which all keys will be generated
By default keys are generated in a folder called keys in the current directory

-host_id is the unique ids of all the hosts with keys generated 

-keysize is the size of the private key that will be generated for each host
 Note: keysize must be greater than and a multiple of 1024
"""

from Crypto.PublicKey import RSA
import sys
import os

#filename = sys.argv.pop()
#print("Running {0} . . . .".format(filename))

keydir = str('keys/')
add_keydir = False
add_size = False
keysize = 4096
add_id = False
host_ids = []
index=0

sys.stdout.write (sys.argv[0])

for args in sys.argv:
	#print(args)

	if args == '-keydir' and index+1 < len(sys.argv):
	#	print ("-keydir invoked")
	#	print ("add_keydir = True")
	#	print ("add_id = False")
		add_size = False
		add_keydir = True
		add_id = False
	
	elif args == '-host_id' and not add_id:
	#	print ("-host_id invoked")
	#	print ("add_id = True")
		add_size = False
		add_keydir = False
		add_id = True

	elif args == '-keysize' and not add_size:
		add_keydir = False
		add_id = False
		add_size = True

	elif not args == '-keydir' and not args == '-host_id' and add_id:
	#	print ("{0} added to host_ids".format(args))
		host_ids.append(args)

	elif add_keydir:
	#	print ("add_keydir = False")
	#	print ("keydir = {0}".format(keydir))
		add_keydir = False
		keydir = args
	
	elif add_size:
		try:
			keysize = int(args)
			if not keysize%1024 == 0:
				raise Exception("Invalid -keysize arg")
		except Exception:	
			print ("Invalid -keysize arg, expected integer multiple of 1024")
			sys.exit()
		
		
	elif args == 'generateKeys.py':
		pass

	else:
		print ("--Usage: python generateKeys.py -keydir <path_to_keys> -host_id <args_of_host_id>")
		sys.exit()

print ("Generating keys...")
try:
	os.stat(keydir)
except:
	os.mkdir(keydir)
for ids in host_ids:
	key = RSA.generate(keysize)
	public_key = key.publickey().exportKey('PEM')
	private_key = key.exportKey('PEM')
	
	open(keydir + ids + '_pri.pem', 'w').write(private_key)
	open(keydir + ids + '_pub.pem', 'w').write(public_key)

print("..finished!")	
