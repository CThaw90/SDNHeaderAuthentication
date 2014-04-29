Verification Logic
~~~~~~~~~~~~~~~~~~~~~~~

The verification script for the controller is in the python file ``sdn_testing.py`` 

Run this by loading the private and public keys into memory from the key directory.
Use the directory path as an argument to the controller script.
``./pox.py sdn_testing.py -keydir='<full_key_directory_path>'``

There are keys already generated and located in the keys directory.
You can generate and test keys by putting the new generated keys into a folder
and using the path to that directory as an argument to ``-keydir``.

``Note: You must use the naming conventions in order for the controller to properly
load the keydata files. Use <Whatever>_pri.pem for private keys and 
<Whatever>_pub.pem for public keys. Remember the underscore between the name and the 
type id.``

Public and private key files can be generated with the following script:

.. code-block:: pycon

	mininet:$ python
	>>> from Crypto.PublicKey import RSA
	>>> key_dir = str("/home/mininet/pox/keys/") # Use any directory path
	>>> private_keyfile = str("mykey_pri.pem") # Use any valid file string before underscore ( _ )
	>>> public_keyfile = str("mykey_pub.pem") # Use any valid file string before underscore ( _ ) 
	
	>>> key = RSA.generate(2048)
	>>> public_key = key.publickey().exportKey('PEM')
	>>> private_key = key.exportKey('PEM')
	
	>>> open(key_dir + private_keyfile, 'w').write(private_key)
	>>> open(key_dir + public_keyfile, 'w').write(public_key)
	
Once the controller has loaded all keys into memory you can run the 
``host_script.py`` python script to send a signature string to the controller for 
verification.