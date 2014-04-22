SDNHeaderAuthentication
=======================

An implementation of Authenticated Headers in a Software-Defined Network Environment

The ``cryptography`` package requires dependencies that are not provided 
by the default python package on the Mininet Ubuntu distro. Instructions 
are provided for installing the necessary packages and modules.

``Six`` is the first Python library needed for running the ``cryptography``
python module. Run the ``sudo python setup.py install`` from within the 
``six`` directory and be sure that the module can be imported via the 
python interpreter;

.. code-block:: pycon
	
	mininet:$ python
	>>> import six
	>>>
	
After necessary packages and modules are imported you should be able to 
run the following commands with no errors from within the python 
interpreter or via a Python script.

.. code-block:: pycon

	>>> from cryptography.fernet import Fernet
	>>> # Put this somewhere sage!
	>>> key = Fernet.generate_key()
	>>> f = Fernet(key)
	>>> token = f.encrypt(b"Secret Message")
	>>> token
	>>> f.decrypt(token)
	'Secret Message'

You can find more information in the `documentation`_.

.. _`documentation`: https://cryptography.io/