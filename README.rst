SDNHeaderAuthentication
=======================

An implementation of Authenticated Headers in a Software-Defined Network Environment

The ``cryptography`` package requires dependencies that are not provided 
by the default python package on the Mininet Ubuntu distro. Instructions 
are provided for installing the necessary packages and modules.

You can clone this repo and run the commands from within the three root
directories: ``six`` ``cffi`` ``libffi`` ``cryptography``.

I don't think the mininet environment supports outside internet activity 
so these would need to be imported via a Shell connection or localhost
file transfer.

``Note:`` There are extra developer modules that these packages depend on
for installation and setup, however the current distro of mininet should
be adequate enough to support them all.

Python Six
~~~~~~~~~~~~~~~

``Six`` is the first Python library needed for running the ``cryptography``
python module. Run the ``python setup.py install`` from within the 
``six`` directory and be sure that the module can be imported via the 
python interpreter;

.. code-block:: pycon
	
	mininet:$ python
	>>> import six
	>>>
	
Package libffi
~~~~~~~~~~~~~~~~
	
Next you want to install the ``libffi`` python library package. You can 
use the one available but it might be easier to just clone it from the 
the `libffi repository`_. 

If you use the version source code to build ``libffi`` you must run the ``./autogen.sh`` command and then run``./configure``.

Once ``configure`` has finished, type ``make``. Note that you must be 
using GNU make. You can ftp GNU make from ftp.gnu.org:/pub/gnu/make
Ensure texinfo is installed

To ensure that libffi is working as advertised, type ``make check``. This
will require that you have DehaGNU installed.

To install the library an header files, type ``make install``.

Package cffi
~~~~~~~~~~~~~~~
Navigate to the cffi directory. 

Ensure you have the ``python-dev`` package. Run ``sudo apt-get install python-dev`` After the python-dev finishes install use the command 
``python setup_base.py install``. 

Python-Dev may have to be manually imported from another machine.

You should now be able to import both Python modules via the interpreter

.. code-block:: pycon

	mininet:$ python
	>>> import six
	>>> import cffi

Package cryptography
~~~~~~~~~~~~~~~~~~~~~~
Navigate to the cryptography directory

Run the ``python setup.py install`` command.
	
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

.. _`libffi repository`: https://github.com/atgreen/libffi