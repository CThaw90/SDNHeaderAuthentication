# Controllers

## Add PYTHONPATH
`export PYTHONPATH=$PYTHONPATH:/home/mininet/development/SDNHeaderAuthentication`

You should replace "development/SDNHeaderAuthentication" with the right path on you local machine.

## Run

1. Run the controllers in different ports

Controller0 is used to inject encrypted message in a packet payload. It is assumed that key exchange process has a way to change secret keys between the controllers and hosts.

`pox.py openflow.of_01 --port=6644 controller.auth_controller0`

Controller1 is used to authenticate a packet. It first read the first 128 bytes from payload. Then it decrypt the content using the key pior changed with hosts.

`pox.py openflow.of_01 --port=6655 controller.auth_controller1`


Controller2 is l3_learning in POX

`pox.py forwarding.l2_learning


2. Create mininet topo

`sudo mn --custom ../topo/simple_topo.py --mac`



3. Ping hosts
