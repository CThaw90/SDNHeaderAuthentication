# Controllers

## Run
1. Create mininet topo

`sudo mn --custom ../top/simple_topo.py --mac`

2. Run the controllers in different ports

Controller0 is used to inject encrypted message in a packet payload. It is assumed that key exchange process has a way to change secret keys between the controllers and hosts.
`pox.py openflow.of_01 --port=6633 auth_controller0`

Controller1 is used to authenticate a packet. It first read the first 128 bytes from payload. Then it decrypt the content using the key pior changed with hosts.
`pox.py openflow.of_01 --port=6644 auth_controller1`
