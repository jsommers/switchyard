Examples
********

This folder contains a few different examples of Switchyard user code, as described below.  Sample exercises intended for classroom use can be found in the ``exercises`` folder.  For additional instructor materials (including exercises, full tests, etc.), please email jsommers@colgate.edu.


Basic send/receive examples
---------------------------

There are a few simple examples to illustrate sending and receiving packets using Switchyard.  

``sendpkt.py``
    This program is designed to send one packet (an ICMP echo request) out each available interface.  It should be invoked as a Switchyard program (not as a regular Python program).  For example: ``swyard.py sendpkt.py``.  You will likely need to run this program as root in order to successfully send packets.

``sniff.py``
    This program is a simple "packet sniffer", which just prints out a string representation of each packet as it is received.  It should be invoked as a Switchyard program, e.g., ``swyard.py sniff.py``.  It may need to be run as root in order to successfully capture and print packets.

``sydump.py``
    This program *uses* the Switchyard libraries, but is just executed as a regular Python program.  It captures packets from one interface, prints out each packet, and also stores the packet in a file named ``sydump.pcap``.  

    This program can just be invoked as ``python3 sydump.py``, assuming Switchyard and its dependencies have been installed.

``readpkt.py``
    This program also just *uses* the Switchyard libraries but is just executed as a regular Python program.  I reads packet data stored in a libpcap file and prints a string representation of each packet to the console.  

    This program can just be invoked as ``python3 readpkt.py``, assuming Switchyard and its dependencies have been installed.

Network hub example
-------------------

There are two files
discussed quite extensively in the documentation
hubtests.py
myhub.py

Application layer code + stack example
--------------------------------------
clientapp_udpstackex.py
server_udpstackex.py
udpstack_tests.py
udpstack.py
only can be used on macos.  fun to run w/o starting server; you'll see the ICMP destination unreachable (port unreachable) come back.

Topology construction example
-----------------------------
for use with cli, under construction
star_topology.py