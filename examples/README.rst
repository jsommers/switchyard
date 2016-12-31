Examples
********

This folder contains a few different examples of Switchyard user code, as described below.  Sample exercises intended for classroom use can be found in the ``exercises`` folder.  For further details and explanation of various API calls in the examples below, please refer to the documentation. For additional instructor materials (including exercises, full tests, etc.), please email jsommers@colgate.edu.

Basic send/receive examples
---------------------------

There are a few simple examples to illustrate sending and receiving packets using Switchyard.  

``sendpkt.py``
    This program is designed to send one packet (an ICMP echo request) out each available interface.  It should be invoked as a Switchyard program (not as a regular Python program).  For example: ``swyard sendpkt.py``.  You will likely need to run this program as root in order to successfully send packets.

``sniff.py``
    This program is a simple "packet sniffer", which just prints out a string representation of each packet as it is received.  It should be invoked as a Switchyard program, e.g., ``swyard sniff.py``.  It may need to be run as root in order to successfully capture and print packets.

``sydump.py``
    This program *uses* the Switchyard libraries, but is just executed as a regular Python program.  It captures packets from one interface, prints out each packet, and also stores the packet in a file named ``sydump.pcap``.  

    This program can just be invoked as ``python3 sydump.py``, assuming Switchyard and its dependencies have been installed.

``readpkt.py``
    This program also just *uses* the Switchyard libraries but is just executed as a regular Python program.  I reads packet data stored in a libpcap file and prints a string representation of each packet to the console.  

    This program can just be invoked as ``python3 readpkt.py``, assuming Switchyard and its dependencies have been installed.

Network hub example
-------------------

The network hub example is discussed quite extensively in the documentation.  There are two files here related to that example: ``hubtests.py`` and ``myhub.py``.  It can be executed as ``swyard -t hubtests.py myhub.py``

Application layer code + stack example
--------------------------------------

Switchyard contains a *socket emulation capability* which can be used to run a (mostly) standard UDP-based Python socket program and have that program use a Switchyard-based networking stack.  There are four example files related to this capability:

``clientapp_udpstackex.py``
    A client socket-based program that sends a UDP message to 127.0.0.1:10000 and waits for one response back from a server.

``server_udpstackex.py``
    A server socket-based program that binds to UDP port 10000 and echos back whatever gets sent to it.

``udpstack_tests.py``
    A test file that waits for a message emitted from a client program and mimics a server's response back to the client.

``udpstack.py``
    A Switchyard program that implements the very basics of a UDP networking stack.  It presently assumes that only the localhost interface is used (thus ARP and a forwarding decision are not required).  To run this program in *real* mode currently requires use of macos (Linux and other OSes are not yet supported).

To run this example in test mode, you can use the following command line:
``swyard -t udpstack_tests.py -a clientapp_udpstackex.py udpstack.py``

To run this example in real mode, you might want to start the server first, but you don't actually need to::

    $ python3 server_udpstackex.py

The Switchyard component(s) then can be executed as:``swyard -i lo0 -a clientapp_udpstackex.py udpstack.py``.  Note that if the server isn't started, you should see an ICMP destination unreachable (port unreachable) error message returned to the stack.  

Finally, note that to execute the client and server *without* any Switchyard involvement requires a single line edit in the client file to import the Python socket library instead of Switchyard's socket emulation library. 
