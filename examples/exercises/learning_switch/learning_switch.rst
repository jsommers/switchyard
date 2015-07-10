Overview
--------

In this exercise, you will write the code to implement the core logic in an Ethernet learning switch using the Switchyard framework.  Besides using Switchyard for developing and testing your switch, you can deploy it in Mininet to test it in a "live" setting. The code you'll need to add should be less than 20 lines (and possibly quite a bit less depending on exactly how you write the code).

Note: the ``setup.sh`` script in this directory can be used to bootstrap your development environment.  It clones the Switchyard repository from Github and installs any necessary Python modules.  If you already have an environment set up, you don't need to run this script.

Ethernet Learning Switch Operation
----------------------------------

An Ethernet learning switch is a device that has a set of interfaces ("ports") with links connected to other switches, and to end hosts.  When Ethernet frames arrive on any port/interface, the switch sends the frame on an appropriate output port if the switch knows that the host is reachable through that port, or floods the frame out all ports if it does not know where the host is.

Consider the picture below.  Say that Switch 1 doesn't know the locations of any host on the network, and that H1 wants to send an Ethernet frame to H3.  When that frame arrives at Switch 1, it sees Ethernet source address ``00:00:00:00:00:01`` and destination address ``00:00:00:00:00:03``.  From this packet arrival, it knows that it can now reach H1 by send a frame out the same interface on which this frame has arrived.  However, it does not know where to send to frame to reach H3, so it floods the packet out all ports except the one on which the frame arrived.  Eventually, H3 will receive the frame.  If it replies to H1, Switch 1 will receive a frame with the source address as H3's address, and the frame will arrive on the interface connected to Switch 2.  At this point, Switch 1 now knows exactly which ports it needs to use to send frames to either H1 or H3.
  

.. image:: ls_diagram.png

The following flowchart summarizes the example described above.  The only additional considerations shown in the flowchart are if the destination address is the same as one of the Ethernet addresses on the switch itself (i.e., the frame is intended for the switch), or the Ethernet destination address is the broadcast address (``FF:FF:FF:FF:FF:FF``).

.. image:: ls_flowchart.png
  

Your Task
---------

Your task is to implement the logic in the above flowchart, using the Switchyard framework.  This directory contains a starter file named ``myswitch.py``, which is the only file you'll need to modify.

Two links to Switchyard API documentation which you may need are:

* Packet parsing/construction reference: http://cs.colgate.edu/~jsommers/switchyard/reference.html#packet-parsing-and-construction
* Ethernet packet header reference: http://cs.colgate.edu/~jsommers/switchyard/reference.html#ethernet-header

Note that the documentation has examples on running Switchyard in test mode and in real mode, along with a walkthrough of creating a simple hub device, which is useful background material for this exercise.

Challenge Problem
-----------------

Real learning switches remove forwarding table entries after some number of seconds have elapsed so that a learning switch can adapt to changes in network topology.  Implement a timeout feature in your learning switch.  Choose some reasonable value for a timeout (e.g., 30 seconds).


Testing and Deploying your Switch
---------------------------------

You should first develop your switch code using the Switchyard test framework.   If you run::

	./switchyard/srpy.py -t -s switchtests.srpy myswitch.py


it will execute a series of test cases against your program and display whether the tests pass or fail.  Once you get the tests to pass, you can try running your code in Mininet.

To run your switch in Mininet, run the ``switchtopo.py`` custom topology script.  It will create a small network consisting of a single switch with three hosts (client, server1, and server2) in the following configuration (note that only IP addresses of the 3 hosts are shown in the picture; Ethernet MAC addresses for each interface (6 interfaces total) are not shown).

To start up Mininet using this script, just type::

	$ sudo python switchtopo.py

Once Mininet starts up, you should open a terminal window on the Mininet node named "switch"::

	mininet> xterm switch


In the window that opens, run your switch in "real" (non-test) mode::

	$ ./switchyard/srpy.py myswitch.py


To examine whether your switch is behaving correctly, you can do the following:

1. Open terminals on client and server1 (``xterm client`` and ``xterm server1`` from the Mininet prompt)
2. In the server1 terminal, run ``wireshark -k``.  Wireshark is a program that allows you to "snoop" on network traffic arriving on a network interface.  We'll use this to verify that we see packets arriving at server1 from client.
3. In the terminal on the client node, type ``ping -c 2 192.168.100.1``.  This command will send two "echo" requests to the server1 node.  The server1 node should respond to each of them if your switch is working correctly.  You should see at the two echo request and echo replies in wireshark running on server1, and you will probably see a couple other packets (e.g., ARP, or Address Resolution Protocol, packets).
4. If you run wireshark on server2, you should not see the echo request and reply packets (but you will see the ARP packets, since they are sent with broadcast destination addresses).

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
