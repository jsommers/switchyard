Writing a Switchyard Program
****************************

.. index:: switchy_main, srpy_main, main

A Switchyard program is simply a Python program that includes an explicit "startup" function.  The startup function can either be named ``switchy_main``, ``srpy_main``, or simply ``main``.   This function must accept a single parameter, which is a reference to the Switchyard "network object" (described below).  The network object is used to send and receive packets to and from network interfaces.  

.. index:: srpy.py

Note that a Switchyard program isn't executed *directly* with the Python interpreter.  You will instead use the Switchyard program ``srpy.py`` to start up the Switchyard framework and tell ``srpy.py`` to load your code.  Details on how to do this are given in 

A Switchyard program will typically also import other Switchyard modules such as  modules for parsing and constructing packets, dealing with network addresses, and other functions.

Introducing the "network object"
================================

As mentioned above, a Switchyard program can simply have a ``main`` function that accepts a single argument.  The parameter passed to ``main`` is called the "network object".  It is on this object that you can call methods for sending and receiving packets.  For example, here is a program that receives one packet, prints something out, then quits.

.. code-block:: python
    
    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net):
        input_port,packet = net.recv_packet()
        print ("Received {} on {}".format(packet, input_port))

In addition to having methods for sending and receiving packets, the network object has methods to allow gathering a list of interfaces (ports) attached to your network device (i.e., the switch or router for which you're creating the logic).



a set of methods that allow you to find out about interfaces attached to your network device (e.g., your switch or router), receive packets from the network, and emit a packet on a network interface.  There are also some important classes and functions in a module called srpy_common.

Important classes and functions in srpy_common are:

Interfaces (ports)
==================


The Interface class, which models a single logical interface on a network device.  It has four properties:
name: the name of the interface
ethaddr: the Ethernet address associated with the interface as a POX EthAddr object
ipaddr: the IP address associated with the interface as a POX IPAddr object
netmask: the subnet mask associated with the interface as a POX IPAddr object
The Shutdown and NoPackets exception classes
Shutdown is raised when the Switchyard framework is shutting down
NoPackets is raised when you attempt to receive packets, but none arrive prior to a "timeout" occurring
log_debug, log_info, log_warn, log_failure
Each of these functions takes a string as a parameter and prints it to the console as a logging message
Alternatively, you can simply use the print statement to write to the console

The methods available on the net object are:
interfaces(): this method returns a list of Interface objects (as described above) attached to your network device.   As an example for using this method, here is a short program that defines a srpy_main function.  The program just iterates through the list of interfaces returned from net.interfaces(), and prints out the name, Ethernet MAC address, IP address, and IP subnet mask associated with each interface:

::
    def srpy_main(net):
        for intf in net.interfaces():
            print intf.name, intf.ethaddr, intf.ipaddr, intf.netmask

Example output from the above program might be::

    eth2 10:00:00:00:00:03 172.16.42.1 255.255.255.252
    eth1 10:00:00:00:00:02 10.10.0.1 255.255.0.0
    eth0 10:00:00:00:00:01 192.168.1.1 255.255.255.0

Notice that there is no ordering to the list of interfaces returned.

There is also a ports() method that is just an alias of interfaces().

interface_by_name(devicename), interface_by_ipaddr(ipaddr), interface_by_macaddr(ethaddr): these methods are alternative ways to obtain an Interface object, by supplying a device name (e.g., "eth0") an IP address configured on a device, or an Ethernet MAC address configured on a device.  They are basically convenience methods provided so that you do not have to continually iterate over the list of interfaces.

recv_packet(timeout): this method waits for timeout seconds for any packets to arrive.  If a packet arrives before timeout seconds have passed, it returns a tuple of three items: the device name that the packet arrived on, a timestamp, and a POX packet object.  If no packets arrive before timeout seconds pass, the method raises a NoPackets exception.

send_packet(dev, packet): this method sends a packet (which must be a POX Ethernet packet object) on the device named dev.  The name dev must match the name of one of the interfaces given in the interface list.

shutdown(): this signals to the Switchyard framework that your program is done and exiting.  It should be the last thing you call in a SRPY program.

Packet parsing and construction
===============================

basic pattern and core ideas of packet libraries

examples:

  * ether + ip + icmp
  * ether + arp
  * ether + ip + udp + payload
  * ether + ip + tcp + payload

include examples with looking at particular aspects of address objects


A longer example
================

A simple template for a Switchyard program is as follows:

FIXME: explain

.. code-block:: python

    #!/usr/bin/env python

    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net): 
        while True:
            try:
                dev,packet = net.recv_packet(timeout=1.0)
            except NoPackets:
                # timeout waiting for packet arrival
                continue
            except Shutdown:
                # we're done; bail out of while loop
                return

            # just print each packet to the console
            print (packet.dump()) 

        # before exiting our main function perform shutdown on network
        net.shutdown()

