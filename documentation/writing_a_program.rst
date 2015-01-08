Writing a Switchyard Program
****************************

.. index:: switchy_main, srpy_main, main

A Switchyard program is simply a Python program that includes an explicit "startup" function.  The startup function can either be named ``switchy_main``, ``srpy_main``, or simply ``main``.   This function must accept a single parameter, which is a reference to the Switchyard "network object" (described below).  The network object is used to send and receive packets to and from network interfaces.  

.. index:: srpy.py

Note that a Switchyard program isn't executed *directly* with the Python interpreter.  You will instead use the Switchyard program ``srpy.py`` to start up the Switchyard framework and tell ``srpy.py`` to load your code.  Details on how to do this are given in 

A Switchyard program will typically also import other Switchyard modules such as  modules for parsing and constructing packets, dealing with network addresses, and other functions.

Introducing the "network object"
================================

As mentioned above, a Switchyard program can simply have a ``main`` function that accepts a single argument.  The parameter passed to ``main`` is called the "network object".  It is on this object that you can call methods for sending and receiving packets and getting information about ports on the device for which you're implementing the logic.

Sending and receiving packets
-----------------------------

Here is a program that receives one packet, prints it out, sends it *back out the same interface*, then quits.

.. code-block:: python
    
    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net):
        input_port,packet = net.recv_packet()
        print ("Received {} on {}".format(packet, input_port))
        net.send_packet(input_port, packet)

This program isn't likely to be very useful --- it is just meant as an illustration of two of the key methods on the network object.  In more detail:

 * ``recv_packet(timeout=None, timestamp=False)``

     Receive packets from any device on which one is available.
     Blocks until a packet is received, unless a timeout value >= 0
     is supplied.  Raises ``Shutdown`` exception when device(s) are shut 
     down (i.e., on a SIGINT to the process).  Raises ``NoPackets`` when 
     there are no packets that can be read.

     Returns a tuple of length 2 or 3, depending whether the timestamp
     is desired:

     * ``device``: network device name on which packet was received as a string
     * ``timestamp``: floating point value of time at which packet was received (optionally returned; only if ``timestamp=True``)
     * ``packet``: Switchyard Packet object.  

 * ``send_packet(output_port, packet)``

     Send the Switchyard ``Packet`` object ``packet`` out the port
     named ``output_port``.  If ``output_port`` is not valid (i.e., it
     doesn't exist), ``SwitchyException`` is raised.

Note that in the above call to ``recv_packet``, no arguments are given
so the call will block until a packet is received, and no timestamp will be
returned (just the input port and the packet object).  Importantly, note also
that we aren't handling any potential exceptions that could occur.  In
particular, we really should be handling *at least* the situation in which
the framework is shut down (and we receive a ``Shutdown`` exception).  Just
for completeness, we should also handle the ``NoPackets`` exception, although
if the code is designed to block indefinitely we shouldn't receive that
particular exception.  
(Note: these exceptions are defined in ``switchyard.lib.common``.) 

Let's rewrite the code above, and now put everything in a ``while`` loop
so that we keep reading and sending packets as long as we're running.  
We will eventually turn this code into a working network *hub* implementation [#f1]_,
but it's currently broken because it still just sends a packet out the same
port on which it arrived:

.. code-block:: python
    
    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net):
        while True:
            try:
                input_port,packet = net.recv_packet()
            except Shutdown:
                print ("Got shutdown signal; exiting")
            except NoPackets:
                print ("No packets were available.")

            # if we get here, we must have received a packet
            print ("Received {} on {}".format(packet, input_port))
            net.send_packet(input_port, packet)


Getting information about ports (interfaces) on the device
----------------------------------------------------------

The only other methods available the network object related to interfaces ...


In addition to having methods for sending and receiving packets, the network object has methods to allow gathering a list of interfaces (ports) attached to your network device (i.e., the switch or router for which you're creating the logic).




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

.. code-block:: python
    
    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net):
        print ("Hub is starting up with these ports:")
        for port in net.ports():
            print ("{}: ethernet address {}".format(port.name, port.ethaddr)) 

        while True:
            try:
                input_port,packet = net.recv_packet()
            except Shutdown:
                # got shutdown signal
                break
            except NoPackets:
                # try again...
                continue

            # send the packet out all ports *except*
            # the one on which it arrived
            for port in net.ports():
                if port.name != input_port:
                    net.send_packet(port.name, packet)


Other methods on the network object
-----------------------------------

The only other method available on the network object is ``shutdown``:

 * ``shutdown()`` this signals to the Switchyard framework that your program is done and exiting.  It should be the last thing you call in a Switchyard program.

A really complete implementation of our hub is now:

.. code-block:: python
    
    from switchyard.lib.packet import *
    from switchyard.lib.address import *
    from switchyard.lib.common import *

    def main(net):
        print ("Hub is starting up with these ports:")
        for port in net.ports():
            print ("{}: ethernet address {}".format(port.name, port.ethaddr)) 

        while True:
            try:
                input_port,packet = net.recv_packet()
            except Shutdown:
                # got shutdown signal
                break
            except NoPackets:
                # try again...
                continue

            # send the packet out all ports *except*
            # the one on which it arrived
            for port in net.ports():
                if port.name != input_port:
                    net.send_packet(port.name, packet)

        # new line of code:
        # shutdown is the last thing we do
        net.shutdown()


Packet parsing and construction
===============================

basic pattern and core ideas of packet libraries

examples:

  * ether + ip + icmp
  * ether + arp
  * ether + ip + udp + payload
  * ether + ip + tcp + payload

include examples with looking at particular aspects of address objects


Utility functions (e.g., logging)
=================================

``log_debug``, ``log_info``, etc.

Others?

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

.. [#f1] A hub is a network device with multiple physical ports.  Any packet
   to arrive on a port is sent back out *all* ports **except** for the one
   on which it arrived.
