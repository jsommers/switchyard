.. _coding:

Writing a Switchyard Program
****************************

.. index:: switchy_main, srpy_main, main

A Switchyard program is simply a Python program that includes an explicit "startup" function.  The startup function can either be named ``switchy_main``, ``srpy_main``, or simply ``main``.   This function must accept a single parameter, which is a reference to the Switchyard "network object" (described below).  The network object is used to send and receive packets to and from network interfaces.  

.. index:: srpy.py

A Switchyard program isn't executed *directly* with the Python interpreter.  You will instead use the Switchyard program ``srpy.py`` to start up the Switchyard framework and tell ``srpy.py`` to load your code.  Details on how to do this are given in the chapters on running a Switchyard in the "test" environment (:ref:`runtest`) and running Switchyard in a "live" environment (:ref:`runlive`).

A Switchyard program will typically also import other Switchyard modules such as  modules for parsing and constructing packets, dealing with network addresses, and other functions.  These modules are introduced below and described in detail in the API reference chapter (:ref:`apiref`).

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

This program isn't likely to be very useful --- it is just meant as an illustration of two of the key methods on the network object:

.. py:method:: recv_packet(timeout=None, timestamp=False)

   Receive packets from any device on which one is available.
   Blocks until a packet is received, unless a timeout value >= 0
   is supplied.  

   :param float timeout: The amount of time to wait to receive a packet, or ``None`` if the call should block until a packet is received (this is the default behavior)
   :param bool timestamp: Indicate whether a timestamp associated with packet arrival is desired or not (default behavior is not to return a timestamp)
   :return: A tuple of length 2 or 3, depending whether the timestamp is desired.  If no timestamp returns the device name (str) and the packet.  If a timestamp, returns device name, timestamp, and the packet.
   :raises Shutdown: if the network device is shut down (i.e., by stopping the Switchyard program)
   :raises NoPackets: if no packets are received before the timeout expires.
   
.. py:method:: send_packet(output_port, packet)

   Send the Switchyard ``Packet`` object ``packet`` out the port
   named ``output_port``.  
   
   :param str output_port: The name of the port on which to send the packet
   :param Packet packet: A Switchyard packet object to send out the given interface
   :return: None
   :raises SwitchyException: if the ``output_port`` is invalid

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
but it's currently broken because it still just sends a packet out the *same port* on which it arrived:

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

The only other methods available the network object relate to getting information about the ports/interfaces attached to the device on which the Switchyard code is running.  The two basic methods are ``ports`` and ``interfaces``:

.. py:method:: interfaces()
 
   Get a list of ports that are configured on the current network device.
   An alias method ``ports`` does exactly the same thing.

   :return: list of ``Interface`` objects

Each object returned from the ``interfaces`` or ``ports`` method is an instance of the class ``Interface`` and describes one interface/port on the device.  The ``Interface`` class is defined in the module ``switchyard.lib.common``:

.. py:class:: switchyard.lib.common.Interface
   
   .. py:attribute:: name 
 
      The name of the interface (e.g., eth0) as a string
      
   .. py:attribute:: ethaddr 

      The Ethernet address associated with the interface, as a
      switchyard.lib.address.EthAddr instance.

   .. py:attribute:: ipaddr

      The IPv4 address associated with the interface, if any.  Returns
      an object of type IPv4Address.  If there is no address assigned
      to the interface, the address is 0.0.0.0.
      A limitation with the Interface implementation in Switchyard at present
      is that only one address can be associated with an interface, and
      it must be an IPv4 address.

   .. py:attribute:: netmask

      The network mask associated with the IPv4 address assigned to the
      interface.  The netmask defaults to 255.255.255.255 (/32) if none
      is specified.

For example, to simply print out information regarding each interface
defined on the current network device, you could use the following
program:

.. code-block:: python

    def srpy_main(net):
        for intf in net.interfaces():
            print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)

        # could also be:
        # for intf in net.ports():
        #    ...


Entirely depending on how the network device is configured, output from 
the above program might look like the following::

    eth2 10:00:00:00:00:03 172.16.42.1 255.255.255.252
    eth1 10:00:00:00:00:02 10.10.0.1 255.255.0.0
    eth0 10:00:00:00:00:01 192.168.1.1 255.255.255.0

Note that there is *no ordering* to the list of interfaces returned.

There are a few convenience methods related to ``ports`` and ``interfaces``, 
which can be used to look up a particular interface given a name, IPv4 address,
or Ethernet (MAC) address:

.. py:method:: interface_by_name(name)

   This method returns an ``Interface`` object given a string name
   of a interface.  An alias method ``port_by_name(name)`` also exists.

   :param str name: The name of the device, e.g., "eth0"
   :return: An ``Interface`` object or None if the name is invalid

.. py:method:: interface_by_ipaddr(ipaddr)

   This method returns an ``Interface`` object given an IP address configured
   on one of the interfaces.  The IP address may be given as a string or as 
   an IPv4Address object.  An alias method ``port_by_ipaddr(devicename)`` 
   also exists.

   :param ipaddr:
   :type ipaddr: IP address as a string or as an IPv4Address object
   :return: An ``Interface`` object or None if the IP address isn't configured on one of the ports

.. py:method:: interface_by_macaddr(ethaddr)

   This method returns an ``Interface`` object given an Ethernet (MAC) address
   configured on one of the interfaces.  An alias method 
   ``port_by_macaddr(devicename)`` also exists.

   :param ethaddr:
   :type ethaddr: Ethernet address as a string (e.g. "11:22:33:44:55:66") or as an instance of EthAddr class
   :return: An ``Interface`` object or None if the MAC address isn't configured on one of the ports


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


The Shutdown and NoPackets exception classes
Shutdown is raised when the Switchyard framework is shutting down
NoPackets is raised when you attempt to receive packets, but none arrive prior to a "timeout" occurring
log_debug, log_info, log_warn, log_failure
Each of these functions takes a string as a parameter and prints it to the console as a logging message
Alternatively, you can simply use the print statement to write to the console

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
