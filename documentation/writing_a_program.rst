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
        # add some informational text about ports on this device
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

        # shutdown is the last thing we should do
        net.shutdown()



Introduction to packet parsing and construction
===============================================

This section provides an overview of packet construction and parsing
in Switchyard.  For full details on these capabilities, see :ref:`pktlib`.

Switchyard's packet construction/parsing library is found in
``switchyard.lib.packet``.  It's design is based on a few other 
libraries out there, including POX's library [#f2]_ and Ryu's library [#f3]_.

There are a few key ideas to understand when using the packet library:

 * The ``Packet`` class acts as a container of headers (rather,
   header objects).
 * Headers within a packet can be accessed through methods on the Packet
   container object, and also by indexing.  Headers are ordered starting with lowest layer protocols.  For example, if a ``Packet`` has an ``Ethernet`` header (which is likely to be the lowest layer protocol),
   this header can be accessed with index 0 as in ``pktobj[0]``.  Indexes can be integers, and they can also be packet header class names (e.g., ``Ethernet``, ``IPv4``, etc.).  For example, to access the ``Ethernet`` header of a packet, you can write ``pktobj[Ethernet]``.
 * Fields in header objects are accessed through standard Python
   *properties*.  (The code to manipulate header fields thus looks
   like it is just accessing instance variables.)
 * A packet object can be constructed by either expliciting instantiating
   and object and adding headers, or it can be formed by "adding" (using
   the ``+`` operator) headers together, or by adding headers onto a packet
   (using ``+`` or ``+=``).
 * The Switchyard framework generally *automatically* handles serializing
   and deserializing Packet objects to and from byte sequences (i.e., wire
   format packets), but you can also explicitly invoke those methods if 
   you need to.

.. figure:: packet.*
   :align: center

Here are some examples using ``Ethernet``, ``IPv4``, and ``ICMP`` headers.
First, let's construct a packet object and add these headers to the packet:

>>> from switchyard.lib.packet import *
>>> p = Packet()   # construct a packet object
>>> e = Ethernet() # construct Ethernet header
>>> ip = IPv4()    # construct IPv4 header
>>> icmp = ICMP()  # construct ICMP header
>>> p += e         # add eth header to packet
>>> p += ip        # add ip header to packet
>>> p += icmp      # add icmp header to packet
>>> print (p)
Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP | IPv4 0.0.0.0->0.0.0.0 ICMP | ICMP EchoRequest 0 0 (0 data bytes)

A shorthand for doing the above is:

>>> p = Ethernet() + IPv4() + ICMP()

The effect of "adding" headers together is to construct a packet, just as the first example.
Note that with the above example, the default Ethertype for the Ethernet header is IPv4, and
the default protocol number for IPv4 is ICMP.  Thus, the above example is somewhat special in
that we didn't need to modify any of the packet header fields to create a (mostly) valid packet.

Switchyard does *not* ensure that a constructed Packet is sensible in any way.  It is possible
to put headers in the wrong order, to supply illogical values for header elements (e.g., a protocol number in the IPv4 header that doesn't match the next header in the packet), and to do other invalid things.  Switchyard gives you the tools for constructing packets, but doesn't tell you how to do so.

The ``num_headers`` Packet method returns the number of headers in a packet, which returns
the expected number for this example:

>>> p.num_headers()
3

Note that the ``len`` function on a packet returns the number of bytes that the Packet would consume if it was in wire (serialized) format.  The ``size`` method returns the same value.  

>>> len(p)
42
>>> p.size()
42

(Note: Ethernet header is 14 bytes + 20 bytes IP + 8 bytes ICMP = 42 bytes.)

Packet header objects can be accessed conveniently by indexing.  Standard negative indexing also works.  For example, to obtain a reference to the Ethernet header object and to inspect and modify the Ethernet header, we might do the following:

>>> p[0]
<switchyard.lib.packet.ethernet.Ethernet object at 0x104474248>
>>> p[0].src
EthAddr('00:00:00:00:00:00')
>>> p[0].dst
EthAddr('00:00:00:00:00:00')
>>> p[0].dst = "ab:cd:ef:00:11:22"
>>> str(p[0])
'Ethernet 00:00:00:00:00:00->ab:cd:ef:00:11:22 IP'
>>> p[0].dst = EthAddr("00:11:22:33:44:55")
>>> str(p[0])
'Ethernet 00:00:00:00:00:00->00:11:22:33:44:55 IP'
>>> p[0].ethertype
<EtherType.IP: 2048>
>>> p[0].ethertype = EtherType.ARP
>>> print (p)
Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 ARP | IPv4 0.0.0.0->0.0.0.0 ICMP | ICMP EchoRequest 0 0 (0 data bytes)
>> p[0].ethertype = EtherType.IPv4 # set it back to sensible value

Note that all header field elements are accessed through *properties*.  For Ethernet headers, there are three properties that can be inspected and modified, ``src``, ``dst`` and ``ethertype``, as shown above.  Note again that Switchyard doesn't prevent a user from setting header fields to illogical values, e.g., when we set the ethertype to ARP.  All ``EtherType`` values are specified in ``switchyard.lib.packet.common``, and imported when the module ``switchyard.lib.packet`` is imported.

Accessing header fields in other headers works similarly.  Here are examples involving the IPv4 header:

>>> str(p[1])
'IPv4 0.0.0.0->0.0.0.0 ICMP'
>>> p[1].protocol
<IPProtocol.ICMP: 1>
>>> p[1].src
IPv4Address('0.0.0.0')
>>> p[1].dst
IPv4Address('0.0.0.0')
>>> p[1].dst = '149.43.80.13'

IPv4 protocol values are specified in ``switchyard.lib.packet.common``, just as with ``EtherType`` values.  The full set of properties that can be manipulated in the IPv4 header as well as all other headers is described in the reference documentation for the packet library: :ref:`pktlib`.

Lastly, an example with the ICMP header shows some now-familiar patterns.  The main difference with ICMP is that the "data" portion of an ICMP packet changes, depending on the ICMP type.  For example, if the type is 8 (ICMP echo request) the ICMP data becomes an object that allows the identifier and sequence values to be inspected and modified.

>>> p[2]
<switchyard.lib.packet.icmp.ICMP object at 0x104449c78>
>>> p[2].icmptype
<ICMPType.EchoRequest: 8>
>>> p[2].icmpcode
<EchoRequest.EchoRequest: 0>
>>> p[2].icmpdata
<switchyard.lib.packet.icmp.ICMPEchoRequest object at 0x1044742c8>
>>> icmp.icmpdata.sequence
0
>>> icmp.icmpdata.identifier
0
>>> icmp.icmpdata.identifier = 42
>>> icmp.icmpdata.sequence = 13
>>> print (p)
Ethernet 00:00:00:00:00:00->00:11:22:33:44:55 IP | IPv4 0.0.0.0->149.43.80.13 ICMP | ICMP EchoRequest 42 13 (0 data bytes)

By default, no "payload" data are included in with an ICMP header, but we can change that using the ``data`` property on the icmpdata part of the header:

>>> icmp.icmpdata.data = "hello, world"
>>> print (p)
Ethernet 00:00:00:00:00:00->00:11:22:33:44:55 IP | IPv4 0.0.0.0->149.43.80.13 ICMP | ICMP EchoRequest 42 13 (12 data bytes)

To serialize the packet into a wire format sequence of bytes, we can use the ``to_bytes()`` method:

>>> p.to_bytes()
b'\x00\x11"3DU\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00(\x00\x00\x00\x00\x00\x01\xba\xd6\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xb7|\x00*\x00\rhello, world'

Other header classes that are available in Switchyard include ``Arp``, ``UDP``, ``TCP``, ``IPv6``, and ``ICMPv6``.  Again, see :ref:`pktlib` for details on these header classes, and full documentation for all classes.

Utility functions (e.g., logging)
=================================

There are a few additional utility functions that are useful when developing
a Switchyard program related to logging and debugging.  These functions
are all included by importing the module ``switchyard.lib.common``.

Logging functions
-----------------

Switchyard uses the standard Python logging facilities, but provides four
convenience functions.  Each of these functions takes a string as a 
parameter and prints it to the console as a logging message.  The only 
difference with the functions relates to the logging *level* 
(see https://docs.python.org/3.4/library/logging.html#levels), and whether
the output is colored to visually highlight a problem.  The default logging
level is INFO  within Switchyard.  If you wish to include debugging messages,
you can use the ``-d`` flag for the various invocation programs (e.g., srpy),
as described in :ref:`runtest` and :ref:`runlive`.


.. py:function:: log_debug(str)

   Write a debugging message to the log using the log level DEBUG.  

.. py:function:: log_info(str)

   Write a debugging message to the log using the log level INFO.  

.. py:function:: log_warn(str)

   Write a debugging message to the log using the log level WARNING.  Output
   is colored magenta.

.. py:function:: log_failure(str)

   Write a debugging message to the log using the log level CRITICAL.  Output
   is colored red.

Alternatively, you can simply use the print statement to write to the
console, but writing to the log provides a much more structured way of
writing information to the screen.

Invoking the debugger
---------------------

Although a longer discussion of debugging is included in a later section
(:ref:`debugging`), it is worth mentioning that there is a built-in
function named ``debugger`` that can be used *anywhere* in Switchyard
code to immediately invoke the standard Python pdb debugger.

For example, if we add a call to ``debugger()`` in the example code above
just *after* the try/except block, then run the code in a test environment
(for details on how to do this, see :ref:`runtest`), the program pauses
immediately after the call to debugger and the pdb prompt is shown::

    # after hub code is started in test environment, 
    # some output is shown, followed by this:

    > /Users/jsommers/Dropbox/src/switchyard/xhub.py(29)main()
    -> for port in net.ports():
    (Pdb) list
     24     
     25                 debugger()
     26     
     27                 # send the packet out all ports *except*
     28                 # the one on which it arrived
     29  ->             for port in net.ports():
     30                     if port.name != input_port:
     31                         packet[0].src = 'ab:cd:ef:ff:ff:ff'
     32                         net.send_packet(port.name, packet)
     33     

As you can see, the program is paused on the next executable line following
the call to ``debugger()``.  At this point, any valid ``pdb`` commands
can be given to inspect program state.  Once again, see later sections
for details on running Switchyard code (:ref:`runtest`, :ref:`runlive`) and
on other debugging capabilities (:ref:`debugging`).



.. [#f1] A hub is a network device with multiple physical ports.  Any packet
   to arrive on a port is sent back out *all* ports **except** for the one
   on which it arrived.

.. [#f2] https://github.com/noxrepo/pox

.. [#f3] https://github.com/osrg/ryu

