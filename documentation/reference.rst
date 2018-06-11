.. _apiref:

API Reference
*************

Before getting into all the details, it is important to note that all the below API features can be imported through the module ``switchyard.lib.userlib``.

.. automodule:: switchyard.lib.userlib

Unless you are concerned about namespace pollution, importing all Switchyard symbols into your program can be done with the following:

.. code-block:: python

   from switchyard.lib.userlib import *


.. _netobj:

Net object reference
====================

The *net* object is used for sending and receiving packets on network interfaces/ports.  The API documentation below is for a base class that defines the various methods on a net object; there are two classes that derive from this base class which help to implement Switchyard's test mode and Switchyard's live network mode.

.. autoclass:: switchyard.llnetbase.LLNetBase
   :members:
   :inherited-members:
   :exclude-members: set_devupdown_callback, intf_down, intf_up

   An object of this class is passed into the main function of a user's
   Switchyard program.  Using methods on this object, a user can send/receive
   packets and query the device for what interfaces are available and how
   they are configured.



.. _intf-detail:

Interface and InterfaceType reference
=====================================

The ``InterfaceType`` enumeration is referred to by the ``Interface`` class, which encapsulates information about a network interface/port.  The ``InterfaceType`` defines some basic options for types of interfaces:

.. autoclass:: switchyard.lib.interface.InterfaceType

   .. attribute:: Unknown=1
   .. attribute:: Loopback=2
   .. attribute:: Wired=3
   .. attribute:: Wireless=4

The ``Interface`` class is used to encapsulate information about a network interface:

.. autoclass:: switchyard.lib.interface.Interface
   :members:
   :undoc-members:
   :member-order: name, ethaddr, ipaddr, netmask, ipinterface, ifnum, iftype


.. _addresses:

Ethernet and IP addresses
=========================

Switchyard uses the built-in ``ipaddress`` module to the extent possible.  Refer to the Python library documentation for details on the ``IPv4Address`` class and related classes.  As noted in the source code, the ``EthAddr`` class based on source code from the POX Openflow controller.

.. autoclass:: switchyard.lib.address.EthAddr
   :members:
   :undoc-members:

There are two enumeration classes that hold special values for the IPv4 and IPv6 address families.  Note that since these classes derive from ``enum``, you must use ``name`` to access the name attribute and ``value`` to access the value (address) attribute.

.. autoclass:: switchyard.lib.address.SpecialIPv4Addr

   .. attribute:: IP_ANY = ip_address("0.0.0.0")
   .. attribute:: IP_BROADCAST = ip_address("255.255.255.255")


.. autoclass:: switchyard.lib.address.SpecialIPv6Addr

   .. attribute:: UNDEFINED = ip_address('::')
   .. attribute:: ALL_NODES_LINK_LOCAL = ip_address('ff02::1')
   .. attribute:: ALL_ROUTERS_LINK_LOCAL = ip_address('ff02::2')
   .. attribute:: ALL_NODES_INTERFACE_LOCAL = ip_address('ff01::1')
   .. attribute:: ALL_ROUTERS_INTERFACE_LOCAL = ip_address('ff01::2')


.. _pktlib:

Packet parsing and construction reference
=========================================

.. autoclass:: switchyard.lib.packet.Packet
   :members:
   :undoc-members:

   The Packet class acts as a container for packet headers.  The
   + and += operators are defined for use with the Packet class
   to add on headers (to the end of the packet).  Indexing can also
   be done with Packet objects to access individual header objects.
   Indexes may be integers (from 0 up to, but not including, the number
   of packet headers), or indexes may also be packet header class names.
   Exceptions are raised for invaliding indexing of either kind.

   The optional raw parameter can accept a bytes object, which assumed
   to be a serialized packet to be reconstructed.  The optional parameter
   first_header indicates the first header of the packet to be reconstructed,
   which defaults to Ethernet.

   >>> p = Packet()
   >>> p += Ethernet()
   >>> p[0]
   <switchyard.lib.packet.ethernet.Ethernet object at 0x10632bb08>
   >>> p[Ethernet]
   <switchyard.lib.packet.ethernet.Ethernet object at 0x10632bb08>
   >>> str(p)
   'Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP'
   >>> str(p[0])
   'Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP'
   >>> str(p[Ethernet])
   'Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP'
   >>>

To delete/remove a header, you can use the ``del`` operator as if the packet
object is a Python list::

    >>> del p[0] # delete/remove first header in packet
    >>>

You can assign new header objects to a packet by integer index, but not
by packet header class index::

    >>> p[0] = Ethernet() # assign a new Ethernet header to index 0
    >>>

Header classes
--------------

In this section, detailed documentation for all packet header classes is given.  For each header class, there are three common *instance* methods that may be useful and which are *not* documented below for clarity. They are defined in the base class ``PacketHeaderBase``.  Note that any new packet header classes that derive from ``PacketHeaderBase`` must implement these three methods.

.. autoclass:: switchyard.lib.packet.PacketHeaderBase
   :members: size, to_bytes, from_bytes


There are also three common *class* methods that are used when creating a new packet header class (see :ref:`new-packet-header-types`).

.. autoclass:: switchyard.lib.packet.PacketHeaderBase
   :members: set_next_header_class_key, add_next_header_class, set_next_header_map


------

Ethernet header
---------------

.. autoclass:: switchyard.lib.packet.Ethernet
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes

   Represents an Ethernet header with fields src (source Ethernet address),
   dst (destination Ethernet address), and ethertype (type of header to
   come in the packet after the Ethernet header).  All valid ethertypes are
   defined below.

.. autoclass:: switchyard.lib.packet.common.EtherType

   .. attribute:: IP = 0x0800
   .. attribute:: IPv4 = 0x0800
   .. attribute:: ARP = 0x0806
   .. attribute:: x8021Q = 0x8100
   .. attribute:: IPv6 = 0x86dd
   .. attribute:: SLOW = 0x8809
   .. attribute:: MPLS = 0x8847
   .. attribute:: x8021AD = 0x88a8
   .. attribute:: LLDP = 0x88cc
   .. attribute:: x8021AH = 0x88e7
   .. attribute:: IEEE8023 = 0x05dc

   The EtherType class is derived from the built-in Python Enumerated
   class type.  Note that some values start with 'x' since they must
   start with an alphabetic character to be valid in the enum.

By default, the Ethernet header addresses are all zeroes ("00:00:00:00:00:00"),
and the ethertype is IPv4.  Here is an example of creating an Ethernet header
and setting the header fields to non-default values:

>>> e = Ethernet()
>>> e.src = "de:ad:00:00:be:ef"
>>> e.dst = "ff:ff:ff:ff:ff:ff"
>>> e.ethertype = EtherType.ARP

As with all packet header classes, keyword parameters can be used to initialize header attributes:

>>> e = Ethernet(src="de:ad:00:00:be:ef", dst="ff:ff:ff:ff:ff:ff", ethertype=EtherType.ARP)


.. .. autoclass:: switchyard.lib.packet.Vlan
..    :members:
..    :undoc-members:
..    :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes

------

ARP (address resolution protocol) header
----------------------------------------

.. autoclass:: switchyard.lib.packet.Arp
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

.. autoclass:: switchyard.lib.packet.common.ArpOperation

   .. attribute:: Request = 1
   .. attribute:: Reply = 2

The ``Arp`` class is used for constructing ARP (address resolution protocol)
requests and replies.  The ``hardwaretype`` property defaults to ``Ethernet``,
so you don't need to set that when an ``Arp`` object is instantiated.  The
operation can be set using the enumerated type ``ArpOperation``, as indicated
above.  The remaining fields hold either ``EthAddr`` or ``IPv4Address`` objects,
and can be initialized using string representations of Ethernet or IPv4
addresses as appropriate.  Below is an example of creating an ARP request.
You can assume in the example that the senders Ethernet and IPv4
addresses are ``srchw`` and ``srcip``, respectively.  You can also
assume that the IPv4 address for which we are requesting the Ethernet
address is ``targetip``.

.. code-block:: python

    ether = Ethernet()
    ether.src = srchw
    ether.dst = 'ff:ff:ff:ff:ff:ff'
    ether.ethertype = EtherType.ARP
    arp = Arp(operation=ArpOperation.Request,
              senderhwaddr=srchw,
              senderprotoaddr=srcip,
              targethwaddr='ff:ff:ff:ff:ff:ff',
              targetprotoaddr=targetip)
    arppacket = ether + arp

------

IP version 4 header
-------------------

.. autoclass:: switchyard.lib.packet.IPv4
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

   Represents an IP version 4 packet header.  All properties relate to
   specific fields in the header and can be inspected and/or modified.

   Note that the field named "hl" ("h-ell") stands for "header length".
   It is the size of the header in 4-octet quantities.  It is a read-only
   property (cannot be set).

   Note also that some IPv4 header option classes are available in
   Switchyard, but are currently undocumented.

.. autoclass:: switchyard.lib.packet.common.IPProtocol

   .. attribute:: ICMP = 1
   .. attribute:: TCP = 6
   .. attribute:: UDP = 17

   The IPProtocol class derives from the Python 3-builtin Enumerated
   class type.  There are other protocol numbers defined.  See
   :py:mod:`switchyard.lib.packet.common` for all defined values.

A just-constructed IPv4 header defaults to having all zeroes for
the source and destination addresses ('0.0.0.0') and the protocol
number defaults to ICMP.  An example of creating an IPv4 header
and setting various fields is shown below:

>>> ip = IPv4()
>>> ip.srcip = '10.0.1.1'
>>> ip.dstip = '10.0.2.42'
>>> ip.protocol = IPProtocol.UDP
>>> ip.ttl = 64

------


IP version 6 header
-------------------

.. autoclass:: switchyard.lib.packet.IPv6
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

------

UDP (user datagram protocol) header
-----------------------------------

.. autoclass:: switchyard.lib.packet.UDP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

   The UDP header contains just source and destination port fields.

To construct a packet that includes an UDP header as well as some application
data, the same pattern of packet construction can be followed:

>>> p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
>>> p[UDP].src = 4444
>>> p[UDP].dst = 5555
>>> p += b'These are some application data bytes'
>>> print (p)
Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP | IPv4 0.0.0.0->0.0.0.0 UDP | UDP 4444->5555 | RawPacketContents (37 bytes) b'These are '...
>>>

Note that we didn't set the IP addresses or Ethernet addresses above, but
did set the IP protocol to correctly match the next header (UDP).  Adding
a payload to a packet is as simple as tacking on a Python ``bytes`` object.
You can also construct a ``RawPacketContents`` header, which is just a
packet header class that wraps a set of raw bytes.

------

TCP (transmission control protocol) header
------------------------------------------

.. autoclass:: switchyard.lib.packet.TCP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

   Represents a TCP header.  Includes properties to access/modify TCP
   header fields.

Setting TCP header flags can be done by assigning 1 to any of the
mnemonic flag properties:

>>> t = TCP()
>>> t.SYN = 1

To check whether a flag has been set, you can simply inspect the
the flag value:

>>> if t.SYN:
>>> ...

------

ICMP (Internet control message protocol) header (v4)
----------------------------------------------------

.. autoclass:: switchyard.lib.packet.ICMP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

   Represents an ICMP packet header for IPv4.

.. autoclass:: switchyard.lib.packet.common.ICMPType

   .. attribute:: EchoReply = 0
   .. attribute:: DestinationUnreachable = 3
   .. attribute:: SourceQuench = 4
   .. attribute:: Redirect = 5
   .. attribute:: EchoRequest = 8
   .. attribute:: TimeExceeded = 11


The icmptype and icmpcode header fields
determine the value stored in the icmpdata property.  When the icmptype
is set to a new value, the icmpdata field is *automatically* set to
the correct object.

>>> i = ICMP()
>>> print (i)
ICMP EchoRequest 0 0 (0 data bytes)
>>> i.icmptype = ICMPType.TimeExceeded
>>> print (i)
ICMP TimeExceeded:TTLExpired 0 bytes of raw payload (b'') OrigDgramLen: 0
>>> i.icmpcode
<ICMPCodeTimeExceeded.TTLExpired: 0>
>>> i.icmpdata
<switchyard.lib.packet.icmp.ICMPTimeExceeded object at 0x10d3a3308>

Notice above that when the icmptype changes, other contents in the ICMP
header object change appropriately.

To access and/or modify the *payload* (i.e., data) that comes after the ICMP header, use ``icmpdata.data``.  This object is a raw bytes object and can be accessed and or set.  For example, with many ICMP error messages, up to the first 28 bytes of the "dead" packet should be included, starting with the IPv4 header.  To do that, you must set the ``icmpdata.data`` attribute with the byte-level representation of the IP header data you want to include, as follows:

>>> i.icmpdata.data
b''
>>> i.icmpdata.data = pkt.to_bytes()[:28]
>>> i.icmpdata.origdgramlen = len(pkt)
>>> print (i)
ICMP TimeExceeded:TTLExpired 28 bytes of raw payload (b'E\x00\x00\x14\x00\x00\x00\x00\x00\x01') OrigDgramLen: 42
>>>

In the above code segment, ``pkt`` should be a Packet object that just contains the IPv4 header and any subsequent headers and data.  It must *not* include an Ethernet header.  If you need to strip an Ethernet header, you can get its index (``pkt.get_header_index(Ethernet)``), then remove the header by index (``del pkt[index]``).

Notice that above, the ``to_bytes`` method returns the byte-level representation of the IP header we're including as the payload.  The ``to_bytes`` method can be called on any packet header, or on an packet object (in which case *all* packet headers will be byte-serialized).

To set the icmpcode, a dictionary called ``ICMPTypeCodeMap`` is defined
in ``switchyard.lib.packet``.  Keys in the dictionary are of type ``ICMPType``, and values for each key is another enumerated type indicating the valid
codes for the given type.

>>> from switchyard.lib.packet import *
>>> ICMPTypeCodeMap[ICMPType.DestinationUnreachable]
<enum 'DestinationUnreachable'>

Just getting the dictionary value isn't particularly helpful, but if you
coerce the enum to a list, you can see all valid values:

>>> list(ICMPTypeCodeMap[ICMPType.DestinationUnreachable])
[ <DestinationUnreachable.ProtocolUnreachable: 2>,
  <DestinationUnreachable.SourceHostIsolated: 8>,
  <DestinationUnreachable.FragmentationRequiredDFSet: 4>,
  <DestinationUnreachable.HostUnreachable: 1>,
  <DestinationUnreachable.DestinationNetworkUnknown: 6>,
  <DestinationUnreachable.NetworkUnreachableForTOS: 11>,
  <DestinationUnreachable.HostAdministrativelyProhibited: 10>,
  <DestinationUnreachable.DestinationHostUnknown: 7>,
  <DestinationUnreachable.HostPrecedenceViolation: 14>,
  <DestinationUnreachable.PrecedenceCutoffInEffect: 15>,
  <DestinationUnreachable.NetworkAdministrativelyProhibited: 9>,
  <DestinationUnreachable.NetworkUnreachable: 0>,
  <DestinationUnreachable.SourceRouteFailed: 5>,
  <DestinationUnreachable.PortUnreachable: 3>,
  <DestinationUnreachable.CommunicationAdministrativelyProhibited: 13>,
  <DestinationUnreachable.HostUnreachableForTOS: 12> ]

Another example, but with the much simpler EchoRequest:

>>> list(ICMPTypeCodeMap[ICMPType.EchoRequest])
[<EchoRequest.EchoRequest: 0>]

If you try to set the icmpcode to an invalid value, an exception will be
raised:

>>> i = ICMP()
>>> i.icmptype = ICMPType.DestinationUnreachable
>>> i.icmpcode = 44
Traceback (most recent call last):
...
>>>

You can either (validly) set the code using an integer, or a valid enumerated
type value:

>>> i.icmpcode = 2
>>> print(i)
ICMP DestinationUnreachable:ProtocolUnreachable 0 bytes of raw payload (b'') NextHopMTU: 0
>>> i.icmpcode = ICMPTypeCodeMap[i.icmptype].HostUnreachable
>>> print (i)
ICMP DestinationUnreachable:HostUnreachable 0 bytes of raw payload (b'') NextHopMTU: 0

Below are shown the ICMP data classes, as well as any properties that can
be inspected and/or modified on them.

.. autoclass:: switchyard.lib.packet.ICMPEchoReply
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. autoclass:: switchyard.lib.packet.ICMPDestinationUnreachable
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. autoclass:: switchyard.lib.packet.ICMPSourceQuench
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. autoclass:: switchyard.lib.packet.ICMPRedirect
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. autoclass:: switchyard.lib.packet.ICMPEchoRequest
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. autoclass:: switchyard.lib.packet.ICMPTimeExceeded
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class


ICMP (Internet control message protocol) header (v6)
----------------------------------------------------

.. autoclass:: switchyard.lib.packet.ICMPv6
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

   Represents an ICMPv6 packet header.

Additional ICMPv6 headers to support the Network Discovery Protocol, [RFC4861](http://tools.ietf.org/html/rfc4861) are also available in Switchyard:

  * ICMPv6NeighborSolicitation
  * ICMPv6NeighborAdvertisement
  * ICMPv6RedirectMessage

To create an ICMPv6 packet an instance of type ``ICMPv6`` can be created.  You will want (and need) to set its ``icmptype`` appropriately, too.  For example:

>>> icmpv6 = ICMPv6()
>>> icmp.icmptype = ICMPv6Type.RedirectMessage
>>>
>>> ## OR Directly when initializing the ICMPv6 header
>>> # icmpv6 = ICMPv6(icmptype=ICMPv6Type.RedirectMessage)
>>>
>>> r = ICMPv6RedirectMessage()
>>> # or r = icmpv6.icmpdata if already assigned to ICMPv6 object
>>> r.targetaddr = IPv6Address( "::0" )
>>> r.options.append( ICMPv6OptionRedirectedHeader( redirected_packet=p ))
>>> r.options.append( ICMPv6OptionTargetLinkLayerAddress( address="00:00:00:00:00:00" )
>>>
>>> icmpv6.icmpdata = r

There are several ICMPv6 options which can be attached to these:

  * ICMPv6OptionSourceLinkLayerAddress
  * ICMPv6OptionTargetLinkLayerAddress
  * ICMPv6OptionRedirectedHeader


.. autoclass:: switchyard.lib.packet.ICMPv6NeighborSolicitation
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class


.. ### Properties
.. * targetaddr
.. * options


.. autoclass:: switchyard.lib.packet.ICMPv6NeighborAdvertisement
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

.. ICMPv6NeighborAdvertisement
.. ---------------------------
..
.. ### Properties
.. * targetaddr
.. * routerflag
.. * solicitedflag
.. * overrideflag
.. * options
..

.. autoclass:: switchyard.lib.packet.ICMPv6RedirectMessage
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class, set_next_header_class_key, set_next_header_map, add_next_header_class

..
.. ICMPv6RedirectMessage
.. ---------------------
..
.. ### Properties
.. * targetaddr
.. * destinationaddr
.. * options

.. autoclass:: switchyard.lib.packet.icmpv6.ICMPv6Option

.. autoclass:: switchyard.lib.packet.icmpv6.ICMPv6OptionSourceLinkLayerAddress

.. autoclass:: switchyard.lib.packet.icmpv6.ICMPv6OptionTargetLinkLayerAddress

.. autoclass:: switchyard.lib.packet.icmpv6.ICMPv6OptionRedirectedHeader

>>> # need to add various ICMPv6 examples


Test scenario creation
======================

.. autoclass:: switchyard.lib.testing.TestScenario
   :members:
   :undoc-members:
   :exclude-members: cancel_timer, done, get_failed_test, next, print_summary, scenario_sanity_check, testpass, wrapevent, timeout, do_setup, do_teardown, setup, teardown, lastout, failed_test_reason, write_files

.. autoclass:: switchyard.lib.testing.PacketInputEvent
   :members:

.. autoclass:: switchyard.lib.testing.PacketInputTimeoutEvent
   :members:

.. autoclass:: switchyard.lib.testing.PacketOutputEvent
   :members:

Application-layer
=================

Two static methods on the ``ApplicationLayer`` class are used to send messages up a socket application and to receive messages from socket applications.

.. autoclass:: switchyard.lib.socket.ApplicationLayer
   :members:

Switchyard's socket emulation module is intended to follow, relatively closely, the methods and attributes available in the built-in :py:mod:`socket` module.

.. autoclass:: switchyard.lib.socket.socket
   :members:


Utility functions
=================

.. autofunction:: switchyard.lib.logging.log_failure

.. autofunction:: switchyard.lib.logging.log_warn

.. autofunction:: switchyard.lib.logging.log_info

.. autofunction:: switchyard.lib.logging.log_debug

.. autofunction:: switchyard.lib.debugging.debugger
