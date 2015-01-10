.. _apiref: 

API Reference
*************

The "net" object
================

.. autoclass:: switchyard.switchy_real.PyLLNet 
   :members:
   :inherited-members:
   :exclude-members: set_devupdown_callback

   An object of this class is passed into the main function of a user's
   Switchyard program.  Using methods on this object, a user can send/receive
   packets and query the device for what interfaces are available and how
   they are configured.

.. _pktlib:

Packet parsing and construction
===============================

.. autoclass:: switchyard.lib.packet.Packet
   :members:
   :undoc-members:

   The Packet class acts as a container for packet headers.  The
   + and += operators are defined for use with the Packet class
   to add on headers (to the end of the packet).  Indexing can also
   be done with Packet objects to access individual header objects.

   >>> p = Packet()
   >>> p += Ethernet()
   >>> p[0]
   <switchyard.lib.packet.ethernet.Ethernet object at 0x10632bb08>
   >>> str(p)
   'Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP'
   >>> str(p[0])
   'Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP'
   >>> 

Header classes
--------------

In this section, detailed documentation for all packet header classes is
given.  For each header class, there are three common methods that may be
useful and which are *not* documented below for clarity:

 * ``size()``: returns the number of bytes that the header would consist of when serialized to wire format
 * ``to_bytes()``: returns the serialized (wire format) representation of the packet as a byte string
 * ``from_bytes(b)``: parses a byte string representing this packet header and constructs the various header fields from the raw bytes

.. autoclass:: switchyard.lib.packet.Ethernet
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes

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


.. autoclass:: switchyard.lib.packet.Vlan
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes

.. autoclass:: switchyard.lib.packet.IPv4
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

.. autoclass:: switchyard.lib.packet.common.IPProtocol

   .. attribute:: ICMP = 1
   .. attribute:: TCP = 6
   .. attribute:: UDP = 17

   The IPProtocol class derives from the Python 3-builtin Enumerated
   class type.  There are other protocol numbers defined.  See 
   switchyard.lib.packet.common for all defined values.

.. autoclass:: switchyard.lib.packet.UDP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

.. autoclass:: switchyard.lib.packet.TCP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

.. autoclass:: switchyard.lib.packet.ICMP
   :members:
   :undoc-members:
   :exclude-members: next_header_class, pre_serialize, size, to_bytes, from_bytes, checksum

.. autoclass:: switchyard.lib.packet.common.ICMPType

   .. attribute:: EchoReply = 0
   .. attribute:: DestinationUnreachable = 3
   .. attribute:: SourceQuench = 4
   .. attribute:: Redirect = 5
   .. attribute:: EchoRequest = 8
   .. attribute:: TimeExceeded = 11

.. autoclass:: switchyard.lib.packet.ICMPEchoReply
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class

.. autoclass:: switchyard.lib.packet.ICMPDestinationUnreachable
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class

.. autoclass:: switchyard.lib.packet.ICMPSourceQuench
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class

.. autoclass:: switchyard.lib.packet.ICMPRedirect
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class

.. autoclass:: switchyard.lib.packet.ICMPEchoRequest
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class

.. autoclass:: switchyard.lib.packet.ICMPTimeExceeded
   :members:
   :inherited-members:
   :undoc-members:
   :exclude-members: to_bytes, from_bytes, size, pre_serialize, next_header_class


.. FIXME: do something about this, later

.. Test scenario creation
.. ======================
.. 
.. .. autoclass:: switchyard.lib.testing.Scenario
..    :members:


Utility functions
=================

.. automodule:: switchyard.lib.common
   :members:
   :exclude-members: setup_logging, LLNetBase

.. autofunction:: switchyard.lib.debug.debugger

