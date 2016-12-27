.. _advanced:

Advanced API topics
*******************

This section introduces two additional, and slightly advanced topics related to Switchyard APIs: creating new packet header types and using Switchyard's application-layer socket emulation capabilities.

.. _new-packet-header-types:

.. index:: packet headers, new packet header types

Creating new packet header types
--------------------------------

For some Switchyard programs, it can be useful to create new packet header types.  For example, say you want to implement a simplified dynamic routing protocol within an IP router.  You might want to be able to create a new packet header for your routing protocol, and have those packet headers integrate well with the existing Switchyard ``Packet`` class.  Similarly, say you want to implement a simplified Ethernet spanning tree protocol: being able to create a new packet header for carrying spanning tree information would be helpful.

Before discussing how to create a new packet header class that integrates well with the rest of Switchyard, it is important to note that it is not strictly *required* to create a new packet header class for either of the above example projects.  Instead, you could use the existing ``RawPacketContents`` header, which has one attribute (``data``), a ``bytes`` object.  To use a ``RawPacketContents`` header, you would need to handle all *packing* ("serialization") and *unpacking* ("deserialization") of header fields to and from the bytes object explicitly in your code.  While this approach "works", it leads to a less cohesive and encapsulated design and to code that may be a bit more difficult to debug because it is not well-integrated into Switchyard.

If you want to work with Switchyard's packet header and packet classes, there are two main steps to take:

  * First, create a new class that derives from ``PacketHeaderBase``.  There are two required methods (``to_bytes()`` and ``from_bytes()``) that you'll need to write, and some other things to be aware of when writing this class.
  * Second, some configuration to the packet header class that appears *before* your header in a normal packet needs to be done.  This is just a matter of a couple method class to do the configuration.

These steps are described below along with short examples and a longer (full) example follows.

Creating a new packet header class
""""""""""""""""""""""""""""""""""

As mentioned above, to create a new packet header class you must create a class that derives from ``PacketHeaderBase``.  There are two required methods to implement:

``to_bytes()``
  This method returns a serialized packet header in the form of a ``bytes`` object.  One of the easiest ways to "pack" a set of values into a ``bytes`` object is to use Python's ``struct`` module (refer to the Python library documentation for details).  The examples in this section use ``struct``.

``from_bytes(raw)``
  This method accepts a bytes object as a parameter and returns a ``bytes`` object.  It populates attributes in the packet header by unpacking the ``bytes`` object.  The method should raise an exception if there aren't enough bytes to fully reconstruct the packet header.  Any part of the ``bytes`` object passed as a parameter that *aren't* used (i.e., there are more bytes passed in to the method than are necessary to reconstruct the header) should be returned by the method.  As with the ``to_bytes()`` method, Python's ``struct`` module is useful for performing the unpacking.

There is one restriction when implementing a new packet header class:

  * The ``__init__`` method should only take *optional* parameters.  Switchyard assumes that a packet header object can be constructed which assigns attributes to reasonable default values, thus no explicit initialization parameters can be required by the constructor (``__init__``). Moreover, for compatibility with keyword-style attribute assignment in packet header classes, a ``kwargs`` parameter should be included and passed to the base class initialization method call.

Below is an example of a new packet header called ``UDPPing`` that contains a single attribute: ``sequence``.  This packet header is designed to be included in a packet following a ``UDP`` header.  Besides implementing an ``__init__`` method (which optionally accepts an initial sequence value) and the two required methods, there are property getter and setter methods for ``sequence`` and a string conversion magic method.  Note that we've decided to store the sequence value as a network-byte-order (big endian) unsigned 16 bit value (this is what the ``!H`` signifies for ``_PACKFMT``: refer to the ``struct`` Python library documentation):

.. literalinclude:: code/udpappheader.py
   :language: python
   :lines: 1-32

Given the way the ``UDPPing`` packet header class has been defined, we can either set the ``sequence`` explicitly with the property setter, pass a value into the ``__init__`` method, or use keyword syntax:

.. code-block:: none

    >>> up1 = UDPPing()
    >>> print(up1)
    UDPPing seq: 0
    >>> up2 = UDPPing()
    >>> up2.sequence = 13
    >>> print(up2)
    UDPPing seq: 13
    >>> up3 = UDPPing(sequence=42)
    >>> print(up3)
    UDPPing seq: 0

If we now create a full ``Packet`` object, we might do something like the following.  Note that our code both *serializes* and *deserializes* the packet.  We do this to test (at least in a limited way) that our ``to_bytes()`` and ``from_bytes()`` methods work as expected.  Here is the code:

.. literalinclude:: code/udpappheader.py
   :language: python
   :lines: 46-56
   :dedent: 4

And here is the output:

.. code-block:: none

    Before serialize/deserialize: Ethernet 11:22:11:22:11:22->22:33:22:33:22:33 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP 55555->12345 | UDPPing seq: 42
    After deserialization: Ethernet 11:22:11:22:11:22->22:33:22:33:22:33 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP 55555->12345 | RawPacketContents (2 bytes) b'\x00*'

Notice that the first line of output shows the full packet as we expect, including the final ``UDPPing`` header.  The next line to follow, however, shows that the packet has been reconstructed with the final header as ``RawPacketContents``, not ``UDPPing``.  What happened?

Configuring the lower-layer header class
""""""""""""""""""""""""""""""""""""""""

What happened in the above example is that Switchyard does not have enough information to know that the bytes that follow the UDP header should be interpreted as the contents of a ``UDPPing`` packet.  It is possible, however, to give this information to Switchyard.  

Switchyard assumes that there exists one attribute in a packet header that can be used to determine how to map *values* of that attribute to a *packet header class*.  Not surprisingly, these mappings are stored in the form of a Python dictionary.  For example, by default the ``Ethernet`` class is configured to use the value of the ``ethertype`` attribute as a lookup *key* to determine the type of the packet header that follows.  It contains a few initial mappings, including a mapping from ``EtherType.IP`` to ``IPv4``.  Similarly, the ``IPv4`` class uses values in the ``protocol`` attribute as keys to look up the packet header type that should come next.  

Switchyard contains methods to make it possible to change the *attribute* on which lookups are performed, to *add* new mappings from a value on the mapped attribute to a packet header class, and to *completely (re)initialize* the mappings from attribute values to packet header classes.  Noting that one should, of course, use care when modifying any existing mappings or when modifying the attribute on which mappings are performed, here are the three *class* methods available on ``PacketHeaderBase``-derived classes:

``set_next_header_class_key(attr)``
  This method is used to specify the *attribute* on which lookups to determine the next header class should be performed.  Switchyard-provided header classes contain sensible defaults for this value.  For example, with ``Ethernet`` this attribute is preconfigured as ``ethertype``, for ``IPv4`` this attribute is configured as ``protocol``, and with ``UDP`` and ``TCP`` this attribute is configured as ``dst`` (i.e., the destination port is used as the key).  Most other headers are configured with the empty string, indicating that no "next header" is assumed by Switchyard.

``add_next_header_class(attr, hdrcls)``
  This method is used to add a new attribute value-header class mapping to the next header mapping dictionary.  

``set_next_header_map(mapdict)`` 
  This method can be used to replace any previous dictionary with a new one.  Switchyard-provided header classes are configured with sensible defaults.  Use with care, since a replacement of a next header class mapping in a highly dependend-upon header class (e.g, ``IPv4``) will likely break lots of things.

.. note:: 
   
   A key limitation of Switchyard, currently, is that arbitrary values for core protocol number enumerations (in particular, ``EtherType`` and ``IPProtocol``) cannot be dynamically added and/or modified because Python's ``enum`` types are constant once created.  This makes it impossible, at present, to use *arbitrary* protocol numbers for new layer 3 or 4 protocols and packet header types.  This will be changed in a future version of Switchyard.  In the meantime, a workaround is to use an existing protocol number which is not used in the next header map.  For example, if you are implementing a routing protocol on top of IPv4, you could use ``IPProtocol.OSPF`` as the protocol number for your (non-OSPF) protocol since Switchyard does not have any current mapping between that protocol number and a packet header class.  


Building on the previous example with ``UDPPing``, if we add *one* line of code to, in a sense, *register* a particular UDP destination port as being associated with the ``UDPPing`` protocol, the final couple bytes can get properly interpreted and deserialized into the right packet header (notice the first line of code, which is the *only* difference with the previous example):

.. literalinclude:: code/udpappheader.py
   :language: python
   :lines: 60-70
   :dedent: 4

Here is the output, showing 

.. code-block:: none

    Before serialize/deserialize: Ethernet 11:22:11:22:11:22->22:33:22:33:22:33 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP 55555->12345 | UDPPing seq: 0
    After deserialization: Ethernet 11:22:11:22:11:22->22:33:22:33:22:33 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP 55555->12345 | UDPPing seq: 0


.. _app-layer:

.. index:: socket emulation, application layer, end-host protocol stack

Application layer socket emulation and creating full protocol stacks
--------------------------------------------------------------------

``import switchyard.lib.socket as socket``

.. figure:: applayer.*
   :align: center
   :figwidth: 80%



.. figure:: applayer_detail.*
   :align: center
   :figwidth: 80%

.. todo:: need to discuss basic idea of ApplicationLayer class, how to start up swyard in test/live environments, how to make socket program that uses Switchyard, etc.  Use UDP client example (and also show a UDP server example using bind()).  Maybe also cook up and try a simple TCP client example.

.. todo:: maybe also talk about firewalling here?

.. todo:: be clear about limitations wrt UDP, no TCP server, maybe TCP client?
