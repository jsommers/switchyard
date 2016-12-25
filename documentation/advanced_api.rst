.. _advanced:

Advanced API topics
*******************

This section introduces two additional, and slightly advanced topics related to Switchyard APIs: creating new packet header types and using Switchyard's application-layer socket emulation capabilities.

.. _new-packet-header-types:

.. index:: packet headers, new packet header types

Creating new packet header types
================================

For some Switchyard programs, it can be useful to create new packet header types.  For example, say you are implementing a simplified dynamic routing protocol within an IP router.  You might want to be able to create a new packet header for your routing protocol, and have those packet headers integrate nicely with the existing Switchyard ``Packet`` class and the rest of the Switchyard framework.

.. todo:: finish this: use example of routing protocol and cook up some examples to show serialization, deserialization (i.e., use of class methods in PacketHeader class)

.. _app-layer:

.. index:: socket emulation, application layer, end-host protocol stack

Application layer socket emulation and creating full protocol stacks
====================================================================


.. figure:: applayer.*
   :align: center
   :figwidth: 80%



.. figure:: applayer_detail.*
   :align: center
   :figwidth: 80%

.. todo:: need to discuss basic idea of ApplicationLayer class, how to start up swyard in test/live environments, how to make socket program that uses Switchyard, etc.  Use UDP client example (and also show a UDP server example using bind()).  Maybe also cook up and try a simple TCP client example.

.. todo:: maybe also talk about firewalling here?

.. todo:: be clear about limitations wrt UDP, no TCP server, maybe TCP client?
