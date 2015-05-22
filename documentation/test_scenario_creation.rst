Test scenario creation
**********************

In some situations, you may be given a set of tests to run in order to have some confidence that your program works correctly.  What if nobody has written a set of tests for poor you?  Never fear: creating a test scenario is pretty straightforward.

A test scenario is simply a Python program that exports one symbol (variable name) called ``scenario``, which refers to an instance of the class ``Scenario``.  A ``Scenario`` object contains a series of *test expectations*.  These expectations may be one of three types:

 * A particular packet should arrive on a particular interface/port
 * A particular packet should be emitted out one or more ports
 * The user code should *time out* when calling ``recv_packet`` because no packets are available

The class ``Scenario`` is defined in the module ``switchyard.lib.testing``.  A scenario describes some imaginary network device (i.e., a switch or router) and some series of expectations of how a user program should behave if packets arrive on particular ports, etc.  The methods available on the 
Scenario class reflect these basic requirements:

.. py:class:: switchyard.lib.testing.Scenario(name)

   Initialize a new test scenario.  The name can be any meaningful
   description of the given test sequence.

   .. py:method:: add_interface(name, ethaddr, ipaddr=None, netmask=None)

      Add an interface to the imaginary network device that is the subject
      of this test sequence.  

   .. py:method:: expect(expectation, description)

      Add a new expectation to the test scenario.  The expectation argument must
      be an object of type ``PacketInputEvent``, ``PacketInputTimeoutEvent``, or 
      ``PacketOutputEvent``.
      Note that the order of adding expectations via calls to ``expect`` is critical:
      add expectations in the "right" order!

The three "event" classes set up the specific expectations for each test, as described next.

.. py:class:: switchyard.lib.testing.PacketInputEvent(portname, packet, display=None)

   Create an expectation that a particular packet will arrive on a port named ``portname``.  
   The packet must be an instance of the Switchyard ``Packet`` class.  The ``portname``
   is just a string like ``eth0``.

   The ``display`` argument indicates whether a particular header in the packet should
   be emphasized on output when Switchyard shows test output to a user.  By default,
   all headers are shown.  If a test creator wants to ignore the Ethernet header but
   emphasize the IPv4 header, he/she could use the argument ``display=IPv4``.  That is,
   the argument is just the class name of the packet header to be emphasized.

.. py:class:: switchyard.lib.testing.PacketInputTimeoutEvent(timeout)

   Create an expectation that the Switchyard user program will *time out* prior to receiving 
   a packet.  The timeout value is the number of seconds to wait within the test framework
   before raising the ``NoPackets`` exception in the user code.  In order for this test expectation
   to pass, the user code must correctly handle the exception and must not emit a packet.

.. py:class:: switchyard.lib.testing.PacketOutputEvent(*args, display=None, exact=True, wildcard=[], predicates=[])

   Create an expectation that the user program will emit packets out one or more ports/interfaces.
   The only required arguments are ``args``, which is an *even number* of arguments where, for
   each pair of arguments, the first is a port name (e.g., eth0) and the second is a reference to
   a packet object.  Normally, a test wishes to establish that the *same* packet has been emitted
   out multiple interfaces.  To do that, you could simply write::

       p = Packet()
       # fill in some packet headers ...
       PacketOutputEvent("eth0", p, "eth1", p, "eth2", p)

   The above code expects that the same packet (named p) will be emitted out three interfaces (eth0, eth1, and eth2).

   By default, the PacketOutputEvent class looks for an **exact** match between the reference
   packet supplied to PacketOutputEvent and the packet that the user code actually emits.  In some
   cases, this isn't appropriate or even possible.  For example, you may want to verify that packets
   are forwarded correctly using standard IP (longest prefix match) forwarding rules, but you may not
   know the payload contents of a packet because another test element may modify them.  As another
   example, in IP forwarding you know that the TTL (time-to-live) should be decremented by one, but
   the specific value in an outgoing packet depends on the value on the incoming packet, which the
   test framework may not know in advance.  To handle these situations, you can supply ``exact``, ``wildcard``, and/or ``predicates`` arguments.

    * Setting ``exact`` to ``False`` causes only certain header fields to be compared to verify a "match".  In particular: Ethernet source and destination addresses, Ethernet ethertype field, IPv4 source and destination addresses and protocol, and TCP or UDP port numbers (or ICMP type/code fields).  

    * When specifying that matches should not be exact (i.e., ``exact=False``), some header field
      comparisons can be "wildcarded" causing *any* value in an outgoing packet to match correctly.
      To indicate that some fields should be wildcarded, you can supply one or more strings in the ``wildcard`` argument.  In particular: dl_src and dl_dst correspond to Ethernet source and destination addresses ("data-link" addresses), dl_type corresponds to the Ethernet ethertype,
      nw_src, nw_dst, and nw_proto correspond to the IPv4 source, destination, and protocol ("nw" means network layer), and tp_src and tp_dst correspond to UDP/TCP ports (or ICMP type/code) ("tp" means transport layer). (Note that the field names are borrowed from the Openflow specification.)

      Lastly, predicate functions can be supplied to make *arbitrary* tests against packets.  The
      ``predicates`` argument can take a list of either ``lambda`` functions or strings that contain
      lambda function definitions (they're ``eval``\'ed internally by Switchyard).  There is one
      parameter given to the ``lambda``, which is the packet to be evaluated.


Test scenario example
=====================

Below is an example of a creating two test expectations for a network hub device:

.. code-block:: python

    from switchyard.lib.testing import Scenario, PacketInputEvent, PacketOutputEvent
    from switchyard.lib.packet import *

    def create_scenario():
        s = Scenario("hub tests")
        s.add_interface('eth0', '10:00:00:00:00:01')
        s.add_interface('eth1', '10:00:00:00:00:02')
        s.add_interface('eth2', '10:00:00:00:00:03')

        # test case 1: a frame with broadcast destination should get sent out all ports except ingress
        testpkt = Ethernet() + IPv4() + ICMP()
        testpkt[0].src = "30:00:00:00:00:02"
        testpkt[0].dst = "ff:ff:ff:ff:ff:ff"
        testpkt[1].src = "172.16.42.2"
        testpkt[1].dst = "255.255.255.255"

        # expect that the packet should arrive on port eth1
        s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth1")

        # expect that the packet should be sent out ports eth0 and eth2 (but *not* eth1)
        s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet), "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")

        return s

    # the name scenario here is required --- the Switchyard framework will
    # explicitly look for an object named scenario in the test description file.
    scenario = create_scenario()


Compiling a test scenario
=========================

A test scenario can be run *directly* with ``srpy``, or it can be *compiled* into a form that can be distributed without giving away the code that was used to construct the reference packets.  To compile a test scenario, you can simply invoke ``srpy`` with the ``-c`` flag, as follows::

    ./srpy.py -c -s examples/hubtests.py

The output from this command should be a new file named ``hubtests.srpy`` containing the obfuscated test scenario.  This file can be used as the argument to the ``-s`` option, just as you would supply a "normal" Python (.py) test scenario file.
