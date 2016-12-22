.. _test-scenario-creation:

Test scenario creation
**********************

Writing tests to determine whether a piece of code behaves as expected is an important part of the software development process.  With Switchyard, it is possible to create a set of tests that verify whether a program attempts to receive packets when it should and sends the *right* packet(s) out the *right* ports.  This section describes how to construct such tests.

A *test scenario* is Switchyard's term for a series of tests that verify a program's behavior.  A test scenario is simply a Python source code file that includes a particular variable name (symbol) called ``scenario``, which must refer to an instance of the class ``TestScenario``.  A ``TestScenario`` object contains the basic configuration for an imaginary network device along with an ordered series of *test expectations*.  These expectations may be one of three types:

  * that a particular packet should arrive on a particular interface/port,
  * that a particular packet should be emitted out one or more ports, and
  * that the user program should *time out* when calling ``recv_packet`` because no packets are available.

To start off, here is an example of an *empty* test scenario:

.. literalinclude:: code/emptytestscenario.py
   :caption: An empty test scenario.
   :language: python

If we run ``swyard`` in test mode using this test description and *any* Switchyard program, here's the output we should see:

.. code-block:: none

    Results for test scenario test example: 0 passed, 0 failed, 0 pending


    All tests passed!

Notice that in the above example code, we assigned the instance of the ``TestScenario`` class to a variable named ``scenario``.  An assignment to this variable name is **required**.  If it is not found, you'll get an ``ImportError`` exception.  Notice also that there's one parameter to ``TestScenario``: this value can be any meaningful description of the test scenario.

There are two methods on ``TestScenario`` that are used to configure the test environment:

  * ``add_interface(name, macaddr, ipaddr=None, netmask=None, **kwargs)``

    This method adds an interface/port to an imaginary network device that is the subject of the test scenario.  For example, if you are creating a test for an IP router and you want to verify that a packet received on one port is forwarded out another (different) port on the device, you will need to add *at least* two interfaces.  Arguments to the ``add_interface`` method are used to specify the interface's name (e.g., ``en0``), its hardware Ethernet (MAC) address, and its (optional) IP address and netmask.  

    Two optional keyword arguments can also be given: ``ifnum`` can be used to explicitly specify the number (integer) associated with this interface, and ``iftype`` can be used to explicitly indicate the type of the interface.  A value from the enumeration ``InterfaceType`` must be used, e.g., ``Wired``, ``Wireless``, ``Loopback``, or ``Unknown``. The type of an interface defaults to ``InterfaceType.Unknown``.

  * ``add_file(filename, text)``

    It is sometimes necessary to make sure that certain text files are available during a test that a user program expects, e.g., a static forwarding table for an IP router.  This method can be used to specify that a file with the name ``filename`` and with contents ``text`` should be written to the current directory when the test scenario is run.

There is one method that creates a new test expectation in the test scenario:

  * ``expect(expectation_object, description)``

    This method adds a new expected event to the test scenario.  The first parameter must be an object of type ``PacketInputEvent``, ``PacketInputTimeoutEvent``, or ``PacketOutputEvent`` (each described below).  The order in which expectations are added to a test scenario is critical: be certain that they're added in the right order for the test you want to accomplish!

    The description parameter is a short text description of what this test step is designed to accomplish.  In ``swyard`` test output, this description is what is printed for each step in both the abbreviated and verbose output: make sure it is descriptive enough so that the purpose of the test can be easily understood.  At the same time, try to keep the text short so that it isn't overwhelming to a reader.


The three *event* classes set up the specific expectations for each test, as described next.

  * ``PacketInputEvent(portname, packet, display=None, copyfromlastout=None)``

    Create an expectation that a particular packet will arrive and be received on a port named ``portname``.  The packet must be an instance of the Switchyard ``Packet`` class.  The ``portname`` is just a string like ``eth0``.  This port/interface must have previously be configured in the test scenario using the method ``add_interface`` (see above).

    The ``display`` argument indicates whether a particular header in the packet should be emphasized on output when Switchyard shows test output to a user.  By default, all headers are shown.  If a test creator wants to ignore the Ethernet header but emphasize the IPv4 header, he/she could use the argument ``display=IPv4``.  That is, the argument is just the class name of the packet header to be emphasized.

    The ``copyfromlastout`` argument can be used to address the situation in which a test scenario does not know some of the header values in the most recently sent packet, but must construct a new input packet that contains those (unknown) values.  This is a bit of a corner case, but comes up when 



  * ``PacketInputTimeoutEvent(timeout)``

    Create an expectation that the Switchyard user program will call ``recv_packet`` but *time out* prior to receiving anything.  The timeout value is the number of seconds to wait within the test framework before raising the ``NoPackets`` exception in the user code.  In order for this test expectation to pass, the user code must correctly handle the exception and must not emit a packet.

    Note that the test framework will pause for the *entire* duration of the given timeout.  If a user program calls ``net.recv_packet(timeout=1.0)`` but the timeout given for a ``PacketInputTimeoutEvent`` is 5 seconds, the call to ``recv_packet`` will appear to have blocked for 5 seconds, not 1.  So to force a ``NoPackets`` exception, the timeout value given to this event must be greater than the timeout value used in a call to ``recv_packet``.
 
  * ``PacketOutputEvent(*args, display=None, exact=True, predicates=[], wildcard=[])``

    Create an expectation that the user program will emit packets out one or more ports/interfaces. The only required arguments are ``args``, which must be an **even number** of arguments.  For each pair of arguments given, the first is a port name (e.g., eth0) and the second is a reference to a packet object.  Normally, a test wishes to establish that the *same* packet has been emitted out multiple interfaces.  To do that, you could simply write::

       p = Packet()
       # fill in some packet headers ...
       PacketOutputEvent("eth0", p, "eth1", p, "eth2", p)

    The above code expects that the same packet (named ``p``) will be emitted out three interfaces (eth0, eth1, and eth2).

    By default, the PacketOutputEvent class looks for an **exact** match between the reference packet supplied to PacketOutputEvent and the packet that the user code actually emits.  In some cases, this isn't appropriate or even possible.  For example, you may want to verify that packets are forwarded correctly using standard IP (longest prefix match) forwarding rules, but you may not know the payload contents of a packet because another test element may modify them.  As another example, in IP forwarding you know that the TTL (time-to-live) should be decremented by one, but the specific value in an outgoing packet depends on the value on the incoming packet, which the test framework may not know in advance.  To handle these situations, you can supply ``exact``,  ``wildcard``, and/or ``predicates`` arguments.  

    * Setting ``exact`` to ``False`` causes only certain header fields to be compared to verify a "match".  In particular: Ethernet source and destination addresses, Ethernet ethertype field, IPv4 source and destination addresses and protocol, and TCP or UDP port numbers (or ICMP type/code fields).  

    * When specifying that matches should not be exact (i.e., ``exact=False``), some header field
      comparisons can be "wildcarded" causing *any* value in an outgoing packet to match correctly.
      To indicate that some fields should be wildcarded, you can supply one or more strings in the ``wildcard`` argument.  In particular: dl_src and dl_dst correspond to Ethernet source and destination addresses ("data-link" addresses), dl_type corresponds to the Ethernet ethertype,
      nw_src, nw_dst, and nw_proto correspond to the IPv4 source, destination, and protocol ("nw" means network layer), and tp_src and tp_dst correspond to UDP/TCP ports (or ICMP type/code) ("tp" means transport layer). (Note that the field names are borrowed from the Openflow specification.)

      Lastly, predicate functions can be supplied to make *arbitrary* tests against packets.  The
      ``predicates`` argument can take a list of either ``lambda`` functions or strings that contain
      lambda function definitions (they're ``eval``\'ed internally by Switchyard).  There is one
      parameter given to the ``lambda``, which is the packet to be evaluated.


.. todo:: new, more general wildcarding example

.. todo:: may need to modify wildcard stuff to only have limited fields compared, by default, much like OF, and allow wildcarding along those lines


Test scenario example
=====================

Below is an example of a creating two test expectations for a network hub device:

.. code-block:: python

    from switchyard.lib.userlib import *

    def create_scenario():
        s = TestScenario("hub tests")
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

A test scenario can be run *directly* with ``swyard``, or it can be *compiled* into a form that can be distributed without giving away the code that was used to construct the reference packets.  To compile a test scenario, you can simply invoke ``swyard`` with the ``-c`` flag, as follows::

    swyard -c examples/hubtests.py

The output from this command should be a new file named ``hubtests.srpy`` containing the obfuscated test scenario.  This file can be used as the argument to the ``-c`` option.
