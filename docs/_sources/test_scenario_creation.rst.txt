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

    The ``copyfromlastout`` argument can be used to address the situation in which a test scenario author wants to construct an incoming packet (that will be received by ``recv_packet``) which has the same values in some packet header fields as the most recent packet emitted.  For example, when creating a protocol stack, an application (socket) program might emit a packet with a source port number assigned by the socket emulation module.  The destination port number in an arriving packet needs to be the same as the packet that was previously emitted in order for it to be handed to the correct application program.  Thus, the ``copyfromlastout`` can be used to copy one or more packet header attributes from the *last* emitted packet to header fields in an incoming packet.

    ``copyfromlastout`` can take a tuple of 5 elements: the interface/port name out which the packet was sent, a header class name and attribute to copy *from*, and a header class name and attribute to copy *to*.  For example, if we wanted to copy the UDP source port value from the last packet emitted out port ``en1`` to the UDP destination port of the packet to be received, we could use the following::

        PacketInputEvent('en1', pkt, copyfromlastout('en1', UDP, 'src', UDP, 'dst'))

    Note that we would need to have created a ``Packet`` object named ``pkt`` which included a UDP header for this example to work correctly.


  * ``PacketInputTimeoutEvent(timeout)``

    Create an expectation that the Switchyard user program will call ``recv_packet`` but *time out* prior to receiving anything.  The timeout value is the number of seconds to wait within the test framework before raising the ``NoPackets`` exception in the user code.  In order for this test expectation to pass, the user code must correctly handle the exception and must not emit a packet.

    To force a ``NoPackets`` exception, the timeout value given to this event must be greater than the timeout value used in a call to ``recv_packet``.  Note also that the test framework will pause for the *entire* duration of the given timeout.  If a user program calls ``net.recv_packet(timeout=1.0)`` but the timeout given for a ``PacketInputTimeoutEvent`` is 5 seconds, the call to ``recv_packet`` will appear to have blocked for 5 seconds, not 1.

 
  * ``PacketOutputEvent(*args, display=None, exact=True, predicates=[], wildcard=[])``

    Create an expectation that the user program will emit packets out one or more ports/interfaces. The only required arguments are ``args``, which must be an **even number** of arguments.  For each pair of arguments given, the first is a port name (e.g., ``en0``) and the second is a reference to a packet object.  Normally, a test wishes to establish that the *same* packet has been emitted out multiple interfaces.  To do that, you could simply write::

       p = Packet()
       # fill in some packet headers ...
       PacketOutputEvent('en0', pkt, 'en1', pkt, 'en2', pkt)

    The above code expects that the same packet (named ``pkt``) will be emitted out three interfaces (``en0``, ``en1``, and ``en2``).

    By default, the PacketOutputEvent class looks for an **exact** match between the reference packet supplied to PacketOutputEvent and the packet that the user code actually emits.  In some cases, this isn't appropriate or even possible.  For example, you may want to verify that packets are forwarded correctly using standard IP (longest prefix match) forwarding rules, but you may not know the payload contents of a packet because another test element may modify them.  As another example, in IP forwarding you know that the TTL (time-to-live) should be decremented by one, but the specific value in an outgoing packet depends on the value on the incoming packet, which the test framework may not know in advance.  To handle these situations, you can supply ``exact``,  ``wildcard(s)``, and/or ``predicate(s)`` keyword arguments, as detailed below.

    * **Exact vs. subset matching**:  Setting ``exact`` to ``True`` or ``False`` determines whether *all* packet header attributes are compared (``exact=True``) or whether a limited subset are compared (``exact=False``). 

      The set of header fields that are compared when ``exact=False`` is specified are: Ethernet source and destination addresses, Ethernet ethertype field, Vlan vlanid and ethertype field, ARP target and sender protocol and hardware addresses (four fields), IPv4/IPv6 source and destination addresses and protocol, and TCP/UDP src/dst port numbers (or ICMP/ICMPv6 icmptype/icmpcode fields).  Note that in subset matching no packet payloads are compared.

    * **Wildcard fields**:  In addition to specifying the ``exact`` keyword parameter, it is possible to specify that some additional header fields should be *wildcarded*.  That is, the wildcarded header fields are allowed to contain *any* value.  Wildcards are specified using a tuple of two elements: a header class name and a field name.

      A single wildcard can be supplied (i.e., one 2-tuple) with the ``wildcard`` keyword parameter, or a *list* of 2-tuples can be supplied with the ``wildcards`` keyword.  For example, the following line of code uses subset matching (``exact=False``) and one wildcard.  For this example, assume that the packet ``pkt`` contains ``Ethernet``, ``IPv4``, and ``UDP`` headers::

          PacketOutputEvent('en0', pkt, exact=False, wildcard=(IPv4, 'src'))

      Note that for the above example, the only fields compared in the IPv4 header would be the destination address and protocol field (since other fields are already ignored with ``exact=False``).

      Here is another example that ignores source addresses in the Ethernet, IPv4 and UDP fields, leaving only two fields in the Ethernet header to be compared (dst and ethertype), two fields to be compared in the IPv4 header (dst and protocol) and one field in UDP (dst).  Again, assume that the packet ``pkt`` contains ``Ethernet``, ``IPv4``, and ``UDP`` headers::

          PacketOutputEvent('en0', pkt, exact=False, wildcards=[(Ethernet, 'src'), (IPv4, 'src'), (UDP, 'src')])


    .. note:: 

       Switchyard previously allowed certain strings (modeled on the Openflow 1.0 specification) to be used to indicate wildcarded fields.  These strings can *no longer be used* in the current version of Switchyard.  To specify wildcarded fields,  you **must** use the ``(hdrclass, attribute)`` syntax.


    * **Predicate functions**:  Lastly, predicate functions can be supplied to make *arbitrary* tests against packets.  The ``predicate`` keyword argument can take a single ``lambda`` function in the form of a string, and the ``predicates`` keyword argument can take a *list* of ``lambda`` functions, each as strings.  Each lambda given must take a single argument (the packet object to be inspected) and must yield a boolean value.  (Note that internally, each lambda definition is ``eval``\'ed by Switchyard.)

      Here is one example that checks whether the IPv4 ttl field is between 32 and 34, inclusive.  Note that this line of code contains a *single* predicate function as a string::

          PacketOutputEvent('en1', pkt, exact=False, predicate='''lambda p: p.has_header(IPv4) and 32 <= p[IPv4].ttl <= 34''')

      To provide multiple predicates, just use the ``predicates`` (plural) keyword and provide a list of lambdas-as-strings.



Test scenario examples
======================

First, here is an example of a test scenario in which a packet is constructed and is expected to be received on port ``eth1``, then sent back out the same port, unmodified.  Notice in the example that the name ``scenario`` is *required*.

.. literalinclude:: code/testscenario1.py
   :caption: A test scenario in which a packet is received then sent back out the same port.
   :language: python

Here is an additional example with a bit more complexity.  The context for this example might be that we are implementing an IPv4 router.  First, notice that we include in the scenario a static forwarding table file (``forwarding_table.txt``) to be written out when the scenario is executed.  We construct a packet destined to a particular IP address and create an expectation that it arrives on port ``eth0``.  We then construct an expectation that the packet should be forwarded out port ``eth2`` (note that according to the forwarding table, any packets destined to 2.0.0.0/8 should be forwarded out that port).  We also include a predicate function to test that the IPv4 ttl is decremented by 1.  Note that if we did not include this predicate, *any* ttl value would be accepted since we have specified ``exact=False``.  Note also that if we had set ``exact=True`` we would almost certainly need to wildcard several fields, e.g., checksums in the IPv4 and UDP headers, and would still need to include a predicate to check that ttl has been properly decremented.  Furthermore, if we were writing a test scenario for an IP router, we would also want to include expectations that the correct ARP messages were sent in order to obtain the hardware address corresponding to the next hop IP address.

.. literalinclude:: code/testscenario2.py
   :caption: A simplified IP forwarding test scenario.
   :language: python


Compiling a test scenario
=========================

A test scenario can be run *directly* with ``swyard`` or it can be *compiled* into a form that can be distributed without giving away the code which was used to construct it.  Compiled test scenario files are, by default, given a ``.srpy`` extension; uncompiled test scenarios should just be regular Python (``.py``) files.

To compile a test scenario, you can simply invoke ``swyard`` with the ``-c`` flag, as follows::

    swyard -c code/testscenario2.py 

The output from this command should be a new file named ``code/testscenario2.srpy`` containing the obfuscated test scenario.  This file can be used as the argument to the ``-t`` option when later running a Switchyard program against those tests.

.. note::

   Note that if a scenario is *compiled* using a different version of Python than the one used to *run* a test scenario (especially a different major version, e.g., 3.4 vs. 3.5), you may get some mysterious errors.  The errors are due to the fact that serialized representations of Python objects may change from one version to the next; if there are any changes, then the version used to run the test cannot correctly deserialize the various objects stored in the test scenario.
