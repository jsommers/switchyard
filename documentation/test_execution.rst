.. _runtest:

Running in the test environment
*******************************

To run Switchyard in test mode, you should have a "scenario" file that includes specific test cases to run.  These files may have an extension .srpy if they're been "compiled", but they may also just be plain Python (.py) files.

Let's say your program is named ``myhub.py``.  To invoke Switchyard in test mode and subject your program to a set of tests, at minimum you would invoke ``srpy.py`` as follows::

    $ srpy.py -t -s hubtests.srpy myhub

Note that the ``-t`` option puts ``srpy`` in test mode.  The ``-s`` option
specifies the test scenario to be executed, and the final argument is the
name of your code.  It doesn't matter whether you include the ``.py`` 
extension on the end of your program name, so::

    $ srpy.py -t -s hubtests.srpy myhub.py

would work the same as above.

When you run ``srpy`` in test mode and all tests pass, you'll see something
similar to the following::

    Results for test scenario hub tests:8 passed, 0 failed, 0 pending
    Passed:
    1   An Ethernet frame with a broadcast destination address
        should arrive on eth1
            Expected event: recv_packet Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) on eth1
    2   The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
            Expected event: send_packet(s) Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth2 and Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth0
    ... (output continues)


Note that the above output is truncated (it includes the details for 8 tests) and is shown in colored text when run in a capable terminal.  

A test scenario is composed of a series of test *expectations*.  Test expectations may be that a packet arrives on a particular interface, or that a packet is emitted out one or more interfaces, or that the user code calls ``recv_packet`` but times out.  Notice in the output above that each individual test expectation contains significant detail on the nature of the specific test.  Reading this information can help to understand what the tests are trying to accomplish, especially when a test expectation fails.

If some test expectation is not met, then the output indicates that something has gone wrong and, by default, Switchyard gives the user the standard Python pdb debugger prompt.  The motivation for immediately putting the user in pdb is to enable just-in-time debugging.  If the test output is read carefully and can be used to identify a flaw by inspecting code and data at the time of failure, then this should help to facilitate the development/testing/debugging cycle.  At least that's the hope.

Say that we've done something wrong in our code, which causes a test expectation to fail.  The output we see might be similar to the following:

::

    $ ./srpy.py -t -s examples/hubtests.py xhub.py  
    19:15:56 2015/01/10     INFO Starting test scenario examples/hubtests.py

    Results for test scenario hub tests:1 passed, 1 failed, 6 pending

    Passed:
    1   An Ethernet frame with a broadcast destination address
        should arrive on eth1
            Expected event: recv_packet Ethernet
            ab:cd:ef:ff:ff:ff->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) on eth1

    Failed:
        The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
            Expected event: send_packet(s) Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth2 and Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth0

    Pending (couldn't test because of prior failure):
    1   An Ethernet frame from 20:00:00:00:00:01 to
        30:00:00:00:00:02 should arrive on eth0
            Expected event: recv_packet Ethernet
            20:00:00:00:00:01->30:00:00:00:00:02 IP | IPv4
            192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) on eth0
    ... (output continues)

Notice in the first line of output that Switchyard shows how many tests pass, how many have
failed, and how many are *pending*.  The pending category simply means that tests cannot be run because some earlier test failed.   In the example above, the output from ``srpy`` clearly shows which test fails (test expectation 2).  When that happens, some additional explanatory text is shown, and the user is "dumped" into a pdb prompt at the point of failure.  The text output can be *a lot* to read, but the most important text concerning the failed test is reproduced just before the pdb session is started, as shown in this example:


::

    ... (more text above about scenarios that passed, failed, and are pending)

    ************************************************************
    Your code didn't crash, but a test failed.
    ************************************************************

    This is the Switchyard equivalent of the blue screen of death.
    Here (repeating what's above) is the failure that occurred:

        The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
        In particular:
            An exact match failed.   Here is the packet that failed the
            check: Ethernet ab:cd:ef:ff:ff:ff->ff:ff:ff:ff:ff:ff IP |
            IPv4 172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0
            0 (0 data bytes).  Here is exactly what I expected: Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes).

    ... (some output excluded for clarity)

    -> net.send_packet(port.name, packet)
    (Pdb) list
     25                 # send the packet out all ports *except*
     26                 # the one on which it arrived
     27                 for port in net.ports():
     28                     if port.name != input_port:
     29                         packet[0].src = 'ab:cd:ef:ff:ff:ff'
     30  ->                     net.send_packet(port.name, packet)
     31     
     32             # new line of code:
     33             # shutdown is the last thing we do
     34             net.shutdown()
    [EOF]
    (Pdb) 

Notice that the final output shows the context of the error.  An Ethernet frame should have been sent out two different ports, but the frame's contents failed to match what was expected.  Reading the specific text shows that the source Ethernet address did not match (look carefully above).  In the pdb session, when we list the code we see that the previous line foolishly set the Ethernet source address to something non-sensical.  Note that at the pdb prompt you can inspect *any* variable in order to figure out what's gone wrong, and walk up and down the call stack, if necessary.

Even more verbose output
------------------------

If you'd like even more verbose output, you can add the ``-v`` (verbose) and/or ``-d`` (debug) flags to ``srpy``.  The ``-d`` flag may be more trouble than it's worth since it enables all DEBUG-level log messages to be printed to the console.  If you're really stuck trying to figure out what's going on, however, this may be useful.

If you don't like pdb
---------------------

If you don't appreciate being dumped into the ``pdb`` debugger when something fails (maybe you're a cretin who really just likes ``printf``-style debugging?), you can add the ``--nopdb`` flag to ``srpy``.  With the ``--nopdb`` option, Switchyard will print out information about test failure, but you'll go straight back to a command-line prompt.

If you'd like to use a debugger, but just not ``pdb``, you can use the ``--nohandle`` (or ``-e``) option to tell Switchyard not to trap any exceptions, but to let them be raised normally.  You can then catch any exceptions using an alterative debugger.  For example, if you'd like to use the ``PuDB`` debugger, you could invoke ``srpy.py`` as follows::

    $ python3 -m pudb.run srpy.py --nohandle ... 

Where the ellipsis is replaced with other command-line arguments to ``srpy.py``.  
.. _debugging:

Debugging Switchyard code
=========================

When running Switchyard, especially in test mode, it is often very helpful to use the interactive Python debugger as you work out problems and figure things out.  With the ``import`` of ``switchyard.lib.common`` you get a function named ``debugger``.  You can insert calls to the ``debugger`` function where ever you want to have an interactive debugger session start up.   For example, we could modify the above template program to invoke a debugger session when ever we receive a packet.  

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

            # invoke the debugger every time we get here, which
            # should be for every packet we receive!
            debugger()

        # before exiting our main function,
        # perform shutdown on network
        net.shutdown()

As noted above, if there is a runtime error in your code, Switchyard will automatically dump you into the Python debugger (pdb) to see exactly where the program crashed and what may have caused it.  You can use any Python commands to inspect variables, and try to understand the state of the program at the time of the crash.
