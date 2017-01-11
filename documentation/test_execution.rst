.. _runtest:

Running in the test environment
*******************************

To run Switchyard in test mode, a *test scenario* file is needed.  This file includes specifications of various events (sending particularly crafted packets, receiving packets, etc.) that a Switchyard program is expected to do if it behaves correctly.  Also needed, of course, is the Switchyard program you wish to test.  The test scenario files may be regular Python (``.py``) files, but they may alternatively have an extension ``.srpy`` if they have been *compiled*.  For details on creating and compiling test scenarios, see :ref:`test-scenario-creation`.

Let's say your program is named ``myhub.py``.  To invoke Switchyard in test mode and subject your program to a set of tests, at minimum you would invoke ``swyard`` as follows::

    $ swyard -t hubtests.srpy myhub

Note that the ``-t`` option puts ``swyard`` in test mode.  The argument to the ``-t`` option should be the name of the test scenario to be executed, and the final argument is the name of your code.  It doesn't matter whether you include the ``.py`` extension on the end of your program name, so::

    $ swyard -t hubtests.srpy myhub.py

would work the same as above.

Test output
^^^^^^^^^^^

When you run ``swyard`` in test mode and all tests pass, you'll see something similar to the following:

.. code-block:: none
   :caption: Abbreviated (normal) test output.

    Results for test scenario hub tests: 8 passed, 0 failed, 0 pending

    Passed:
    1   An Ethernet frame with a broadcast destination address
        should arrive on eth1
    2   The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
    3   An Ethernet frame from 20:00:00:00:00:01 to
        30:00:00:00:00:02 should arrive on eth0
    4   Ethernet frame destined for 30:00:00:00:00:02 should be
        flooded out eth1 and eth2
    5   An Ethernet frame from 30:00:00:00:00:02 to
        20:00:00:00:00:01 should arrive on eth1
    6   Ethernet frame destined to 20:00:00:00:00:01 should be
        flooded out eth0 and eth2
    7   An Ethernet frame should arrive on eth2 with destination
        address the same as eth2's MAC address
    8   The hub should not do anything in response to a frame
        arriving with a destination address referring to the hub
        itself.

    All tests passed!


Note that the above output is an abbreviated version of test output and is normally shown in colored text when run in a capable terminal.

Verbose test output
^^^^^^^^^^^^^^^^^^^

If you invoke ``swyard`` with the ``-v`` (verbose) option, the test output includes quite a bit more detail:

.. code-block:: none
   :caption: Verbose test output.

    Results for test scenario hub tests: 8 passed, 0 failed, 0 pending

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
            data bytes) out eth0 and Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth2
    3   An Ethernet frame from 20:00:00:00:00:01 to
        30:00:00:00:00:02 should arrive on eth0
            Expected event: recv_packet Ethernet
            20:00:00:00:00:01->30:00:00:00:00:02 IP | IPv4
            192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) on eth0

    ... 

Note that the above output has been truncated --- output would normally be shown for all tests.  When invoked with the *verbose* option, individual tests show exactly what packets would be expected (either as input to a device or as output from it).  

*Test scenario* descriptions that drive test executions as shown here are composed of a series of test *expectations*.  Test expectations may be that a packet is received on a particular port, or that a packet is emitted out one or more ports, or that the user code calls ``recv_packet`` but times out (and thus nothing is received).  Both the abbreviated and verbose test output shown above contain brief descriptions of the nature of each test.  In the verbose output, packet details related to each test are also shown.  Reading this information can help to understand what the tests are trying to accomplish, especially when a test expectation fails.

When a test fails
^^^^^^^^^^^^^^^^^

If some test expectation is not met, then the output indicates that something has gone wrong and, by default, Switchyard gives the user the standard Python pdb debugger prompt.  The motivation for immediately putting the user in pdb is to enable just-in-time debugging.  If the test output is read carefully and can be used to identify a flaw by inspecting code and data at the time of failure, then this should help to facilitate the development/testing/debugging cycle.  At least that's the hope.

Say that we've done something wrong in our code which causes a test expectation to fail.  The output we see might be similar to the following (note that to create the output below, we've used the full set of hub device tests, but the code we've used is the broken code we started with in :ref:`coding` that sends any packet back out the same port that it arrived on):

.. code-block:: none
   :caption: Normal (abbreviated) test output when one test fails. 

    Results for test scenario hub tests: 1 passed, 1 failed, 6 pending


    Passed:
    1   An Ethernet frame with a broadcast destination address
        should arrive on eth1


    Failed:
        The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
            Expected event: send_packet(s) Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4 | ICMP out
            eth0 and Ethernet 30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP |
            IPv4 | ICMP out eth2


    Pending (couldn't test because of prior failure):
    1   An Ethernet frame from 20:00:00:00:00:01 to
        30:00:00:00:00:02 should arrive on eth0
    2   Ethernet frame destined for 30:00:00:00:00:02 should be
        flooded out eth1 and eth2
    3   An Ethernet frame from 30:00:00:00:00:02 to
        20:00:00:00:00:01 should arrive on eth1
    4   Ethernet frame destined to 20:00:00:00:00:01 should be
        flooded out eth0 and eth2
    5   An Ethernet frame should arrive on eth2 with destination
        address the same as eth2's MAC address
    6   The hub should not do anything in response to a frame
        arriving with a destination address referring to the hub
        itself.

    ... (output continues)

Notice in the first line of output that Switchyard shows how many tests pass, how many have
failed, and how many are *pending*.  The pending category simply means that tests cannot be run because some earlier test failed.   In the example above, the output from ``swyard`` clearly shows which test fails; when that happens, some additional explanatory text is shown, and a debugger session is started as close as possible to the point of failure.  When not run in verbose mode, Switchyard will show abbreviated test descriptions for any passed tests and any pending tests, but the failed test will show everything.

Following the overall test results showing passed, failed, and pending tests, some summary information is displayed about the test failure, and a debugging session is started.  By default, Switchyard uses Python's built-in ``pdb`` debugger.  At the very end of the output, a stack trace is shown and a debugger prompt is displayed:

.. code-block:: none
   :caption: Additional output from a test failure.  Notice the error diagnosis in the output below, as well as how Switchyard invokes the debugger (pdb) at the point of failure.

    ************************************************************
    Your code didn't crash, but a test failed.
    ************************************************************

    This is the Switchyard equivalent of the blue screen of death.
    As far as I can tell, here's what happened:

        Expected event:
            The Ethernet frame with a broadcast destination address
            should be forwarded out ports eth0 and eth2

        Failure observed:
            You called send_packet with an unexpected output port eth1.
            Here is what Switchyard expected: send_packet(s) Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth0 and Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth2.

    You can rerun with the -v flag to include full dumps of packets that
    may have caused errors. (By default, only relevant packet context may
    be shown, not the full contents.)


    I'm throwing you into the Python debugger (pdb) at the point of failure.
    If you don't want pdb, use the --nopdb flag to avoid this fate.

    > /Users/jsommers/Dropbox/src/switchyard/switchyard/llnettest.py(95)send_packet()
    -> SwitchyardTestEvent.EVENT_OUTPUT, device=devname, packet=pkt)
    > /Users/jsommers/Dropbox/src/switchyard/documentation/code/inout1.py(6)main()
    -> net.send_packet(input_port, packet)
    (Pdb) 

Again, notice that the last couple lines show a (partial) stack trace.   These lines can help a bit to understand the context of the error, but it is often helpful to show the source code around the failed code in light of the error diagnosis under "Failure observed", which says that we called ``send_packet`` with an unexpected output port. If we keep reading the diagnosis, we see that the packet was expected to be forwarded out two ports (eth0 and eth2), but was instead sent on eth1.  Showing the source code can be accomplished with ``pdb``'s ``list`` command:

.. code-block:: none
   :caption: Output from pdb when listing the source code at the point of failure.

    (Pdb) list
      8     
      9         # alternatively, the above line could use indexing, although
     10         # readability suffers:
     11         #    recvdata[0], recvdata[2], recvdata[1]))
     12     
     13  ->     net.send_packet(recvdata.input_port, recvdata.packet)
     14     
     15         # likewise, the above line could be written using indexing
     16         # but, again, readability suffers:
     17         # net.send_packet(recvdata[1], recvdata[2])
    [EOF]
    (Pdb) 

Between thinking about the observed failure and viewing the code, we might realize that we have foolishly sent the frame out the same interface on which it arrived.

Another example
^^^^^^^^^^^^^^^

To give a slightly different example, let's say that we're developing the code for a network hub, and because we love sheep, we decide to set every Ethernet source address to ``ba:ba:ba:ba:ba:ba``.  When we execute Switchyard in test mode (e.g., ``swyard -t hubtests.py baaadhub.py``), we get the following output:

.. code-block:: none
   :caption: Test output for an example in which all Ethernet source addresses have been hijacked by sheep.

    Results for test scenario hub tests: 1 passed, 1 failed, 6 pending

    Passed:
    1   An Ethernet frame with a broadcast destination address
        should arrive on eth1


    Failed:
        The Ethernet frame with a broadcast destination address
        should be forwarded out ports eth0 and eth2
            Expected event: send_packet(s) Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth0 and Ethernet
            30:00:00:00:00:02->ff:ff:ff:ff:ff:ff IP | IPv4
            172.16.42.2->255.255.255.255 ICMP | ICMP EchoRequest 0 0 (0
            data bytes) out eth2


    Pending (couldn't test because of prior failure):
    1   An Ethernet frame from 20:00:00:00:00:01 to
        30:00:00:00:00:02 should arrive on eth0
    2   Ethernet frame destined for 30:00:00:00:00:02 should be
        flooded out eth1 and eth2
    3   An Ethernet frame from 30:00:00:00:00:02 to
        20:00:00:00:00:01 should arrive on eth1
    4   Ethernet frame destined to 20:00:00:00:00:01 should be
        flooded out eth0 and eth2
    5   An Ethernet frame should arrive on eth2 with destination
        address the same as eth2's MAC address
    6   The hub should not do anything in response to a frame
        arriving with a destination address referring to the hub
        itself.


    ************************************************************
    Your code didn't crash, but a test failed.
    ************************************************************

    This is the Switchyard equivalent of the blue screen of death.
    As far as I can tell, here's what happened:

        Expected event:
            The Ethernet frame with a broadcast destination address
            should be forwarded out ports eth0 and eth2

        Failure observed:
            You called send_packet and while the output port eth0 is ok,
            an exact match of packet contents failed.  In the Ethernet
            header, src is wrong (is ba:ba:ba:ba:ba:ba but should be
            30:00:00:00:00:02).

    ... output continues ...


In this case, we can see that the first section is basically the same as with the other erroneous code, but the failure description is different:  Switchyard tells us that in the Ethernet header, the ``src`` attribute was wrong.  If, at the ``pdb`` prompt, we type ``list``, we see our wooly problem:

.. code-block:: none
   :caption: Pdb source code listing showing the point of test failure.

    (Pdb) list
     28             else:
     29                 for intf in my_interfaces:
     30                     if dev != intf.name:
     31                         log_info ("Flooding packet {} to {}".format(packet, intf.name))
     32                         eth.src = 'ba:ba:ba:ba:ba:ba' # sheep!
     33  ->                     net.send_packet(intf, packet)
     34         net.shutdown()
    [EOF]
    (Pdb) 

So, although the error diagnosis cannot generally state *why* a problem has happened, it can sometimes be quite specific about *what* has gone wrong.  That, coupled with showing the source code context, can be very helpful for tracking down bugs.  It might also be helpful to note that at the pdb prompt, you can inspect *any* variable in order to figure out what's happened, walk up and down the call stack and execute arbitrary Python statements in order to try to determine what has happened.  Debuggers can be a little bit daunting, but they're incredibly helpful tools.

.. seealso:: 

   To learn more about pdb and the various commands and capabilities it has, refer to the Python library documentation (there's a section specifically on ``pdb``).  There are other debuggers out there with additional features, but ``pdb`` is *always* available with any Python distribution so it is worth acquainting yourself with it.



Even more verbose output
^^^^^^^^^^^^^^^^^^^^^^^^

If you'd like even more verbose output, you can add the ``-v`` (verbose) and/or ``-d`` (debug) flags to ``swyard``.  The ``-d`` flag may be more trouble than it's worth since it enables all DEBUG-level log messages to be printed to the console.  If you're really stuck trying to figure out what's going on, however, this may be useful.

If you don't like pdb
^^^^^^^^^^^^^^^^^^^^^

If you don't appreciate being dumped into the ``pdb`` debugger when something fails (maybe you're a cretin who really just likes ``printf``-style debugging?), you can add the ``--nopdb`` flag to ``swyard``.  With the ``--nopdb`` option, Switchyard will print out information about test failure, but you'll go straight back to a command-line prompt.

If you'd like to use a debugger, but just not ``pdb``, you can use the ``--nohandle`` (or ``-e``) option to tell Switchyard not to trap any exceptions, but to let them be raised normally.  You can then catch any exceptions using an alterative debugger.  For example, if you'd like to use the ``PuDB`` debugger, you could invoke ``swyard`` as follows::

    $ python3 -m pudb.run swyard --nohandle ... 

where the ellipsis is replaced with other command-line arguments to ``swyard``.  

.. _debugging:

Debugging Switchyard code
-------------------------

When running Switchyard, especially in test mode, it is often very helpful to use the interactive Python debugger as you work out problems and figure things out.  With the ``import`` of ``switchyard.lib.userlib`` you get a function named ``debugger``.  You can insert calls to the ``debugger`` function where ever you want to have an interactive debugger session start up.   For example, we could create a simple program that starts up a debugger session when ever we receive a packet:

.. literalinclude:: code/enterdebugger.py
   :language: python

If we run the above program, we will stop at the line *after* the call to ``debugger``:

.. code-block:: none
   :caption: When the debugger() call is added to a Switchyard program, execution is halted at the *next* line of code.

    > /users/jsommers/dropbox/src/switchyard/documentation/code/enterdebugger.py(17)main()
    -> hdrs = packet.num_headers()
    (Pdb) list
     12                 break
     13     
     14             # invoke the debugger every time we get here, which
     15             # should be for every packet we receive!
     16             debugger()
     17  ->         hdrs = packet.num_headers()
     18     
     19         # before exiting our main function,
     20         # perform shutdown on network
     21         net.shutdown()
    [EOF]
    (Pdb) 


.. note::

   There are currently a couple limitations when entering ``pdb`` through a call to ``debugger()``.  First, if you attempt to exit ``pdb`` while the Switchyard program is still running, an exception from ``pdb``'s base class (``Bdb``) will get raised.  Thus, it may take a couple invocations of the ``quit`` command to actually exit.  Second, only the ``pdb`` debugger may be invoked through a call to ``debugger``.  


As noted above, if there is a runtime error in your code, Switchyard will automatically dump you into the Python debugger (pdb) to see exactly where the program crashed and what may have caused it.  You can use any Python commands to inspect variables, and try to understand the state of the program at the time of the crash.

Checking code coverage
^^^^^^^^^^^^^^^^^^^^^^

If you want to check which lines of code are *covered* by one or more test scenarios, you can install and use the ``coverage`` package.  This can be helpful for seeing which lines of your code are *not* being exercised by tests, and how you might focus additional testing effort.

To install:

.. code-block:: none

    $ pip3 install coverage

To gather code coverage information, you can invoke ``swyard`` using ``coverage``.  ``coverage`` appears to work best if you give the full path name of ``swyard``, which is what the following command line will do (using backtick-substitution for the ``which swyard`` command).  You can use command-line options to ``swyard`` as you normally would:

.. code-block:: none

    $ coverage run `which swyard` -v -d -t testscenario.py yourcode.py 

Once you've created the coverage information you can display a report.  The html report will nicely show exactly which lines of your code were executed during a test and which weren't.  To avoid seeing coverage information for irrelevant files, you should explicitly tell ``coverage`` which files you want to include in the report.

.. code-block:: none
    
    $ coverage html --include yourcode.py 

After running the above command, you can open the file ``index.html`` within the ``htmlcov`` folder.  Clicking on a file name will show detailed coverage information.
