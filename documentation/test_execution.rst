.. _runtest:

Running in the test environment
*******************************

To run Switchyard in test mode, you should have a "scenario" file that includes specific test cases to run.  These files should typically have an extension .srpy, but they may also just be plain Python (.py) files.

Let's say your program is named myswitch.py.  To invoke Switchyard in test mode and subject your program to a set of tests, you would invoke ``srpy.py`` as follows::

    $ python srpy.py -v -t -s switchtests.srpy myswitch

FIXME: command-line options


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

Also, note that if there is a runtime error in your code, Switchyard will throw you into the Python debugger (pdb) to see exactly where the program crashed.  You can use any Python commands to inspect variables, and try to understand the state of the program at the time of the crash.

FIXME: command-line options to avoid pdb, etc.
