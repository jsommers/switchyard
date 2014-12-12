Running in the test environment
===============================

To run SRPY in test mode, you should have a "scenario" file that includes specific test cases to run.  These files should typically have an extension .srpy, but they may also just be plain Python (.py) files.

Let's say your program is named myswitch.py.  To invoke SRPY in test mode and subject your program to a set of tests, you would invoke SRPY as follows:

$ python srpy.py -v -t -s switchtests.srpy myswitch

In COSC 465 projects, I will supply a setup.sh script that creates a helper script to do the above, named runtests.sh.  In that case, you can simply say:

$ ./runtests.sh


Debugging SRPY code
-------------------

When running SRPY, especially in test mode, it is often very helpful to use the interactive Python debugger as you work out problems and figure things out.  If you import a function named debugger from srpy_common, you can insert calls to the debugger function where ever you want to have an interactive debugger session start up.   For example, we could modify the above template program to invoke a debugger session when ever we receive a packet.  (Note the additional import from srpy_common of debugger.)

::

    #!/usr/bin/env python
    import os
    import os.path
    sys.path.append(os.path.join(os.environ['HOME'],'pox'))
    sys.path.append(os.path.join(os.getcwd(),'pox'))
    import pox.lib.packet as pkt
    from srpy_common import SrpyShutdown, SrpyNoPackets, debugger

    def srpy_main(net):
        while True:
            try:
                dev,ts,packet = net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # timeout waiting for packet arrival
                continue
            except SrpyShutdown:
                # we're done; bail out of while loop
                return

            # invoke the debugger every time we get here, which
            # should be for every packet we receive!
            debugger()

        # before exiting our main function,
        # perform shutdown on network
        net.shutdown()

Also, note that if there is a runtime error in your code, SRPY will throw you into the Python debugger (pdb) to see exactly where the program crashed.  You can use any Python commands to inspect variables, and try to understand the state of the program at the time of the crash.


