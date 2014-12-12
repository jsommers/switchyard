Running in a "live" environment
===============================

Running SRPY in mininet ("live") mode

To run SRPY in a "live" Mininet environment (i.e., "real" packets will arrive and can be emitted, not just packets in the test harness), you simply drop the -t and -s options to SRPY:

::
    $ python srpy.py -v myswitch

There will also be a script created as a side-effect of running setup.sh, in which case you can simply run:

::
    $ ./runreal.sh

Note that you'll need to do either of the above two commands on a node of a Mininet network.  To open a terminal window on a Mininet node, you can use the "xterm" command in Mininet.  For example, if you want to open a terminal window on a Mininet node named "server1", you would type:

::
    mininet> xterm server1

at the Mininet console prompt.  Inside that window, you'd run ./runreal.sh.

