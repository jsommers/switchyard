Running in a "live" environment
*******************************

Switchyard can run in any live environment that supports the libpcap packet capture library.  In particular, you can run your Switchyard code on a standard Linux host, on a MacOS X host, or within a Linux-based virtual machine, including Mininet virtual nodes.

Running on a standard host
==========================

need to run with sudo; firewalling, etc.; command-line options for choosing specific interfaces, etc.

To run Switchyard in a "live" Mininet environment (i.e., "real" packets will arrive and can be emitted, not just packets in the test harness), you simply drop the -t and -s options to Switchyard:

::
    $ sudo python srpy.py -v myswitch

FIXME: show some examples


Running within Mininet
======================

FIXME: command-line options (all work the same, it's just more likely that you want all interfaces and don't need to explicitly set any firewall options)

Note that you'll need to do either of the above two commands on a node of a Mininet network.  To open a terminal window on a Mininet node, you can use the "xterm" command in Mininet.  For example, if you want to open a terminal window on a Mininet node named "server1", you would type:

::
    mininet> xterm server1

at the Mininet console prompt.  Inside that window, you'd run ./runreal.sh.


