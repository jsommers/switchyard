.. _runlive:

Running in a "live" environment
*******************************

Switchyard programs can be either run in an isolated :ref:`test environment <runtest>`, as described above, or on a *live* host operating system.  Switchyard currently supports Linux and macOS hosts for live execution.  

.. note::

   Switchyard uses the ``libpcap`` library for receiving and sending packets, which generally requires *root* privileges.  Although hosts can be configured so that root isn't required for using ``libpcap``, this documentation does not include instructions on how to do so.  The discussion below assumes that you are gaining root privileges by using the ``sudo`` (i.e., "do this as superuser") program.  Contrary to popular belief, ``sudo`` cannot make you a sandwich.


Basic command-line recipe
^^^^^^^^^^^^^^^^^^^^^^^^^

The basic recipe for running Switchyard on a live host is pretty simple.  If we wanted to run the ``sniff.py`` Switchyard program (available in the ``examples`` folder in the Switchyard github repository) and use *all* available network interfaces on the system, we could do the following:

.. code-block:: none

    $ sudo swyard sniff.py

Again, note that the above line uses ``sudo`` to gain the necessary privileges to be able to send and receive "live" packets on a host.  

The ``sniff.py`` program will simply print out the contents of any packet received on *any* interface while the program runs.  To stop the program, type :kbd:`Control+c`.

Here's an example of what output from running ``sniff.py`` might look like.  Note that the following example was run on a macOS host and that the text times/dates have been changed:

.. code-block:: none

    00:00:56 2016/12/00     INFO Enabling pf: No ALTQ support in kernel; ALTQ related functions disabled; pf enabled; Token : 15170097737539790927
    00:00:56 2016/12/00     INFO Using network devices: en1 en0 en2
    00:00:56 2016/12/00     INFO My interfaces: ['en0', 'en1', 'en2']
    00:00:56 2016/12/00     INFO 1482563936.430: en0 Ethernet a4:71:74:49:e2:e6->ac:bc:32:c2:b6:59 IP | IPv4 104.84.41.100->192.168.0.102 TCP | TCP 443->51094 (A 1772379675:466295739) | RawPacketContents (1448 bytes) b'\x17\x03\x03\x0c-\xc5\xeap\xd1L'...
    00:00:56 2016/12/00     INFO 1482563936.430: en0 Ethernet a4:71:74:49:e2:e6->ac:bc:32:c2:b6:59 IP | IPv4 104.84.41.100->192.168.0.102 TCP | TCP 443->51094 (A 1772381123:466295739) | RawPacketContents (1448 bytes) b'\xca5K\xfb\x88\x01\xec\xb4\xf0\x84'...
    00:00:56 2016/12/00     INFO 1482563936.430: en0 Ethernet a4:71:74:49:e2:e6->ac:bc:32:c2:b6:59 IP | IPv4 104.84.41.100->192.168.0.102 TCP | TCP 443->51094 (PA 1772382571:466295739) | RawPacketContents (226 bytes) b'\xb1\x9d\xad8g]\xc3\xech\x9e'...

    ... (more packets, removed for this example)

    ^C
    00:00:58 2016/12/00     INFO Releasing pf: No ALTQ support in kernel; ALTQ related functions disabled; disable request successful. 1 more pf enable reference(s) remaining, pf still enabled.


Note in particular a few things about the above example:

  * First, when started in a live setting, Switchyard *saves* then *clears* any current host firewall settings.  The saved firewall settings are restored when Switchyard exits (see the final log line, above).  

    The reason Switchyard clears the host firewall is that it is often the case that you want Switchyard to receive *all* packets arriving on host interfaces.  While it is possible to specify different firewall settings (see below), the default behavior is to save and clear any firewall rules upon startup, then restore them when exiting.

    Note that on macOS Switchyard configures host firewall settings using ``pfctl`` and on Linux Switchyard uses ``iptables``.

  * By default, Switchyard finds and uses all interfaces on the host that are (1) determined to be "up" (according to libpcap), and (2) *not* a localhost interface.  In the above example run, Switchyard finds and uses three interfaces (``en0``, ``en1``, and ``en2``).  

  * The above example shows three packets that were observed by Switchyard, each arriving on interface ``en0``.  Notice that the three packets each contain Ethernet, IPv4 and TCP packet headers, as well as payload (in the form of RawPacketContents objects at the "end" of each packet).


Here is an example of running the Switchyard example ``sniff.py`` program on a Linux host (note again that the text times/dates have been changed):

.. code-block:: none

    00:00:11 2016/12/00     INFO Saving iptables state and installing switchyard rules
    00:00:11 2016/12/00     INFO Using network devices: enp0s3
    00:00:11 2016/12/00     INFO My interfaces: ['enp0s3']
    00:00:15 2016/12/00     INFO 1482564855.115: enp0s3 Ethernet 08:00:27:bb:27:89->01:00:5e:00:00:fb IP | IPv4 10.0.2.15->224.0.0.251 UDP | UDP 5353->5353 | RawPacketContents (45 bytes) b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00'...
    00:00:16 2016/12/00     INFO 1482564856.172: enp0s3 Ethernet 08:00:27:bb:27:89->33:33:00:00:00:fb IPv6 | IPv6 fe80::a00:27ff:febb:2789->ff02::fb UDP | UDP 5353->5353 | RawPacketContents (45 bytes) b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00'...

    ... (more packets, removed for this example)

    ^C
    00:00:23 2016/12/00     INFO Restoring saved iptables state

Comparing the above output to the earlier macOS output, observe that:

  * The firewall save/restore log lines (first and last) are somewhat different, reflecting the fact that ``iptables`` is used on Linux instead of ``pf``.  

  * There is one interface found and used by Switchyard: ``enp0s3``.

  * Two packets are included in the output above: an IPv4 UDP packet and an IPv6 UDP packet.

As with running Switchyard in a test environment, you may wish to use the ``-v`` and/or ``-d`` options to increase Switchyard's output verbosity or to include debugging messages, respectively.


Including or excluding particular interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When running Switchyard in a virtual machine environment such as on a Mininet container host, it is often the case that you want Switchyard to "take over" all available network interfaces on the host.  When running Switchyard in other environments, however, you may want to restrict the interfaces that it uses.  You may even want Switchyard to use the localhost interface (typically named ``lo0`` or ``lo``).  There are two command-line options that can be used for these purposes.

.. option:: -i <interface-name>

   Explicitly *include* the given interface for use by Switchyard.  This option can be used more than once to include more than one interface.

   If this option is given, *only* the interfaces specified by ``-i`` options will be used by Switchyard.  If no ``-i`` option is specified, Switchyard uses all available interfaces *except* the localhost interface.

   To use a localhost interface, you must explicitly include it using this option.

.. option:: -x <interface-name>

   Explicitly *exclude* the given interface for use by Switchyard.  This option can be used more than once to exclude more than one interface.

   Switchyard's behavior with this option is to first discover *all* interfaces available on the host, then to remove any specified by ``-x``.  

Note that given the semantics described above, it generally makes sense only to specify *one* of ``-i`` or ``-x``.





Firewall options
^^^^^^^^^^^^^^^^

As noted above, Switchyard's default behavior is to 


tcp:*
udp:*
icmp:*

FIXME: make tcp, udp, icmp also work
all
