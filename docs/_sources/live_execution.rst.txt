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

.. note::

   If you can an error when attempting to run ``swyard`` with ``sudo`` such as this::

        sudo: swyard: command not found

   you will need to either create a shell script which activates your Python virtual environment and run that script with ``sudo``, or run ``swyard`` from a root shell (e.g., by running ``sudo -s``.  If doing the latter, you will still need to activate the Python virtual environment once you start the root shell, after which you can run ``swyard`` as normal.  If using Switchyard in Mininet, in any shell you open (e.g., using the ``xterm`` command, which opens a root shell on a virtual host in Mininet) you'll need to activate the Python virtual environment prior to running ``swyard``.


The ``sniff.py`` program will simply print out the contents of any packet received on *any* interface while the program runs.  To stop the program, type :kbd:`Control+c`.

Here's an example of what output from running ``sniff.py`` might look like.  Note that the following example was run on a macOS host and that the text times/dates have been changed:

.. code-block:: none
   :caption: Example of Switchyard output from running in a live environment on a macOS host.

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

    The default behavior of Switchyard is to *block all traffic*.  This behavior may be undesirable in different situations and can be changed through the ``swyard`` command line option ``-f`` or ``--firewall``, as described below.

    Switchyard's manipulation of the host operating system firewall is intended to prevent the host from receiving any traffic that should be the sole domain of Switchyard.  For example, if you are creating a Switchyard-based IP router, you want Switchyard, not the host, to be responsible for receiving and forwarding traffic.  As another example, if you are implementing a protocol stack for a particular UDP-based application, you will want to prevent the host from receiving any of that UDP traffic.

    Note that on macOS Switchyard configures host firewall settings using ``pfctl`` and on Linux Switchyard uses ``iptables``.

  * By default, Switchyard finds and uses all interfaces on the host that are (1) determined to be "up" (according to libpcap), and (2) *not* a localhost interface.  In the above example run, Switchyard finds and uses three interfaces (``en0``, ``en1``, and ``en2``).  

  * The above example shows three packets that were observed by Switchyard, each arriving on interface ``en0``.  Notice that the three packets each contain Ethernet, IPv4 and TCP packet headers, as well as payload (in the form of ``RawPacketContents`` objects at the end of each packet).


Here is an example of running the Switchyard example ``sniff.py`` program on a Linux host (note again that the text times/dates have been changed):

.. code-block:: none
   :caption: Example of Switchyard output from running in a live environment on a Linux host.

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

   To use a localhost interface, you must explicitly include it using this option.  If you explicitly include the localhost interface, you can still explicitly include other interfaces.

.. option:: -x <interface-name>

   Explicitly *exclude* the given interface for use by Switchyard.  This option can be used more than once to exclude more than one interface.

   Switchyard's behavior with this option is to first discover *all* interfaces available on the host, then to remove any specified by ``-x``.  

Note that given the semantics described above, it generally makes sense only to specify *one* of ``-i`` or ``-x``.


.. _firewall:

Firewall options
^^^^^^^^^^^^^^^^

As noted above, Switchyard's default behavior is to prevent the host operating system from receiving any traffic while Switchyard is running.  This may be undesirable in certain situations, and the ``-f`` or ``--firewall`` options to ``swyard`` are available to change this behavior.

The ``-f`` and ``--firewall`` options accept a single rule as a parameter (which in many cases needs to be quoted in the shell).  The rule syntax is ``proto[:port]``, where the ``[:port]`` part is optional and ``proto`` may be one of ``tcp``, ``udp``, ``icmp``, ``none`` or ``all``.  If ``all`` is specified, the port part should not be included; ``all`` will block *all* traffic on the interfaces used by Switchyard.  If ``none`` is specified, again, no port should be specified; ``none`` will cause *no rules to be installed* to block traffic.  Here are some examples:

``tcp``
  Block the host from receiving all TCP traffic
``tcp:8000``
  Block the host from receiving TCP traffic on port 8000
``icmp``
  Block the host from receiving all ICMP traffic
``udp:4567``
  Block the host from receiving UDP traffic on port 4567
``none``
  Do not block any traffic.
``all``
  Block the host from receiving all traffic.  This is the default behavior.

If the ``-v`` (verbose) option is given to ``swyard``, the host firewall module will print (to the log) firewall settings that have been enabled.  Here are two examples from running ``swyard`` in a live environment (on macOS with the ``pf`` firewall).  First, an example showing Switchyard blocking *all* traffic on two interfaces:

.. code-block:: none
   :caption: Running Switchyard in a live environment (macOS) with -v flag: notice log line indicating firewall rules installed (2nd line, 2 rules).


    $ sudo swyard -i lo0 -i en0 -v sniff.py 
    11:39:58 2016/12/00     INFO Enabling pf: No ALTQ support in kernel; ALTQ related functions disabled; pf enabled; Token : 16107925605825483691; 
    11:39:58 2016/12/00     INFO Rules installed: block drop on en0 all
    block drop on lo0 all
    11:39:58 2016/12/00     INFO Using network devices: en0 lo0
    11:39:58 2016/12/00     INFO My interfaces: ['en0', 'lo0']
    ^C11:40:00 2016/12/00     INFO Releasing pf: No ALTQ support in kernel; ALTQ related functions disabled; disable request successful. 4 more pf enable reference(s) remaining, pf still enabled.; 

Here is an example showing Switchyard blocking all ICMP, all TCP, and UDP port 8888:

.. code-block:: none
   :caption: Running Switchyard in a live environment (macOS) with -v flag: notice log line indicating firewall rules installed (2nd line, 3 rules).

    $ sudo swyard -i lo0 --firewall icmp --firewall tcp --firewall 'udp:8888' -v sniff.py 
    11:43:46 2016/12/00     INFO Enabling pf: No ALTQ support in kernel; ALTQ related functions disabled; pf enabled; Token : 16107925605472991531; 
    11:43:46 2016/12/00     INFO Rules installed: block drop on lo0 proto icmp all
    block drop on lo0 proto tcp all
    block drop on lo0 proto udp from any port = 8888 to any port = 8888
    11:43:46 2016/12/00     INFO Using network devices: lo0
    11:43:46 2016/12/00     INFO My interfaces: ['lo0']
    ^C11:43:48 2016/12/00     INFO Releasing pf: No ALTQ support in kernel; ALTQ related functions disabled; disable request successful. 4 more pf enable reference(s) remaining, pf still enabled.; 

And finally, the same example as previous, but on Linux with iptables:

.. code-block:: none
   :caption: Running Switchyard in a live environment (Linux) with -v flag: notice log line indicating firewall rules installed (2nd line, 3 rules).

    # swyard -v sniff.py --firewall icmp --firewall udp:8888 --firewall tcp
    19:53:42 2016/12/00     INFO Saving iptables state and installing switchyard rules
    19:53:42 2016/12/00     INFO Rules installed: Chain PREROUTING (policy ACCEPT)
    target     prot opt source               destination         
    DROP       icmp --  0.0.0.0/0            0.0.0.0/0           
    DROP       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:8888
    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0           
    
    Chain OUTPUT (policy ACCEPT)
    target     prot opt source               destination
    19:53:42 2016/12/00     INFO Using network devices: enp0s3
    19:53:42 2016/12/00     INFO My interfaces: ['enp0s3']
    ^C19:53:45 2016/12/00     INFO Restoring saved iptables state


.. note::

   When using a loopback interface, there are a couple things to be aware of.  First, while Switchyard normally uses ``libpcap`` for sending and receiving packets, a *raw socket* is used for sending packets on the localhost interface.  This is done due to limitations on some operating systems, notably Linux.  Receiving packets is still done with ``libpcap``, though on different operating systems you may observe that packets are encapsulated differently.  In particular, on Linux, an ``Ethernet`` header with zeroed addresses is used, while on macOS the BSD Null header is used, which just consists of a protocol number (i.e., the ethertype value normally found in the Ethernet header).
