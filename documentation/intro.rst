Introduction and Overview
*************************

Switchyard is a Python-based framework for developing and testing network system implementations such as the the Ethernet switch and bridge logic, IP routers and firewalls, and even a "full" TCP/IP stack for end hosts.  It is intended primarily for prototyping and educational use: it isn't intended to be fast, but rather intended to facilitate testing and understanding the network code being developed.

A major goal of Switchyard is to enable the creation of the "brains" of a network device like a switch or router, as depicted in the figure below.  The Switchyard framework assumes that each device has 1 or more "interfaces" or "ports".  Each interface has at minimum a string name (e.g., eth0), and an Ethernet address.  An interface may also have an IPv4 address and a subnet mask associated with it.  Each interface can be assumed to have a (virtual) cable plugged into it, which connects to either a switch, router, or some end host.  The goal of a Switchyard-based program is typically to receive a packet on one port, possibly modify it, then either forward it on one or more interfaces, or drop the packet.

.. figure:: srpyarch.*
   :align: center
   :figwidth: 80%
   
This documentation is organized according the main tasks involved in building and testing the core logic for a network device like a switch or router:  

  1.  How to develop a Switchyard program (see :ref:`coding`) , including what APIs are available for parsing and constructing packets and sending/receiving packets on network interfaces.
  2.  Running a Switchyard program in the test environment (see :ref:`runtest`).  Details for how to create a test scenario can also be found in this chapter.
  3.  Running a Switchyard in a live environment (see :ref:`runlive`), such as a standard Linux host, or within the Mininet emulation environment or some other kind of virtual environment.

**Important Note**: Switchyard is Python 3-only!  You'll get an error (or maybe even more than one error!) if you try to use Switchyard with Python 2.  Python 3.4 is required, at minimum.  An installation guide (see :ref:`install`) is also provided in this documentation to help with getting any necessary libraries installed on your platform to make Switchyard work right.

