Introduction and Overview
*************************

Switchyard is a framework for creating, testing, and experimenting with software implementations of networked systems such as Ethernet switches, IP routers, firewalls and middleboxes, and end-host protocol stacks.  Switchyard can be used for system-building projects targeting layers of the network protocol stack from layer 2 (link layer) and above.  It is intended primarily for educational use and has purpose-built testing and debugging features. Although its design favors understandability over speed, it can work quite nicely as a prototyping environment for new kinds of networked devices.

The Switchyard framework is implemented in Python and consists of two components: a program (``swyard``) which creates a runtime environment for the code that implements some networked system or device, and a collection of library modules that can be used for a variety of tasks such as packet creation and parsing.  The networked system code is implemented in one or more Python files (which you write!) and that use the Switchyard libraries and conform to certain conventions.  The ``swyard`` runtime environment creator and orchestrator seamlessly handles running your code either in a test setting where no actual network traffic is created or in a real or "live" setting in which your code can interact with other networked systems.

The Switchyard runtime environment (depicted below) provides a given networked system with 1 or more "interfaces" or "ports".  A port may represent a wired connection to another device, or may represent a wireless interface, or may represent a "loopback" interface.  In any case, it is through these ports that packets are sent and received.  Each port has, at minimum, a name (e.g., ``en0``) and an Ethernet address.  A port may also have an IPv4 address and network mask associated with it. 


.. figure:: srpyarch.*
   :align: center
   :figwidth: 80%


The goal of a Switchyard-based program is typically to receive a packet on one port, possibly modify it, then either forward it out one or more ports or to drop the packet.  The rest of this documentation is organized around how to perform these tasks in various settings.  In particular: 

 * The next section (see :ref:`coding`) describes how to develop a basic Switchyard program, including what APIs are available for parsing and constructing packets and sending/receiving packets on network interfaces.  
 * Additional Switchyard program development topics are addressed next (see :ref:`advanced`), such as creating new packet header types, and implementing network protocol stacks that can interoperate with a Python socket-based program.  
 * Following that, the next section provides details on running a Switchyard program in the test environment (see :ref:`runtest`).  Details for how to create a test scenario can also be found in this chapter.  
 * The next section describes how to run a Switchyard program in a live environment (see :ref:`runlive`), such as a standard Linux host, or within the Mininet emulation environment or some other kind of virtual environment.  
 * Commonly experienced problems and the solutions to those problems are addressed in the next chapter (see :ref:`faq`).  
 * At the end of this documentation you can find an API reference (see :ref:`apiref`) and an index.

**A note to the pedantic**: In this documentation we use the term *packet* in a generic sense to refer to what may more traditionally be a link layer *frame*, a network layer *packet*, a transport layer *segment*, or an application layer *message*.  

**And one more (genuinely important) note**: Switchyard is Python 3-only!  You'll get an error (or maybe even more than one error!) if you try to use Switchyard with Python 2.  Python 3.4 is required, at minimum.  An installation guide (see :ref:`install`) is also provided in this documentation to help with getting any necessary libraries installed on your platform to make Switchyard work right.
