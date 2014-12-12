Writing a Switchyard Program
============================

A SRPY program is simply a Python program that includes the the required function srpy_main().  The SRPY framework will invoke this function on startup, passing a reference to the SRPY network object as the only parameter.

A SRPY program will typically also import other Python modules such as POX modules for parsing and constructing packets, as well as handling Ethernet and IPv4 addresses.

Methods Available on the "net" Object
-------------------------------------

The object passed as a parameter to srpy_main has a set of methods that allow you to find out about interfaces attached to your network device (e.g., your switch or router), receive packets from the network, and emit a packet on a network interface.  There are also some important classes and functions in a module called srpy_common.

Important classes and functions in srpy_common are:

The Interface class, which models a single logical interface on a network device.  It has four properties:
name: the name of the interface
ethaddr: the Ethernet address associated with the interface as a POX EthAddr object
ipaddr: the IP address associated with the interface as a POX IPAddr object
netmask: the subnet mask associated with the interface as a POX IPAddr object
The SrpyShutdown and SrpyNoPackets exception classes
SrpyShutdown is raised when the SRPY framework is shutting down
SrpyNoPackets is raised when you attempt to receive packets, but none arrive prior to a "timeout" occurring
log_debug, log_info, log_warn, log_failure
Each of these functions takes a string as a parameter and prints it to the console as a logging message
Alternatively, you can simply use the print statement to write to the console

The methods available on the net object are:
interfaces(): this method returns a list of Interface objects (as described above) attached to your network device.   As an example for using this method, here is a short program that defines a srpy_main function.  The program just iterates through the list of interfaces returned from net.interfaces(), and prints out the name, Ethernet MAC address, IP address, and IP subnet mask associated with each interface:

::
    def srpy_main(net):
        for intf in net.interfaces():
            print intf.name, intf.ethaddr, intf.ipaddr, intf.netmask

Example output from the above program might be::

    eth2 10:00:00:00:00:03 172.16.42.1 255.255.255.252
    eth1 10:00:00:00:00:02 10.10.0.1 255.255.0.0
    eth0 10:00:00:00:00:01 192.168.1.1 255.255.255.0

Notice that there is no ordering to the list of interfaces returned.

There is also a ports() method that is just an alias of interfaces().

interface_by_name(devicename), interface_by_ipaddr(ipaddr), interface_by_macaddr(ethaddr): these methods are alternative ways to obtain an Interface object, by supplying a device name (e.g., "eth0") an IP address configured on a device, or an Ethernet MAC address configured on a device.  They are basically convenience methods provided so that you do not have to continually iterate over the list of interfaces.

recv_packet(timeout): this method waits for timeout seconds for any packets to arrive.  If a packet arrives before timeout seconds have passed, it returns a tuple of three items: the device name that the packet arrived on, a timestamp, and a POX packet object.  If no packets arrive before timeout seconds pass, the method raises a SrpyNoPackets exception.

send_packet(dev, packet): this method sends a packet (which must be a POX Ethernet packet object) on the device named dev.  The name dev must match the name of one of the interfaces given in the interface list.

shutdown(): this signals to the SRPY framework that your program is done and exiting.  It should be the last thing you call in a SRPY program.

A simple template for a SRPY program is as follows::

    #!/usr/bin/env python

    import os
    import os.path
    sys.path.append(os.path.join(os.environ['HOME'],'pox'))
    sys.path.append(os.path.join(os.getcwd(),'pox'))
    import pox.lib.packet as pkt
    from srpy_common import SrpyShutdown, SrpyNoPackets

    def srpy_main(net): while True:
            try:
                dev,ts,packet = net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # timeout waiting for packet arrival
                continue
            except SrpyShutdown:
                # we're done; bail out of while loop
                return
            print packet.dump() # just print each packet to the console
            # before exiting our main function,
            # perform shutdown on network
        net.shutdown()

