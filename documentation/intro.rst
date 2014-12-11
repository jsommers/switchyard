Introduction
============

This is an introduction

SRPY documentation
Version 0.1
9 February 2014
jsommers@colgate.edu


Overview

SRPY is a Python library for developing and testing network device implementations such as Ethernet switches and bridges, and IP routers and firewalls.  It is intended for classroom use: it isn't intended to be fast, but rather intended to facilitate testing and understanding the network code being developed.

SRPY stands for "software switches and routers in Python" and is loosely based on the "sr" (software router) project part of the "Building an Internet Router" class at Stanford University (http://yuba.stanford.edu/cs344/).

The goal of SRPY is to enable creating the "brains" of a network device like a switch or router.  SRPY assumes that each device has 1 or more "interfaces" or "ports".  Each interface has at minimum a string name (e.g., eth0), and an Ethernet address.  An interface may also have an IP address and a subnet mask associated with it.  Each interface can be assumed to have a (virtual) cable plugged into it, which connects to either a switch, router, or some end host.  The goal of a SRPY-based program is typically to receive a packet on one port, possibly modify it, then either forward it on one or more interfaces, or drop the packet.



Developing a SRPY-based Program

A SRPY program is simply a Python program that includes the the required function srpy_main().  The SRPY framework will invoke this function on startup, passing a reference to the SRPY network object as the only parameter.

A SRPY program will typically also import other Python modules such as POX modules for parsing and constructing packets, as well as handling Ethernet and IPv4 addresses.

Methods Available on the "net" Object

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

def srpy_main(net):
    for intf in net.interfaces():
            print intf.name, intf.ethaddr, intf.ipaddr, intf.netmask

            Example output from the above program might be:

            eth2 10:00:00:00:00:03 172.16.42.1 255.255.255.252
            eth1 10:00:00:00:00:02 10.10.0.1 255.255.0.0
            eth0 10:00:00:00:00:01 192.168.1.1 255.255.255.0

            Notice that there is no ordering to the list of interfaces returned.

            There is also a ports() method that is just an alias of interfaces().

            interface_by_name(devicename), interface_by_ipaddr(ipaddr), interface_by_macaddr(ethaddr): these methods are alternative ways to obtain an Interface object, by supplying a device name (e.g., "eth0") an IP address configured on a device, or an Ethernet MAC address configured on a device.  They are basically convenience methods provided so that you do not have to continually iterate over the list of interfaces.

            recv_packet(timeout): this method waits for timeout seconds for any packets to arrive.  If a packet arrives before timeout seconds have passed, it returns a tuple of three items: the device name that the packet arrived on, a timestamp, and a POX packet object.  If no packets arrive before timeout seconds pass, the method raises a SrpyNoPackets exception.

            send_packet(dev, packet): this method sends a packet (which must be a POX Ethernet packet object) on the device named dev.  The name dev must match the name of one of the interfaces given in the interface list.

            shutdown(): this signals to the SRPY framework that your program is done and exiting.  It should be the last thing you call in a SRPY program.

            A simple template for a SRPY program is as follows:

            #!/usr/bin/env python

            import os
            import os.path
            sys.path.append(os.path.join(os.environ['HOME'],'pox'))
            sys.path.append(os.path.join(os.getcwd(),'pox'))
            import pox.lib.packet as pkt
            from srpy_common import SrpyShutdown, SrpyNoPackets

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
                                                                                                            
                                                                                                                    print packet.dump() # just print each packet to the console

                                                                                                                        # before exiting our main function,
                                                                                                                            # perform shutdown on network
                                                                                                                                net.shutdown()

                                                                                                                                Running SRPY in test mode

                                                                                                                                To run SRPY in test mode, you should have a "scenario" file that includes specific test cases to run.  These files should typically have an extension .srpy, but they may also just be plain Python (.py) files.

                                                                                                                                Let's say your program is named myswitch.py.  To invoke SRPY in test mode and subject your program to a set of tests, you would invoke SRPY as follows:
                                                                                                                                $ python srpy.py -v -t -s switchtests.srpy myswitch

                                                                                                                                In COSC 465 projects, I will supply a setup.sh script that creates a helper script to do the above, named runtests.sh.  In that case, you can simply say:

                                                                                                                                $ ./runtests.sh

                                                                                                                                Debugging SRPY code

                                                                                                                                When running SRPY, especially in test mode, it is often very helpful to use the interactive Python debugger as you work out problems and figure things out.  If you import a function named debugger from srpy_common, you can insert calls to the debugger function where ever you want to have an interactive debugger session start up.   For example, we could modify the above template program to invoke a debugger session when ever we receive a packet.  (Note the additional import from srpy_common of debugger.)

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

                                                                                                                                                                                                                                                                    Running SRPY in mininet ("live") mode

                                                                                                                                                                                                                                                                    To run SRPY in a "live" Mininet environment (i.e., "real" packets will arrive and can be emitted, not just packets in the test harness), you simply drop the -t and -s options to SRPY:
                                                                                                                                                                                                                                                                    $ python srpy.py -v myswitch

                                                                                                                                                                                                                                                                    There will also be a script created as a side-effect of running setup.sh, in which case you can simply run:
                                                                                                                                                                                                                                                                    $ ./runreal.sh

                                                                                                                                                                                                                                                                    Note that you'll need to do either of the above two commands on a node of a Mininet network.  To open a terminal window on a Mininet node, you can use the "xterm" command in Mininet.  For example, if you want to open a terminal window on a Mininet node named "server1", you would type:
                                                                                                                                                                                                                                                                    mininet> xterm server1
                                                                                                                                                                                                                                                                    at the Mininet console prompt.  Inside that window, you'd run ./runreal.sh.

                                                                                                                                                                                                                                                                    Acknowledgment

                                                                                                                                                                                                                                                                    I gratefully acknowledge support from the NSF.  The materials here are based upon work supported by the National Science Foundation under grant CNS-1054985 ("CAREER: Expanding the functionality of Internet routers").                                                                      
                                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                                                                                                                    Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author and do not necessarily reflect the views of the National Science Foundation.


