Overview
--------

This is the third stage in a series of exercises that have the ultimate goal of creating an IPv4 router.   The basic functions of an Internet router are to:

1. Respond to ARP (address resolution protocol) requests for addresses that are assigned to interfaces on the router.  (Remember that the purpose of ARP is to obtain the Ethernet MAC address associated with an IP address so that an Ethernet frame can be sent to another host over the link layer.)

2. Receive and forward packets that arrive on links and are destined to other hosts.  Part of the forwarding process is to perform address lookups ("longest prefix match" lookups) in the forwarding table.  We will just use "static" routing in our router rather than implement a dynamic routing protocol like RIP or OSPF.

3. Make ARP requests for IP addresses that have no known Ethernet MAC address.  A router will often have to send packets to other hosts, and needs Ethernet MAC addresses to do so.

4. Respond to ICMP messages like echo requests ("pings").

5. Generate ICMP error messages when necessary, such as when an IP packet's TTL (time to live) value has been decremented to zero.

The goal of this stage of the project is to accomplish items 4 and 5 above.  When you're done with this project, you will have a fully functioning Internet router.  You don't need to end there, though: some fun extensions to the router are described in another project description.


Task 1: Responding to ICMP echo requests
----------------------------------------

The first key task for this is for the router to respond to ICMP echo request ("pings") sent to an address assigned to one of its interfaces.

Prior to making a forwarding decision for an incoming IP packet (i.e., a forwarding table lookup), you should first check whether the IP destination address is the same as one of the addresses assigned to one of the router's interfaces.  If the packet is also an ICMP echo request, then you should construct an ICMP echo reply and send it back to the original host that sent the ping.  To do that, you should:

* Construct an ICMP header + echo reply, correctly populating the fields in the header.   See the Switchyard documentation for details on ICMP packet headers.  When creating the EchoReply, do the following:

  * Copy the EchoRequest sequence number into the EchoReply you make, and

  * also copy the identifier in the EchoRequest into the EchoReply, and

  * set the data field in the EchoReply to be the same as the data in the EchoRequest.

* Construct an IP header, which should have the destination IP address set as the source address of the incoming ICMP echo request, and the IP source address set as the router's interface address.  The next header in the packet should be the ICMP header that you created.

* Send (forward) the packet you constructed.  You should already have code from the previous stage of the router to do forwarding table lookups and ARP requests to handle this part.  If you've designed this part of your router reasonably well, this should just be a method/function call for forwarding the echo response.


Task 2: Generating ICMP error messages
--------------------------------------

There are 4 situations in which you'll need to generate ICMP error messages.  To this point, we have either explicitly ignored these error cases, or simply haven't considered them.  The following  describes the specific cases, and the ICMP error message you'll need to generate in response to them:

1.  When attempting to match the destination address of an IP packet with entries in the forwarding table, no matching entries are found (i.e., the router doesn't know where to forward the packet).

    In this case, an **ICMP destination network unreachable** error should be sent back to the host referred to by the source address in the IP packet.  Note: the ICMP type should be destination unreachable, and the ICMP code should be network unreachable.

2.  After decrementing an IP packet's TTL value as part of the forwarding process, the TTL becomes zero.

    In this case, an **ICMP time exceeded** error message should be sent back to the host referred to by the source address in the IP packet.  Note: the ICMP code should be TTL expired.

3.  ARP Failure.  During the forwarding process, the router often has to make ARP requests to obtain the Ethernet address of the next hop or the destination host.  If there is no host that "owns" a particular IP address, the router will never receive an ARP reply.

    If after 5 retransmission of an ARP request the router does not receive an ARP reply, the router should send an **ICMP destination host unreachable** back to the host referred to by the source address in the IP packet.  Note: the ICMP type should be destination unreachable, and the ICMP code should be host unreachable.

4.  An incoming packet is destined to an IP addresses assigned to one of the router's interfaces, but the packet is not an ICMP echo request

    The only packets destined for the router itself that it knows how to handle are ICMP echo requests.  Any other packets should cause the router to send an **ICMP destination port unreachable** error message back to the source address in the IP packet.  Note: the ICMP type should be destination unreachable, and the ICMP code should be port unreachable.
    
Again, refer to the Switchyard documentation on ICMP headers.  

For creating any ICMP error packet (i.e., any of the packets in the table above), you must include as the "data" payload of the ICMP header up to the first 28 bytes of the original packet, starting with the IPv4 header.  (That is, your ICMP message will include part of the packet that caused the problem.)  The switchyard documentation has an example of doing this, and an example is also given below.  Also, be careful to make sure that the newly constructed IP packet you send has a non-zero TTL --- by default, when you create a new IPv4 header, the TTL value is zero (0).  A code formula for including the "dead" packet in the ICMP payload is shown below::

    >>> origpkt = Ethernet() + IPv4() + ICMP()  # assume this is the packet that caused the error
    >>> i = origpkt.get_header_index(Ethernet)
    >>> del origpkt[i] # remove Ethernet header --- the errored packet contents sent with
    >>>            # the ICMP error message should not have an Ethernet header
    >>> icmp = ICMP()
    >>> icmp.icmptype = ICMPType.TimeExceeded
    >>> icmp.icmpdata.data = origpkt.to_bytes()[:28]
    >>> str(icmp)
    "ICMP TimeExceeded:TTLExpired 28 bytes of raw payload (b'E\\x00\\x00\\x1c\\x00\\x00\\x00\\x00\\x00\\x01') OrigDgramLen: 0"
    >>> ip = IPv4()
    >>> ip.protocol = IPProtocol.ICMP # protocol defaults to ICMP;
    >>>                               # setting it explicitly here anyway
    >>> # would also need to set ip.src, ip.dst, and ip.ttl to something non-zero
    >>> pkt = ip + icmp
    >>> print(pkt)
    IPv4 0.0.0.0->0.0.0.0 ICMP | ICMP TimeExceeded:TTLExpired 28 bytes of raw payload (b'E\x00\x00\x1c\x00\x00\x00\x00\x00\x01') OrigDgramLen: 28

Some questions and answers
--------------------------

Q: When sending ICMP echo replies or error messages, does the router need to do a forwarding table lookup and send ARP requests if needed? Can't the router just send the ICMP messages back on the interface through which the IP packet was received?

  A: The router will still need to do an ARP query as it normally does for forwarding an IP packet. It doesn't matter that an echo request arrives on, say port eth0. The echo reply may end up going out on a different port depending on the forwarding table lookup. The entire lookup and ARP query process should be the same as forwarding an IP packet, and will always behave exactly this way.

Q: How many error messages should be generated if a packet has TTL expired and network unreachable errors at the same time?

  A: Your router will only generate a network unreachable error in this case. Since the router decrements the TTL field after doing a lookup, if the lookup fails then your router will not reach at decrementing the TTL value.

Q: If there are multiple packets buffered for the same destination host or next hop and the router doesn't receive an ARP reply after sending 5 retransmissions of ARP requests what should the router do?

  A: Your router should send an ICMP destination host unreachable message back to the host referred to by the source address in the IP packet. When there are multiple packets buffered for the same destination address, the router will send an ICMP error message to each source host of these packets (even if the same source host sent multiple packets).

Switchyard testing
------------------

To test your router, you can use the same formula you've used in the past::

    $ swyard -t routertests3.srpy myrouter.py

Note that the test scenario file is *not* included in this repository but is available on request.


Mininet ("live") testing
------------------------

Once the Switchyard tests pass, you should test your router in Mininet.  There is a ``start_mininet.py`` script available for building the following network topology:

.. image:: router2_topology.png

(Note that the above topology is not the same as the one implied by the Switchyard tests.)

To test each of the new router functionalities in Mininet, you can open up a terminal on the virtual machine, and cd (if necessary) to the folder where your project files are located (or transfer them into the virtual machine).  Then type the following to get Mininet started::

    $ sudo python start_mininet.py
  
Once Mininet is running, open a terminal on the router node (xterm router) and get the router running (``swyard myrouter.py``).  Again, be aware that you may need to activate a Python virtual environment in order for this command to succeed.

Next, open a terminal on the client node (``xterm client``).  Now, you should be able to:

* Use the ping tool to send an ICMP echo request to an IP address configured on one of the router's interfaces.  Ping should successfully report that it is receiving replies to the echo requests.

* You can also use the ping tool and specifically set the initial TTL in the ICMP packets to be 1, so that when your router receives them, it will decrement the TTL to zero and generate an ICMP time exceeded error.  The -t flag to ping allows you to explicitly set the TTL.  For example::

    client# ping -c 1 -t 1 192.168.200.1

* You can send a ping from the client to an address that doesn't have a match in the router's forwarding table.  There is a route set up on the client to forward traffic destined to 172.16.0.0/16 to the router, but the router doesn't have any forwarding table entry for this subnet.  So the following ping should result in an ICMP destination net unreachable message sent back to the client::

    client# ping -c 1 172.16.1.1

* Probably the most complicated test you can run is to do a "traceroute" across the toy network in Mininet.  From the client, type::

    client# traceroute -N 1 -n 192.168.100.1

  The output you see should be similar to the following::

      traceroute to 192.168.100.1 (192.168.100.1), 30 hops max, 60 byte packets
       1  10.1.1.2  409.501 ms  201.130 ms  200.578 ms
       2  192.168.100.1  607.775 ms  401.868 ms  401.920 ms 

If you can get this working, then you can have pretty high confidence that everything in your router works correctly.  Congratulations!

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
