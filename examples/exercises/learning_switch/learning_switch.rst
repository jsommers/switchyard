Overview

In this exercise, you will write the code to implement the core logic in an Ethernet learning switch.  Your switch will be written in Python using the Switchyard framework.  You'll also need to use Mininet for running your switch in a "live", but emulated, network.  You can start with the hub implementation we did during class.  The code you'll need to add should be less than 20 lines (and possibly quite a bit less depending on exactly how you write the code).


You will need to do this lab in the class virtual machine (or some other appropriately configured virtual machine).  To get started, open a terminal in your VM:

1. Clone the git repo https://github.com/jsommers/cosc465-hw3
2. cd into the cosc465-hw3 directory
3. run ./setup.sh


(Note: the setup.sh script is similar to the one used in class for the hub walkthrough.  If you had problems doing the setup with the in-class walkthrough, please let me know so that we can sort out your dev environment --- you'll really want this to work correctly going forward.)


Ethernet Learning Switch Operation


An Ethernet learning switch is a device that has a set of interfaces with links connected to other switches, and to end hosts.  When Ethernet frames arrive on any port/interface, the switch sends the frame on an appropriate output port if the switch knows that the host is reachable through that port, or floods the frame out all ports if it does not know where the host is.


Consider the picture below.  Say that Switch 1 doesn't know the locations of any host on the network, and that H1 wants to send an Ethernet frame to H3.  When that frame arrives at Switch 1, it sees Ethernet source address 00:00:00:00:00:01 and destination address 00:00:00:00:00:03.  From this packet arrival, it knows that it can now reach H1 by send a frame out the same interface on which this frame has arrived.  However, it does not know where to send to frame to reach H3, so it floods the packet out all ports except the one on which the frame arrived.  Eventually, H3 will receive the frame.  If it replies to H1, Switch 1 will receive a frame with the source address as H3's address, and the frame will arrive on the interface connected to Switch 2.  At this point, Switch 1 now knows exactly which ports it needs to use to send frames to either H1 or H3.
  



The following flowchart summarizes the example described above.  The only additional considerations shown in the flowchart are if the destination address is the same as one of the Ethernet addresses on the switch itself (i.e., the frame is intended for the switch), or the Ethernet destination address is the broadcast address (FF:FF:FF:FF:FF:FF).


  



Your Task


Your task is to implement the logic in the above flowchart, using the Switchyard framework.  The git repo contains a starter file named "myswitch.py", which is the only file you'll need to modify.


Two links to Switchyard API documentation which you may need are:


* Packet parsing/construction reference: http://cs.colgate.edu/~jsommers/switchyard/reference.html#packet-parsing-and-construction
* Ethernet packet header reference: http://cs.colgate.edu/~jsommers/switchyard/reference.html#ethernet-header


Note that the documentation has examples on running Switchyard in test mode and in real mode, along with a walkthrough of creating a simple hub device (similar to what we did in class).


Challenge problem: add "timeouts" to learning switch entries.  Real learning switches remove entries in forwarding tables after T seconds have passed so that the switch can adapt to changes in network topology.  For an optional challenge problem, you can add a timeout capability to your switch.


You should first develop your switch code using the Switchyard test framework.   If you run:
./switchyard/srpy.py -t -s switchtests.srpy myswitch.py


it will execute a series of test cases against your program and display whether the tests pass or fail.  Once you get the tests to pass, you can try running your code in Mininet.


To run your switch in Mininet, run the switchtopo.py custom topology script.  It will create a small network consisting of a single switch with three hosts (client, server1, and server2) in the following configuration (note that only IP addresses of the 3 hosts are shown in the picture; Ethernet MAC addresses for each interface (6 interfaces total) are not shown).


  



To start up Mininet using this script, just type:
$ sudo python switchtopo.py


Once Mininet starts up, you should open a terminal window on the Mininet node named "switch":
mininet> xterm switch


In the window that opens, run your switch in "real" (non-test) mode:
$ . ./py3env/bin/activate # load the "right" python environment
$ ./switchyard/srpy.py myswitch.py


To test whether your switch is behaving correctly, you can do the following:
1. Open terminals on client and server1 (xterm client and xterm server1 from the Mininet prompt)
2. In the server1 terminal, run "wireshark -k".  Wireshark is a program that allows you to "snoop" on network traffic arriving on a network interface.  We'll use this to verify that we see packets arriving at server1 from client.
3. In the terminal on the client node, type "ping -c 2 192.168.100.1".  This command will send two "echo" requests to the server1 node.  The server1 node should respond to each of them if your switch is working correctly.  You should see at the two echo request and echo replies in wireshark running on server1, and you will probably see a couple other packets (e.g., ARP, or Address Resolution Protocol, packets).
4. If you run wireshark on server2, you should not see the echo request and reply packets (but you will see the ARP packets, since they are sent with broadcast destination addresses).


When you're done, submit your myswitch.py code to Moodle.