Message board reliable transport protocol
-----------------------------------------

The goal of the second part of the exercise is to create a UDP-based network stack, which can be used by the client created in part 1 (and also by the server).  The network stack will implement a static window-based form of reliable transport.  After you've implementing this protocol, any lost datagrams between client and server or vice versa should be retransmitted.  Thus, the application should be resilient to any badness going on in the network.  Just to exercise that, you'll create a bit of mischief in the third part of this exercise.

Overview
--------

Your reliable transport protocol will operate on *packets*, not on *bytes* like TCP.  Thus, when you emit an acknowledgment, it will be for a given packet sequence number. 

The reliable transport protocol should operate in *both* directions, from MBclient to MBserver, and also from MBserver to MBclient.  As a result, you'll need to keep track of sequence numbers, acks, and windows for both directions.

Reliable protocol details
-------------------------

An endpoint will send and receive variable-sized IP packets and ACKs.  It will implement a *fixed-size* sender window (SW) and use coarse timeouts.  Let's define two variables, LHS and RHS (both always >= 1), where these variables correspond to the sequence numbers of two packets that have been sent but not necessariliy ACKed yet.  These numbers indicate the lowest and highest sequence numbers for which we are willing to accept an ACK.  They must *always* satisfy the following equation::

    C1: RHS - LHS + 1 <= SW

SW effectively puts a limit on the maximum number of unACKed packets that can be in flight between one endpoint and another.  Logic of changing the RHS is simple: as an endpoint sends packets, it increments the RHS value while being sure *not* to violate the previous condition.  Changing LHS, however, is more tricky.   LHS tells us the packet with the lowest sequence number s_i such that::

    C2: Every packet with sequence number s_j < s_i has been successfully ACKed

Let's look at the following example to better understand this.  Numbers in the boxes indicate the sequence number associated with each packet.  Suppose SW=5.  Initially, LHS=1 and RHS=1::
Let's look at the following example to better understand this.  Numbers in the boxes indicate the sequence number associated with each packet.  Suppose SW=5.  Initially, LHS=1 and RHS=1:

+---+---+---+---+---+
| 1 | 2 | 3 | 4 | 5 |
+---+---+---+---+---+
|LHS|   |   |   |   |
|RHS|   |   |   |   |
+---+---+---+---+---+


Based on what's been discussed above so far, when packets are sent, RHS will increment.  After sending the first 5 packets and not receiving any ACKs, the SW will look like the following:

+---+---+---+---+---+
| 1 | 2 | 3 | 4 | 5 |
+---+---+---+---+---+
|LHS|   |   |   |RHS|
+---+---+---+---+---+

Note that we cannot move RHS any further, or we will violate C1.  This also means that we cannot send any new packets until ACKs are received.  Let's assume that ACKs for packets 1 and 2 arrive.  In this case, LHS should now point to 3 and therefore we can move RHS to 7:

+---+---+---+---+---+
| 3 | 4 | 5 | 6 | 7 |
+---+---+---+---+---+
|LHS|   |   |   |RHS|
+---+---+---+---+---+

Now let's assume that the packets 3 and 4 are dropped or mutilated, which means that the far end point won't be able to ACK them.  Also assume that after some time, ACKs for packets 5 and 6 arrive.  Thus, we have:

+---+---+----+----+---+
| 3 | 4 | 5  | 6  | 7 |
+---+---+----+----+---+
|LHS|   |ackd|ackd|RHS|
+---+---+----+----+---+

Notice that even though the sender received some ACKs for its outstanding packets, since C2 is not satisfied LHS cannot be moved ahead, which also prevents RHS from moving forward (to avoid violating C1).  Unless we implement some additional mechanisms, we'll be stuck in this position forever.  

To get out of this predicament, we will use *coarse timeouts*.  When ever LHS gets stuck in a position for a certain amount of time, unACKed packets will be retransmitted.  So, given the above example, once a timeout occurs, the sender would retransmit packets 3, 4, and 7.  Note that some "interesting" situations can still occur: the sender could receive an ACK for the original transmission of a packet after retransmitting it, or the sender could receive duplicate ACKs.  For this exercise, you can ignore these fun situations: just keep track of whether a packet has been ACKed or not.

Sequence numbers, ACKs, and timeouts: details
---------------------------------------------

Sequence numbers and acknowledgement numbers will be carried in a special new header that you create.  It will go *after* the UDP header, and before any application data.  The format should just be:

+------------------+------------------+
|  seq # (32 bits) |  ack # (32 bits) |
+------------------+------------------+

These values should be encoded in *big-endian* (network byte order) format.  I'd recommend using the Python ``struct`` module for encoding and decoding integers to/from the network.

A value of 0 for either the sequence or ack means that the receiver should *ignore* the value.  Note that this implies that:

 * One of either the sequence or ack number should be non-zero.
 * If the ack field is non-zero, the packet is an acknowledgment for the given packet number
 * If the sequence field is non-zero, there should be some data to follow this header (i.e., message board application data).
 * It is possible for both seq and ack to be non-zero.  In this case, there should be data to follow (seq indicates the sequence number of this data), and ack is the acknowledgment number for some previously sent packet.

The same window size should be used for each direction of packet flow.  The default window size should be set as 8.

The default timeout value should be set to 0.1 seconds (100 milliseconds).  This can be a static value; you do not need to estimate a timeout value by computing round-trip time.

Acknowledgment
--------------

This description is based on a writeup created by Ceyhun Alp at the University of Wisconsin.

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
