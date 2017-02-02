Message board application middlebox
-----------------------------------

The goal of the third and final part of the exercise is to create a simple middlebox device to introduce packet loss in the network.  This part can either be done with "hard-coded" Ethernet address/IPv4 address mappings, or can implement ARP to operate in a more flexible manner.

You'll implement this device using the Switchyard framework.  It will only have two ports, with one port handling traffic to/from a MBclient, and the other port handling traffic to/from a MBserver.  When ever a packet arrives on one port, it should be forwarded out the other port, and vice versa.  There is no need for any explicit routing.

Here's the "fun" part: although there's a pretty dumb forwarding mechanism used by the device, it will also be in charge of probabilistically dropping packets to simulate the evil sorts of things that can happen in a real network.  Packet drops should only happen in the MBserver to MBclient direction, not the other way around.

The ``main`` function of your middlebox device should accept, in addition to the ``net`` object, a floating point number between 0 and 1 which represents the probability of dropping a given packet.

That's it!  

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
