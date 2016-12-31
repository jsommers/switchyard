Router extensions
-----------------

Here are three ideas to consider for extending the functionality of your router:

  * Add a load balancing capability among 2 or more interfaces that are assumed to be connected to links leading to the same far-end destination (either to a single remote router or to multiple co-located routers).  You could create a hash function that uses packet header attributes as input to make a decision about which interface on which to forward the packet.
  * Add a dynamic routing capability; instead of using a static forwarding table, dynamically compute routes through a network.  You could implement something similar to RIPv2 or a simplified version of a protocol like OSPF.
  * Add a firewall capability to the router.

For a full description of the firewall extension, see the ``firewall`` exercise folder.

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
