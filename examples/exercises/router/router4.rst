Router extensions
-----------------

Here are a couple more ideas to consider for extending the functionality of your router:

  * Add a load balancing capability among 2 or more interfaces that are assumed to be connected to links leading to the same far-end destination (either to a single remote router or to multiple co-located routers).  You could create a hash function that uses packet header attributes as input to make a decision about which interface on which to forward the packet.

  * Add a firewall capability to the router.

For a full description of the firewall extension, see the ``firewall`` exercise folder.  For an example description for a RIPv2-like distance vector routing extension, see the ``dvroute`` folder.  For an example description for adding a link-state (OSPF-like) dynamic routing extension, see the ``lsroute`` folder.

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
