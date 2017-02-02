Application layer
-----------------

Note: these exercises are a work in progress and some details may not be clear or correctly included yet.  

This exercise has three parts. In the first part, the goal is to create a Python socket-based client for a "message board" application.  The server with this the client should communicate is already written; only the client needs to be created.  This part of the project does *not* require any use of Switchyard --- only the built-in Python ``socket`` module is used.  UDP is used as as the transport protocol.

The goal of the second part of the exercise is to create a UDP-based network stack, which can be used by the client created in part 1 (and also by the server).  The network stack will implement a static window-based form of reliable transport.

The goal of the third and final part of the exercise is to create a simple middlebox device to introduce packet loss in the network.  This part can either be done with "hard-coded" Ethernet address/IPv4 address mappings, or can implement ARP to operate in a more flexible manner.

The three parts of this exercise are described in detail in three separate documents found in this folder:

 * ``msgboardapp.rst``

 * ``msgboardstack.rst``

 * ``msgboardmiddlebox.rst``



License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/
