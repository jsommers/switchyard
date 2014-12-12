Introduction and Overview
=========================


SRPY is a Python library for developing and testing network device implementations such as Ethernet switches and bridges, and IP routers and firewalls.  It is intended for classroom use: it isn't intended to be fast, but rather intended to facilitate testing and understanding the network code being developed.

SRPY stands for "software switches and routers in Python" and is loosely based on the "sr" (software router) project part of the "Building an Internet Router" class at Stanford University (http://yuba.stanford.edu/cs344/).

The goal of SRPY is to enable creating the "brains" of a network device like a switch or router.  SRPY assumes that each device has 1 or more "interfaces" or "ports".  Each interface has at minimum a string name (e.g., eth0), and an Ethernet address.  An interface may also have an IP address and a subnet mask associated with it.  Each interface can be assumed to have a (virtual) cable plugged into it, which connects to either a switch, router, or some end host.  The goal of a SRPY-based program is typically to receive a packet on one port, possibly modify it, then either forward it on one or more interfaces, or drop the packet.

