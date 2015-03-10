#!/usr/bin/env python

'''
Packet sniffer in Python
'''

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

def switchy_main(net):
    my_interfaces = net.interfaces() 
    log_info ("My interfaces: {}".format([intf.name for intf in my_interfaces]))
    while True:
        try:
            dev,packet = net.recv_packet(timeout=1.0)
        except NoPackets:
            continue
        except Shutdown:
            return

        log_info ("In {} received packet {} on {}".format(net.name, packet, dev))

    net.shutdown()
