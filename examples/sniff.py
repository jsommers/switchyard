#!/usr/bin/env python

'''
Packet sniffer in Python
'''

from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    log_info ("My interfaces: {}".format([intf.name for intf in my_interfaces]))
    while True:
        try:
            timestamp,dev,packet = net.recv_packet(timeout=1.0)
        except NoPackets:
            continue
        except Shutdown:
            return

        log_info ("In {} received packet {} on {}".format(net.name, packet, dev))

    net.shutdown()
