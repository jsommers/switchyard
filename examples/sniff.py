#!/usr/bin/env python

'''
Packet sniffer in Python
'''
import time
import switchyard.lib.address 
import switchyard.lib.packet
from switchyard.lib.common import log_info, NoPackets, Shutdown
from switchyard.lib.debug import debugger

def switchy_main(net):
    my_interfaces = net.interfaces() 
    print ("My interfaces: {}".format([intf.name for intf in my_interfaces]))
    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print ("In {} received packet {} on {}".format(net.name, packet, dev))
    net.shutdown()
