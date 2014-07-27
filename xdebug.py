#!/usr/bin/env python

'''
Ethernet hub in Python.
'''
import time
import switchyard.lib.address 
import switchyard.lib.packet
from switchyard.switchyard.switchy_common import log_info, NoPackets, Shutdown

def switchy_main(net):

    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print ("DEBUG received packet {} on {}".format(dev, packet))

    net.shutdown()
