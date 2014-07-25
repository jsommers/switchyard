#!/usr/bin/env python

'''
Ethernet hub in Python.
'''
import time
import switchyard.lib.address 
import switchyard.lib.packet
from switchyard.switchyard.switchy_common import log_info, NoPackets, Shutdown

def switchy_main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    print ("Entering switchymain: {}".format(mymacs))

    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            print ("Packet intended for me")
        else:
            for intf in my_interfaces:
                if dev != intf.name:
                    print ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
