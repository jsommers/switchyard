#!/usr/bin/env python

'''
Ethernet hub in Python.
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

def switchy_main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            for intf in my_interfaces:
                if dev != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
