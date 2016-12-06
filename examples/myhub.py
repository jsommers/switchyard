#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        try:
            timestamp,dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue

        if eth.dst in mymacs:
            log_info ("Received a packet intended for me")
        else:
            for intf in my_interfaces:
                if dev != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf, packet)
    net.shutdown()
