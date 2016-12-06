#!/usr/bin/env python3

'''
Packet sniffer in Python
'''

from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    log_info ("My interfaces: {}".format([intf.name for intf in my_interfaces]))
    count = 0
    while True:
        try:
            timestamp,dev,packet = net.recv_packet(timeout=1.0)
        except NoPackets:
            continue
        except Shutdown:
            return

        log_info("{:.3f}: {} {}".format(timestamp,dev,packet))
        count += 1

    net.shutdown()
    print ("Got {} packets.".format(count))
