#!/usr/bin/env python

'''
Ethernet hub in Python.
'''
import cn_toolbelt.lib.address 
import cn_toolbelt.lib.packet
from cn_toolbelt.switchyard.switchy_common import log_info, NoPackets, Shutdown

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

        if packet.dst in mymacs:
            log_info("Packet intended for me")
        else:
            log_info("Flooding packet")
            for intf in my_interfaces:
                if dev != intf.name:
                    net.send_packet(intf.name, packet)
    net.shutdown()
