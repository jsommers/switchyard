#!/usr/bin/env python

import switchyard.lib.address 
from switchyard.lib.packet import *
from switchyard.lib.common import log_info, log_debug, NoPackets, Shutdown
from switchyard.lib.debug import debugger
from switchyard.lib.socket import ApplicationLayer

def main(net):
    intf = net.ports()[0]
    print(intf)

    while True:

        data = None
        try:
            data,localaddr,remoteaddr = ApplicationLayer.recv_from_app(timeout=1.0)
        except NoPackets:
            pass
        except Shutdown:
            return

        if data is not None:
            log_debug("Received data from app layer: <{}>".format(data))
            p = Ethernet() + IPv4() + UDP() + data
            p[0].src = '68:a8:6d:04:bd:86'
            p[0].dst = '9c:d3:6d:e6:6f:13'
            p[1].protocol = IPProtocol.UDP
            p[1].srcip = str(intf.ipaddr)  # '127.0.0.1' # localaddr[0]
            p[2].srcport = localaddr[1]
            p[1].dstip = remoteaddr[0]
            p[2].dstport = remoteaddr[1]
            print ("Sending {} to {}".format(p, intf.name))
            # net.send_packet(intf.name, p)

        packet = None
        try:
            dev,packet = net.recv_packet(timeout=1.0)
        except NoPackets:
            pass
        except Shutdown:
            return

        if packet is not None:
            ipidx = packet.get_header_index(IPv4)
            log_debug("Received packet {} on {}".format(packet, dev))
            ApplicationLayer.send_to_app(packet[-1].to_bytes(), (packet[ipidx].srcip, packet[ipidx+1].srcport), (packet[ipidx].dstip, packet[ipidx+1].dstport) )


    net.shutdown()
