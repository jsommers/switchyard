#!/usr/bin/env python3
'''
Simple program that uses Switchyard libraries to emit a packet
on every interface that can be opened. 
'''

from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 

    eth = Ethernet(dst='ff:ff:ff:ff:ff:ff')
    ip = IPv4(dst='192.168.100.100', ttl=16, protocol=IPProtocol.ICMP)
    icmp = ICMP(icmptype=ICMPType.EchoRequest)
    icmp.icmpdata.sequence = 1
    icmp.icmpdata.identifier = 13
    pkt = eth+ip+icmp
    for intf in my_interfaces:
        eth.src = intf.ethaddr
        ip.src = intf.ipaddr
        print("Sending {} out {}".format(pkt, intf.name))
        try:
            net.send_packet(intf.name, pkt)
        except Exception as e:
            log_failure("Can't send packet: {}".format(str(e)))
    net.shutdown()
