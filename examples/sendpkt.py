'''
Simple program that uses Switchyard libraries to emit a packet
on every interface that can be opened. 
'''

import switchyard.lib.address 
from switchyard.lib.packet import Ethernet, IPv4, ICMP, EtherType
from switchyard.lib.common import log_info, NoPackets, Shutdown
from switchyard.lib.debug import debugger

def switchy_main(net):
    my_interfaces = net.interfaces() 

    e = Ethernet()
    e.dst = 'ff:ff:ff:ff:ff:ff'
    e.src = '08:00:27:d3:9b:7d'
    e.ethertype = EtherType.IP
    ip = IPv4()
    ip.dstip = '192.168.100.100'
    icmp = ICMP()
    for intf in my_interfaces:
        net.send_packet(intf.name, e + ip + icmp)
    net.shutdown()
