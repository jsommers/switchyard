'''
Simple program that uses Switchyard libraries to emit a packet
on every interface that can be opened. 
'''

from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 

    e = Ethernet()
    e.dst = 'ff:ff:ff:ff:ff:ff'
    e.ethertype = EtherType.IP
    ip = IPv4()
    ip.dstip = '192.168.100.100'
    icmp = ICMP()
    for intf in my_interfaces:
        e.src = intf.ethaddr
        net.send_packet(intf.name, e + ip + icmp)
    net.shutdown()
