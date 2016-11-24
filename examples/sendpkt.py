'''
Simple program that uses Switchyard libraries to emit a packet
on every interface that can be opened. 
'''

from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 

    eth = Ethernet()
    eth.dst = 'ff:ff:ff:ff:ff:ff'
    eth.ethertype = EtherType.IP
    ip = IPv4()
    ip.dstip = '192.168.100.100'
    icmp = ICMP()
    for intf in my_interfaces:
        eth.src = intf.ethaddr
        try:
            net.send_packet(intf.name, eth + ip + icmp)
        except Exception as e:
            log_failure("Can't send packet: {}".format(str(e)))
    net.shutdown()
