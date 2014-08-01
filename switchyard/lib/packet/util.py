from switchyard.lib.packet import *

def create_ip_arp_request(srchw, srcip, targetip):
    '''
    Create and return a packet containing an Ethernet header
    and ARP header.
    '''
    ether = Ethernet()
    ether.src = srchw
    ether.dst = SpecialEthAddr.ETHER_BROADCAST.value
    ether.ethertype = EtherType.ARP
    arp = Arp()
    arp.operation = ArpOperation.Request
    arp.senderhwaddr = srchw
    arp.senderprotoaddr = srcip
    arp.targethwaddr = SpecialEthAddr.ETHER_ANY.value
    arp.targetprotoaddr = targetip
    return ether + arp
