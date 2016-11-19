from . import *

def create_ip_arp_reply(srchw, dsthw, srcip, targetip):
    '''
    Create an ARP reply (just change what needs to be changed
    from a request)
    '''
    pkt = create_ip_arp_request(srchw, srcip, targetip)
    pkt[0].dst = dsthw
    pkt[1].operation = ArpOperation.Reply
    pkt[1].targethwaddr = dsthw
    return pkt

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
    arp.targethwaddr = SpecialEthAddr.ETHER_BROADCAST.value
    arp.targetprotoaddr = targetip
    return ether + arp
