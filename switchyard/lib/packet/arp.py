from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
import struct
from switchyard.lib.packet.common import EtherType, ArpHwType, ArpOperation

'''
References:
    Plummer. 
        "RFC826", An Ethernet Address Resolution Protocol.
    Finlayson, Mann, Mogul, and Theimer. 
        "RFC903", A Reverse Address Resolution Protocol.
    http://en.wikipedia.org/wiki/Address_Resolution_Protocol
'''

class Arp(PacketHeaderBase):
    __slots__ = ['__hwtype','__prototype','__hwaddrlen','__protoaddrlen',
                 '__operation','__senderhwaddr','__senderprotoaddr',
                 '__targethwaddr','__targetprotoaddr']
    __PACKFMT__ = '!HHBBH6s4s6s4s'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.__hwtype = ArpHwType.Ethernet
        self.__prototype = EtherType.IP
        self.__hwaddrlen = 6
        self.__protoaddrlen = 4
        self.operation = ArpOperation.Request
        self.senderhwaddr = SpecialEthAddr.ETHER_ANY.value
        self.senderprotoaddr = SpecialIPv4Addr.IP_ANY.value
        self.targethwaddr = SpecialEthAddr.ETHER_BROADCAST.value
        self.targetprotoaddr = SpecialIPv4Addr.IP_ANY.value

    def size(self):
        return struct.calcsize(Arp.__PACKFMT__)

    def tail_serialized(self, raw):
        pass

    def to_bytes(self):
        '''
        Return packed byte representation of the ARP header.
        '''
        return struct.pack(Arp.__PACKFMT__, self.__hwtype.value, self.__prototype.value, self.__hwaddrlen, self.__protoaddrlen, self.__operation.value, self.__senderhwaddr.packed, self.__senderprotoaddr.packed, self.__targethwaddr.packed, self.__targetprotoaddr.packed)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < Arp.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an Arp object".format(len(raw)))
        fields = struct.unpack(Arp.__PACKFMT__, raw[:Arp.__MINSIZE__])
        try:
            self.__hwtype = ArpHwType(fields[0])
            self.__prototype = EtherType(fields[1])
            self.__hwaddrlen = fields[2]
            self.__protoaddrlen = fields[3]
            self.operation = ArpOperation(fields[4])
            self.senderhwaddr = EthAddr(fields[5])
            self.senderprotoaddr = IPAddr(fields[6])
            self.targethwaddr = EthAddr(fields[7])
            self.targetprotoaddr = IPAddr(fields[8])
        except Exception as e:
            raise Exception("Error constructing Arp packet object from raw bytes: {}".format(str(e)))
        return raw[Arp.__MINSIZE__:]

    def __eq__(self, other):
        return self.hardwaretype == other.hardwaretype and \
               self.protocoltype == other.protocoltype and \
               self.operation == other.operation and \
               self.senderhwaddr == other.senderhwaddr and \
               self.senderprotoaddr == other.senderprotoaddr and \
               self.targethwaddr == other.targethwaddr and \
               self.targetprotoaddr == other.targetprotoaddr 

    @property
    def hardwaretype(self):
        return self.__hwtype

    @property
    def protocoltype(self):
        return self.__prototype

    @property
    def operation(self):
        return self.__operation

    @operation.setter
    def operation(self, value):
        self.__operation = ArpOperation(value)

    @property
    def senderhwaddr(self):
        return self.__senderhwaddr

    @senderhwaddr.setter
    def senderhwaddr(self, value):
        self.__senderhwaddr = EthAddr(value)

    @property
    def senderprotoaddr(self):
        return self.__senderprotoaddr

    @senderprotoaddr.setter
    def senderprotoaddr(self, value):
        self.__senderprotoaddr = IPAddr(value)

    @property
    def targethwaddr(self):
        return self.__targethwaddr

    @targethwaddr.setter
    def targethwaddr(self, value):
        self.__targethwaddr = EthAddr(value)

    @property
    def targetprotoaddr(self):
        return self.__targetprotoaddr

    @targetprotoaddr.setter
    def targetprotoaddr(self, value):
        self.__targetprotoaddr = IPAddr(value)

    def next_header_class(self):
        '''
        No other headers should follow ARP.
        '''
        return None

    def __str__(self):
        return '{} {}:{} {}:{}'.format(self.__class__.__name__, 
            self.senderhwaddr, self.senderprotoaddr,
            self.targethwaddr, self.targetprotoaddr)

if __name__ == '__main__':
    from switchyard.lib.packet import Ethernet,Packet
    a = Arp()
    e = Ethernet()
    print (a)
    print (a.to_bytes())
    p = e + a
    print (p)
    print (p.headers())
    p = Packet()
    p += e
    p += a
    print (p.headers())
    from switchyard.lib.packet.util import create_ip_arp_request

    p = create_ip_arp_request("00:00:00:11:22:33","1.2.3.4","10.11.12.13")
    x = p.to_bytes()
    print (p.to_bytes())

    px = Packet(raw=x)
    print ("px",px.headers())
    print ("p",p.headers())
    assert(p == px)
