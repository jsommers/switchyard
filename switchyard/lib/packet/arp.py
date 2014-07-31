from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
import struct
from enum import Enum
from switchyard.lib.packet.ethcommon import EtherType

'''
References:
    Plummer, D., "RFC826", An Ethernet Address Resolution Protocol.
    http://en.wikipedia.org/wiki/Address_Resolution_Protocol
'''

class ArpHwType(Enum):
    Ethernet = 1

class ArpOperation(Enum):
    Request = 1
    Reply = 2

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
        self.senderhwaddr = SpecialEthAddr.ETHER_ANY
        self.senderprotoaddr = SpecialIPv4Addr.IP_ANY
        self.targethwaddr = SpecialEthAddr.ETHER_BROADCAST
        self.targetprotoaddr = SpecialIPv4Addr.IP_ANY

    def size(self):
        return struct.calcsize(Arp.__PACKFMT__)

    def to_bytes(self):
        '''
        Return packed byte representation of the ARP header.
        '''
        return struct.pack(Arp.__PACKFMT__, self.__hwtype.value, self.__prototype.value, self.__hwaddrlen, self.__protoaddrlen, self.__operation, self.__senderhwaddr.packed, self.__senderprotoaddr.packed, self.__targethwaddr.packed, self.__targetprotoaddr.packed)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < Arp.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an Arp object".format(len(raw)))
        fields = struct.unpack(Ethernet.__PACKFMT__, raw[:Arp.__MINSIZE__])
        try:
            self.__hwtype = ArpHwType(fields[0])
            self.__prototype = EtherType(fields[1])
            self.__hwaddrlen = fields[2]
            self.__protoaddrlen = fields[3]
            self.operation = ArpOperation(fields[4])
            self.senderhwaddr = EthAddr(fields[5])
            self.senderprotoaddr = EthAddr(fields[6])
            self.targethwaddr = EthAddr(fields[7])
            self.targetprotoaddr = EthAddr(fields[8])
        except Exception as e:
            raise Exception("Error constructing Arp packet object from raw bytes: {}".format(str(e)))
        return raw[Arp.__MINSIZE__:]

    def __eq__(self, other):
        return self.hardwaretype == other.hardwaretype and \
               self.protocoltype == other.protocoltype and \
               self.hwaddrlen == other.hwaddrlen and \
               self.protoaddrlen == other.protoaddrlen and \
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

if __name__ == '__main__':
    a = Arp()
    print (a)
    print (a.to_bytes())

