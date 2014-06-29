from cn_toolbelt.lib.packet.packet import PacketHeaderBase,Packet
from cn_toolbelt.lib.address import EthAddr
import struct
from enum import Enum

class EtherType(Enum):
    IP = 0x0800
    ARP = 0x0806
    _8021Q = 0x8100
    IPV6 = 0x86dd
    SLOW = 0x8809
    MPLS = 0x8847
    _8021AD = 0x88a8
    LLDP = 0x88cc
    _8021AH = 0x88e7
    IEEE802_3 = 0x05dc

EtherTypeClasses = {
    EtherType.IP: None
}

class Ethernet(PacketHeaderBase):
    __slots__ = ['__src','__dst','__ethertype']
    __PACKFMT__ = '!6s6sH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self, src='00:00:00:00:00:00',dst='00:00:00:00:00:00',ethertype=EtherType.IP):
        PacketHeaderBase.__init__(self)
        self.__src = EthAddr(src)
        self.__dst = EthAddr(dst)
        self.__ethertype = EtherType(ethertype)

    def size(self):
        return struct.calcsize(Ethernet.__PACKFMT__)

    @property
    def src(self):
        return self.__src

    @src.setter
    def src(self, value):
        self.__src = EthAddr(value)

    @property
    def dst(self):
        return self.__dst

    @dst.setter
    def dst(self, value):
        self.__dst = EthAddr(value)

    @property
    def ethertype(self):
        return self.__ethertype

    @ethertype.setter
    def ethertype(self, value):
        self.__ethertype = EtherType(value)

    def to_bytes(self):
        '''
        Return packed byte representation of the Ethernet header.
        '''
        return struct.pack(Ethernet.__PACKFMT__, self.__src.raw, self.__dst.raw, self.__ethertype.value)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
        Exception if we can't resurrect the packet.'''
        if len(raw) < Ethernet.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an Ethernet object".format(len(raw)))
        src,dst,ethertype = struct.unpack(Ethernet.__PACKFMT__, raw[:Ethernet.__MINSIZE__])
        self.src = src
        self.dst = dst
        self.ethertype = ethertype
        return raw[Ethernet.__MINSIZE__:]

    def next_header_class(self):
        if self.ethertype not in EtherTypeClasses:
            raise Exception("No mapping for ethertype {} to a packet header class".format(self.ethertype))
        cls = EtherTypeClasses.get(self.ethertype, None)
        # FIXME: Warn!!
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.ethertype))
        return cls

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.ethertype == other.ethertype


if __name__ == '__main__':
    e = Ethernet()
    e2 = Ethernet()
    e3 = Ethernet()
    print (e,e2,e3)
    packet = e + e2
    print (packet)
    for ph in packet:
        print (ph)
    packet2 = Packet()
    packet2 += e3
    packet3 = packet + packet2
    print ("Packet 1")
    for ph in packet:
        print (ph)
    print ("Packet 2")
    for ph in packet2:
        print (ph)
    print ("Packet 3")
    for ph in packet3:
        print (ph)
    b = packet.to_bytes()
    print (b)

    p = Packet(b)
    print (p)
    for i,ph in enumerate(p):
        print (i,ph)
