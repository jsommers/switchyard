from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,SpecialEthAddr
import struct
from switchyard.lib.packet.arp import Arp
from switchyard.lib.packet.ipv4 import IPv4
from switchyard.lib.packet.ipv6 import IPv6
from switchyard.lib.packet.common import EtherType


class Vlan(PacketHeaderBase):
    '''
    Strictly speaking this header doesn't fully represent the 802.1Q header, but
    rather the 2nd half of that header and the "displaced" ethertype
    field from the Ethernet header.  The first two bytes of the 802.1Q header
    basically get treated as the ethertype field in the Ethernet header,
    and that ethertype "points to" this Vlan header for parsing/understanding
    the next 4 bytes (or more, depending on whether QinQ or QinQinQ 
    encapsulation is done).

    first 16 bits is TCI: tag control information
       3 bits: priority code point
       1 bit: drop eligible indicator
       12 bits: vlan id
    '''

    __slots__ = ['__vlanid', '__ethertype']
    __PACKFMT__ = '!HH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self, vlan=0, ethertype=EtherType.IPv4):
        PacketHeaderBase.__init__(self)
        self.vlan = vlan
        self.ethertype = ethertype

    @property
    def vlan(self):
        return self.__vlanid

    @vlan.setter
    def vlan(self, value):
        self.__vlanid = int(value) & 0x0fff # mask out high-order 4 bits

    @property
    def ethertype(self):
        return self.__ethertype

    @ethertype.setter
    def ethertype(self, value):
        self.__ethertype = EtherType(value)

    def from_bytes(self, raw):
        if len(raw) < Vlan.__MINSIZE__:
            raise Exception("Not enough bytes to unpack Vlan header; need {}, only have {}".format(Vlan.__MINSIZE__, len(raw)))
        fields = struct.unpack(Vlan.__PACKFMT__, raw[:Vlan.__MINSIZE__])
        self.vlan = fields[0]
        self.ethertype = fields[1]
        return raw[Vlan.__MINSIZE__:]

    def to_bytes(self):
        return struct.pack(Vlan.__PACKFMT__, self.__vlanid, self.__ethertype.value)

    def __eq__(self, other):
        return self.vlan == other.vlan and self.ethertype == other.ethertype

    def size(self):
        return Vlan.__MINSIZE__

    def tail_serialized(self, raw):
        pass

    def next_header_class(self):
        return EtherTypeClasses[self.ethertype]

    def __str__(self):
        return '{} {} {}'.format(self.__class__.__name__, self.vlan, self.ethertype)

EtherTypeClasses = {
    EtherType.IP: IPv4,
    EtherType.ARP: Arp,
    EtherType.IPv6: IPv6,
    EtherType.x8021Q: Vlan,
}


class Ethernet(PacketHeaderBase):
    __slots__ = ['__src','__dst','__ethertype']
    __PACKFMT__ = '!6s6sH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self, src=SpecialEthAddr.ETHER_ANY.value, dst=SpecialEthAddr.ETHER_ANY.value,ethertype=EtherType.IP):
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
        return struct.pack(Ethernet.__PACKFMT__, self.__src.packed, self.__dst.packed, self.__ethertype.value)

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
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.ethertype))
        return cls

    def tail_serialized(self, raw):
        pass

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.ethertype == other.ethertype

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.src, self.dst, self.ethertype)


if __name__ == '__main__':
    e = Ethernet()
    e2 = Ethernet()
    ip = IPv4()
    print (e,e2,ip)
    packet = e + ip
    print (packet)
    for ph in packet:
        print (ph)

    a = Arp()
    e = Ethernet()
    e.ethertype = EtherType.ARP
    p = e + a
    print (p.headers())
    raw = p.to_bytes()
    px = Packet(raw)

    e = Ethernet(ethertype=EtherType.x8021Q)
    v = Vlan(ethertype=EtherType.IP, vlan=10)
    ip = IPv4()
    from switchyard.lib.packet import ICMP
    icmp = ICMP()
    p = e+v+ip+icmp
    print (p)

    raw = p.to_bytes()
    p2 = Packet(raw)
