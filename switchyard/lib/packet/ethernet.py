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

    __slots__ = ['_vlanid', '_pcp', '_ethertype']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        '''
        VLAN constructor accepts an initial VLAN Id and the EtherType
        of the next header.
        '''
        self._vlanid = 0
        self._pcp = 0
        self._ethertype = EtherType.IP
        super().__init__(**kwargs)

    @property
    def vlan(self):
        return self._vlanid

    @vlan.setter
    def vlan(self, value):
        self._vlanid = int(value) & 0x0fff # mask out high-order 4 bits

    @property
    def pcp(self):
        return self._pcp

    @pcp.setter
    def pcp(self, value):
        self._pcp = max(min(int(value),3),0)

    @property
    def ethertype(self):
        return self._ethertype

    @ethertype.setter
    def ethertype(self, value):
        self._ethertype = EtherType(value)

    def from_bytes(self, raw):
        if len(raw) < Vlan._MINLEN:
            raise Exception("Not enough bytes to unpack Vlan header; need {}, only have {}".format(Vlan._MINLEN, len(raw)))
        fields = struct.unpack(Vlan._PACKFMT, raw[:Vlan._MINLEN])
        self.vlan = fields[0]
        self.pcp = ((fields[0] & 0xf000) >> 12)
        self.ethertype = fields[1]
        return raw[Vlan._MINLEN:]

    def to_bytes(self):
        return struct.pack(Vlan._PACKFMT, ((self._pcp << 12) | self._vlanid), self._ethertype.value)

    def __eq__(self, other):
        return self.vlan == other.vlan and self.ethertype == other.ethertype

    def size(self):
        return Vlan._MINLEN

    def pre_serialize(self, raw, pkt, i):
        pass

    def next_header_class(self):
        return EtherTypeClasses[self.ethertype]

    def __str__(self):
        return '{} {} {}'.format(self.__class__.__name__, self.vlan, self.ethertype.name)

EtherTypeClasses = {
    EtherType.IP: IPv4,
    EtherType.ARP: Arp,
    EtherType.IPv6: IPv6,
    EtherType.x8021Q: Vlan,
    EtherType.NoType: None,
}


class Ethernet(PacketHeaderBase):
    __slots__ = ['_src','_dst','_ethertype']
    _PACKFMT = '!6s6sH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._src = self._dst = EthAddr()
        self._ethertype = EtherType.IP
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(Ethernet._PACKFMT)

    @property
    def src(self):
        return self._src

    @src.setter
    def src(self, value):
        self._src = EthAddr(value)

    @property
    def dst(self):
        return self._dst

    @dst.setter
    def dst(self, value):
        self._dst = EthAddr(value)

    @property
    def ethertype(self):
        return self._ethertype

    @ethertype.setter
    def ethertype(self, value):
        self._ethertype = EtherType(value)

    def to_bytes(self):
        '''
        Return packed byte representation of the Ethernet header.
        '''
        return struct.pack(Ethernet._PACKFMT, self._dst.packed, self._src.packed, self._ethertype.value)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
        Exception if we can't resurrect the packet.'''
        if len(raw) < Ethernet._MINLEN:
            raise Exception("Not enough bytes ({}) to reconstruct an Ethernet object".format(len(raw)))
        dst,src,ethertype = struct.unpack(Ethernet._PACKFMT, raw[:Ethernet._MINLEN])
        self.src = src
        self.dst = dst
        if ethertype <= 1500:
            self.ethertype = EtherType.NoType
        else:
            self.ethertype = ethertype

        return raw[Ethernet._MINLEN:]

    def next_header_class(self):
        if self.ethertype not in EtherTypeClasses:
            raise Exception("No mapping for ethertype {} to a packet header class".format(self.ethertype))
        cls = EtherTypeClasses.get(self.ethertype, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.ethertype))
        return cls

    def pre_serialize(self, raw, pkt, i):
        pass

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.ethertype == other.ethertype

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.src, self.dst, self.ethertype.name)

