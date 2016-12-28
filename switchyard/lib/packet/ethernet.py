import struct
from .packet import PacketHeaderBase,Packet
from ..address import EthAddr,SpecialEthAddr
from .arp import Arp
from .ipv4 import IPv4
from .ipv6 import IPv6
from .common import EtherType
from ..exceptions import *


class Vlan(PacketHeaderBase):
    '''
    Strictly speaking this header doesn't fully represent the 802.1Q header, 
    but rather the 2nd half of that header and the "displaced" ethertype
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
    _next_header_map = {
        EtherType.IP: IPv4,
        EtherType.ARP: Arp,
        EtherType.IPv6: IPv6,
        EtherType.NoType: None,
    }
    _next_header_class_key = '_ethertype'

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
    def vlanid(self):
        return self._vlanid

    @vlanid.setter
    def vlanid(self, value):
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
            raise NotEnoughDataError("Not enough bytes to unpack Vlan header; need {}, "
                "only have {}".format(Vlan._MINLEN, len(raw)))
        fields = struct.unpack(Vlan._PACKFMT, raw[:Vlan._MINLEN])
        self.vlanid = fields[0]
        self.pcp = ((fields[0] & 0xf000) >> 12)
        self.ethertype = fields[1]
        return raw[Vlan._MINLEN:]

    def to_bytes(self):
        return struct.pack(Vlan._PACKFMT, ((self._pcp << 12) | self._vlanid), 
            self._ethertype.value)

    def __eq__(self, other):
        return isinstance(other, Vlan) and \
            self.vlanid == other.vlanid and self.ethertype == other.ethertype

    def size(self):
        return Vlan._MINLEN

    def __str__(self): return '{} {} {}'.format(self.__class__.__name__,
    self.vlanid,  self.ethertype.name)


class Ethernet(PacketHeaderBase):
    __slots__ = ['_src','_dst','_ethertype']
    _PACKFMT = '!6s6sH'
    _MINLEN = struct.calcsize(_PACKFMT)
    _next_header_map = {
        EtherType.IP: IPv4,
        EtherType.ARP: Arp,
        EtherType.IPv6: IPv6,
        EtherType.x8021Q: Vlan,
        EtherType.NoType: None,
    }
    _next_header_class_key = '_ethertype'

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
        return struct.pack(Ethernet._PACKFMT, self._dst.packed, 
            self._src.packed, self._ethertype.value)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
        Exception if we can't resurrect the packet.'''
        if len(raw) < Ethernet._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct an "
                "Ethernet object".format(len(raw)))
        dst,src,ethertype = struct.unpack(Ethernet._PACKFMT, 
            raw[:Ethernet._MINLEN])
        self.src = src
        self.dst = dst
        if ethertype <= 1500:
            self.ethertype = EtherType.NoType
        else:
            self.ethertype = ethertype
        return raw[Ethernet._MINLEN:]

    def __eq__(self, other):
        return isinstance(other, Ethernet) and \
            self.src == other.src and self.dst == other.dst and \
            self.ethertype == other.ethertype

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, 
            self.src, self.dst, self.ethertype.name)
