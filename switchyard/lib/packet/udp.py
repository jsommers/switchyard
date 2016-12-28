import struct

from .packet import PacketHeaderBase
from .common import checksum
from ..exceptions import *

'''
References:
    IETF RFC 768
'''

# FIXME: checksum is broken for ip6

class UDP(PacketHeaderBase):
    __slots__ = ['_src','_dst','_len','_checksum']
    _PACKFMT = '!HHHH'
    _MINLEN = struct.calcsize(_PACKFMT)
    _next_header_map = {}
    _next_header_class_key = ''

    def __init__(self, **kwargs):
        self.src = self.dst = 0
        self._len = self.size()
        self._checksum = 0
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(UDP._PACKFMT)

    def to_bytes(self):
        '''
        Return packed byte representation of the UDP header.
        '''
        return struct.pack(UDP._PACKFMT, self._src, self._dst,
            self._len, self._checksum)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < UDP._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct an UDP object".format(len(raw)))
        fields = struct.unpack(UDP._PACKFMT, raw[:UDP._MINLEN])
        self._src = fields[0]
        self._dst = fields[1]
        self._len = fields[2]
        self._checksum = fields[3]
        return raw[UDP._MINLEN:]

    def __eq__(self, other):
        return self.src == other.src and \
            self.dst == other.dst

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @src.setter
    def src(self,value):
        self._src = value

    @dst.setter
    def dst(self,value):
        self._dst = value

    @property  
    def checksum(self):
        return self._checksum

    def __str__(self):
        return '{} {}->{}'.format(self.__class__.__name__, self.src, self.dst)

    def _compute_checksum_ipv4(self, ip4, xdata):
        if ip4 is None:
            return 0
        xhdr = struct.pack('!IIxBHHHHH', int(ip4.src), int(ip4.dst), 
            ip4.protocol.value, self._len, 
            self.src, self.dst, self._len, 0)
        return checksum(xhdr + xdata)

    def pre_serialize(self, raw, pkt, i):
        self._len = self.size() + len(raw)
        # checksum calc currently assumes we're only dealing with ipv4.
        # will need to be modified for ipv6 support...
        self._checksum = self._compute_checksum_ipv4(pkt.get_header_by_name('IPv4'), raw)
