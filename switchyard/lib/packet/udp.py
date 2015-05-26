from switchyard.lib.packet.packet import PacketHeaderBase
from switchyard.lib.packet.common import checksum
import struct

'''
References:
    IETF RFC 768
'''

# FIXME: currently does *nothing* about checksum

class UDP(PacketHeaderBase):
    __slots__ = ['_srcport','_dstport','_len','_checksum']
    _PACKFMT = '!HHHH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self.srcport = self.dstport = 0
        self._len = self.size()
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(UDP._PACKFMT)

    def to_bytes(self):
        '''
        Return packed byte representation of the UDP header.
        '''
        return struct.pack(UDP._PACKFMT, self._srcport, self._dstport,
            self._len, self._checksum)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < UDP._MINLEN:
            raise Exception("Not enough bytes ({}) to reconstruct an UDP object".format(len(raw)))
        fields = struct.unpack(UDP._PACKFMT, raw[:UDP._MINLEN])
        self._srcport = fields[0]
        self._dstport = fields[1]
        self._len = fields[2]
        self._checksum = fields[3]
        return raw[UDP._MINLEN:]

    def __eq__(self, other):
        return self.srcport == other.srcport and \
            self.dstport == other.dstport

    @property
    def srcport(self):
        return self._srcport

    @property
    def dstport(self):
        return self._dstport

    @srcport.setter
    def srcport(self,value):
        self._srcport = value

    @dstport.setter
    def dstport(self,value):
        self._dstport = value

    @property  
    def checksum(self):
        return self._checksum

    def __str__(self):
        return '{} {}->{}'.format(self.__class__.__name__, self.srcport, self.dstport)

    def next_header_class(self):
        return None

    def _compute_checksum_ipv4(self, ip4, xdata):
        if ip4 is None:
            return 0
        xhdr = struct.pack('!IIxBHHHHH', int(ip4.srcip), int(ip4.dstip), 
            ip4.protocol.value, self._len, 
            self.srcport, self.dstport, self._len, 0)
        return checksum(xhdr + xdata)

    def pre_serialize(self, raw, pkt, i):
        self._len = self.size() + len(raw)
        # checksum calc currently assumes we're only dealing with ipv4.
        # will need to be modified for ipv6 support...
        self._checksum = self._compute_checksum_ipv4(pkt.get_header_by_name('IPv4'), raw)
