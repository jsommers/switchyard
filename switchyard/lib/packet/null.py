from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.packet.ipv4 import IPv4
from switchyard.lib.packet.ipv6 import IPv6
import struct
import socket

AFTypeClasses = {
    socket.AF_INET: IPv4,
    socket.AF_INET6: IPv6
}

class Null(PacketHeaderBase):
    __slots__ = ['_af']

    def __init__(self, af=socket.AF_INET):
        self._af = int(af)
        super().__init__()

    def size(self):
        return 4

    @property
    def af(self):
        return self._af

    @af.setter
    def af(self,value):
        self._af = int(value)

    def to_bytes(self):
        '''
        Return packed byte representation of the Ethernet header.
        '''
        return struct.pack('=I', self._af)

    def from_bytes(self, raw):
        '''Return a Null header object reconstructed from raw bytes, or an
        Exception if we can't resurrect the packet.'''
        if len(raw) < 4:
            raise Exception("Not enough bytes ({}) to reconstruct a Null object".format(len(raw)))
        fields = struct.unpack('=I', raw[:4])
        self._af = fields[0]
        return raw[4:]

    def next_header_class(self):
        if self.af not in AFTypeClasses:
            raise Exception("No mapping for address family {} to a packet header class".format(self.af))
        cls = AFTypeClasses.get(self.af, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.af))
        return cls

    def pre_serialize(self, raw, pkt, i):
        pass

    def __eq__(self, other):
        return self.af == other.af

    def __str__(self):
        return '{}: {}'.format(self.__class__.__name__, self.af)

