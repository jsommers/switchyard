from switchyard.lib.packet.packet import PacketHeaderBase,Packet
import struct

'''
References:
    IETF RFC 768
'''

class Udp(PacketHeaderBase):
    __slots__ = ['__srcport','__dstport','__len']
    __PACKFMT__ = '!HHHH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.__srcport = self.__dstport = 0
        self.__len = self.size()

    def size(self):
        return struct.calcsize(Udp.__PACKFMT__)

    def tail_serialized(self, raw):
        pass

    def to_bytes(self):
        '''
        Return packed byte representation of the UDP header.
        '''
        return struct.pack(Udp.__PACKFMT__, self.__srcport, self.__dstport,
            self.__len, 0)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < Udp.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an Udp object".format(len(raw)))
        fields = struct.unpack(Udp.__PACKFMT__, raw[:Udp.__MINSIZE__])
        self.__srcport = fields[0]
        self.__dstport = fields[1]
        self.__len = fields[2]
        return raw[Udp.__MINSIZE__:]

    def __eq__(self, other):
        return self.srcport == other.srcport and \
            self.dstport == other.dstport

    @property
    def srcport(self):
        return self.__srcport

    @property
    def dstport(self):
        return self.__dstport

    @srcport.setter
    def srcport(self,value):
        self.__srcport = value

    @dstport.setter
    def dstport(self,value):
        self.__dstport = value

    def __str__(self):
        return '{} {}->{}'.format(self.__class__.__name__, self.srcport, self.dstport)

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return
