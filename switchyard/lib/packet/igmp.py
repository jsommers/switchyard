from switchyard.lib.packet.packet import PacketHeaderBase,Packet
import struct

'''
References:
    IETF RFC 1112 (v1), RFC 2236 (v2), RFC 3376, 4604 (v3)
'''


class IGMP(PacketHeaderBase):
    def __init__(self):
        pass

    def size(self):
        pass

    def to_bytes(self):
        '''
        Return packed byte representation of the IGMP header.
        '''
        pass

    def from_bytes(self, raw):
        pass

    def __eq__(self, other):
        raise Exception("Not implemented")

    def __str__(self):
        return '{}'.format(self.__class__.__name__)

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return None
