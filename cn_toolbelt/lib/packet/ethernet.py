from packet_base import PacketHeaderBase, NullPacketHeader
from cn_toolbelt.lib.address import EthAddr
import struct
from enum import Enum

class EtherTypes(Enum):
    ETH_TYPE_IP = 0x0800
    ETH_TYPE_ARP = 0x0806
    ETH_TYPE_8021Q = 0x8100
    ETH_TYPE_IPV6 = 0x86dd
    ETH_TYPE_SLOW = 0x8809
    ETH_TYPE_MPLS = 0x8847
    ETH_TYPE_8021AD = 0x88a8
    ETH_TYPE_LLDP = 0x88cc
    ETH_TYPE_8021AH = 0x88e7
    ETH_TYPE_IEEE802_3 = 0x05dc

class Ethernet(PacketHeaderBase):
    __slots__ = ['src','dst','ethertype']
    __pack__ = '!6s6sH'

    def __init__(self, src='00:00:00:00:00:00',dst='00:00:00:00:00:00',ethertype=EtherTypes.ETH_TYPE_IP):
        PacketHeaderBase.__init__(self)
        self.src = EthAddr(src)
        self.dst = EthAddr(dst)
        self.ethertype = EtherTypes(ethertype)
        self.next = NullPacketHeader()

    def serialize(self):
        return struct.pack(__pack__, self.src.packed, self.dst.packed, self.ethertype) + self.next.serialize()

    def parse(self, raw):
        raise Exception("Not implemented yet")
    

if __name__ == '__main__':
    e = Ethernet()
    print (e)
