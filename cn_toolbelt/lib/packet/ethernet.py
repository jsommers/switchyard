from cn_toolbelt.lib.packet.packet_base import PacketHeaderBase
from cn_toolbelt.lib.address import EthAddr
import struct
from enum import Enum

class EtherType(Enum):
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
    __slots__ = ['__src','__dst','__ethertype']
    __pack__ = '!6s6sH'

    def __init__(self, src='00:00:00:00:00:00',dst='00:00:00:00:00:00',ethertype=EtherType.ETH_TYPE_IP):
        PacketHeaderBase.__init__(self)
        self.__src = EthAddr(src)
        self.__dst = EthAddr(dst)
        self.__ethertype = EtherType(ethertype)

    def __len__(self):
        return struct.calcsize(self.__pack__)

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

    def serialize(self):
        return struct.pack(self.__pack__, self.src.packed, self.dst.packed, self.ethertype) + self.next.serialize()

    def parse(self, raw):
        raise Exception("Not implemented yet")
    

if __name__ == '__main__':
    e = Ethernet()
    e2 = Ethernet()
    print (e)
    for x in e:
        print (x)

    e.addHeader(e2)
    for x in e:
        print (x)
