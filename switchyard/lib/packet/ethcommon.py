from enum import Enum

class EtherType(Enum):
    IP = 0x0800
    ARP = 0x0806
    _8021Q = 0x8100
    IPV6 = 0x86dd
    SLOW = 0x8809
    MPLS = 0x8847
    _8021AD = 0x88a8
    LLDP = 0x88cc
    _8021AH = 0x88e7
    IEEE802_3 = 0x05dc

