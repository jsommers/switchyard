import struct
from abc import ABCMeta, abstractmethod
import pdb
from ipaddress import IPv6Address
from collections import namedtuple

from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv6Addr,SpecialEthAddr
from switchyard.lib.packet.common import IPProtocol
from switchyard.lib.packet.udp import UDP
from switchyard.lib.packet.tcp import TCP
from switchyard.lib.packet.icmp import ICMP
from switchyard.lib.packet.igmp import IGMP
from switchyard.lib.packet.icmpv6 import ICMPv6

'''
References:
    http://en.wikipedia.org/wiki/IPv6
'''

class IPv6HopOption(PacketHeaderBase):
    __slots__ = ['__protocol', '__options' ]
    __PACKFMT__ = '!BB'
    __MINLEN__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.protocol = IPProtocol.ICMP
        self.__options = []

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, value):
        self.__protocol = IPProtocol(value)

    def to_bytes(self):
        raise Exception("Not implemented")

    def tail_serialized(self, raw):
        return

    def size(self):
        raise Exception("Not implemented")

    def __eq__(self, other):
        raise Exception("Not implemented") # FIXME

    def __str__(self):
        return "{} ({} options)".format(self.__class__.__name__, len(self.__options))

    def next_header_class(self):
        if self.protocol not in IPTypeClasses:
            raise Exception("No mapping for IP Protocol {} to a packet header class".format(self.protocol))
        cls = IPTypeClasses.get(self.protocol, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    def from_bytes(self, raw):
        if len(raw) < IPv6HopOption.__MINLEN__:
            raise Exception("Not enough data to unpack IPv6HopOption")

        self.protocol = IPProtocol(raw[0])
        full_header_len = (int(raw[1]) + 1) * 8
        if len(raw) < full_header_len:
            raise Exception("Not enough data to unpack IPv6HopOption")
        full_header = raw[:full_header_len]
        # FIXME: unpack TLVs: type (1), length (1), data (specified in length)
        while len(full_header) > 0:
            optnum = full_header[0]
            optlen = full_header[1]
            optdata = full_header[2:(2+optlen)]
            self.__options.append((optnum,optlen,optdata))
            full_header = full_header[(optlen+2):]
        return raw[full_header_len:]


IPTypeClasses = {
    IPProtocol.ICMP: ICMP,
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
    IPProtocol.IPv6HopOpt: IPv6HopOption,
    IPProtocol.IPv6ICMP: ICMPv6,
    IPProtocol.IGMP: IGMP,
}


class IPv6(PacketHeaderBase):
    __slots__ = ['__trafficclass','__flowlabel','__ttl',
                 '__protocol','__payloadlen',
                 '__srcip','__dstip','__extheaders']
    __PACKFMT__ = '!BBHHBB16s16s'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.trafficclass = 0
        self.flowlabel = 0
        self.ttl = 255
        self.protocol = IPProtocol.ICMP
        self.__payloadlen = 0
        self.srcip = SpecialIPv6Addr.UNDEFINED.value
        self.dstip = SpecialIPv6Addr.UNDEFINED.value
        self.__extheaders = []
        
    def size(self):
        return IPv6.__MINSIZE__ + 0 # FIXME extension headers

    def tail_serialized(self, raw):
        self.__payloadlen = len(raw)

    def to_bytes(self):
        return struct.pack(IPv6.__PACKFMT__,
            6 << 4 | self.trafficclass >> 4,
            (self.trafficclass & 0x0f) << 4 | (self.flowlabel & 0xf0000) >> 16,
            self.flowlabel & 0x0ffff,
            self.__payloadlen, self.protocol.value,
            self.ttl, self.srcip.packed, self.dstip.packed)

    def from_bytes(self, raw):
        if len(raw) < IPv6.__MINSIZE__:
            raise Exception("Not enough data to unpack IPv6 header (only {} bytes)".format(len(raw)))
        fields = struct.unpack(IPv6.__PACKFMT__, raw[:IPv6.__MINSIZE__])
        ipversion = fields[0] >> 4
        if ipversion != 6:
            raise Exception("Trying to parse IPv6 header, but IP version is not 6! ({})".format(ipversion))
        self.trafficclass = (fields[0] & 0x0f) << 4 | (fields[1] >> 4)
        self.flowlabel = (fields[1] & 0x0f) << 16 | fields[2]
        self.__payloadlen = fields[3]
        self.protocol = IPProtocol(fields[4])
        self.ttl = fields[5]
        self.srcip = IPv6Address(fields[6])
        self.dstip = IPv6Address(fields[7])
        # FIXME
        return raw[IPv6.__MINSIZE__:]

    def __eq__(self, other):
        raise Exception("Not implemented") # FIXME

    def next_header_class(self):
        if self.protocol not in IPTypeClasses:
            raise Exception("No mapping for IP Protocol {} to a packet header class".format(self.protocol))
        cls = IPTypeClasses.get(self.protocol, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    # accessors and mutators
    @property
    def trafficclass(self):
        return self.__trafficclass

    @trafficclass.setter
    def trafficclass(self, value):
        self.__trafficclass = value

    @property
    def flowlabel(self):
        return self.__flowlabel

    @flowlabel.setter
    def flowlabel(self, value):
        self.__flowlabel = value

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, value):
        self.__protocol = IPProtocol(value)

    @property
    def ttl(self):
        return self.__ttl

    @ttl.setter
    def ttl(self, value):
        self.__ttl = value

    @property
    def srcip(self):
        return self.__srcip

    @srcip.setter
    def srcip(self, value):
        self.__srcip = IPv6Address(value)

    @property
    def dstip(self):
        return self.__dstip

    @dstip.setter
    def dstip(self, value):
        self.__dstip = IPv6Address(value)

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.srcip, self.dstip, self.protocol.name) 
