import struct
from ipaddress import IPv6Address
from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv6Addr,SpecialEthAddr
from switchyard.lib.packet.common import IPProtocol

from switchyard.lib.packet.icmpv6 import ICMPv6
from switchyard.lib.packet.tcp import TCP
from switchyard.lib.packet.udp import UDP
from switchyard.lib.packet.igmp import IGMP
from switchyard.lib.packet.ipv6ext import IPv6HopOption, IPv6RouteOption, IPv6Fragment, IPv6DestinationOptions, IPv6NoNext, IPv6Mobility, IPv6Shim6

'''
References:
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
'''


IPTypeClasses = {
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
    IPProtocol.IGMP: IGMP,
    IPProtocol.ICMPv6: ICMPv6,

    # IPv6 extension headers
    IPProtocol.IPv6HopOption: IPv6HopOption,
    IPProtocol.IPv6RouteOption: IPv6RouteOption,
    IPProtocol.IPv6Fragment: IPv6Fragment,
    IPProtocol.IPv6DestinationOptions: IPv6DestinationOptions,
    IPProtocol.IPv6NoNext: IPv6NoNext,
    IPProtocol.IPv6Mobility: IPv6Mobility,
    IPProtocol.IPv6Shim6: IPv6Shim6,
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
