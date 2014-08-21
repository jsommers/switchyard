import struct
from ipaddress import IPv6Address
from abc import ABCMeta, abstractmethod
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
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
    IETF RFC 6564 http://tools.ietf.org/html/rfc6564 (uniform format for ipv6 extension headers)
    IETF RFC 7045 http://tools.ietf.org/html/rfc7045 (transmission and processing of ipv6 extension headers)
    IETF RFC 6275 IPv6 mobility
    IETF RFC 5533 Shim6
'''

class IPv6ExtensionHeader(PacketHeaderBase):
    __slots__ = ['__nextheader','__hdrextlen']
    __PACKFMT__ = '!BB'
    __MINLEN__ = 2

    def __init__(self):
        self.__nextheader = None
        self.__hdrextlen = 0

    def tail_serialized(self):
        pass

    def size(self):
        return self.__hdrextlen

    @property
    def nextheader(self):
        return self.__nextheader

    @nextheader.setter
    def nextheader(self, value):
        self.__nextheader = IPProtocol(value)

    @property
    def hdrextlen(self):
        return self.__hdrextlen

    @hdrextlen.setter
    def hdrextlen(self, value):
        self.__hdrextlen = int(value)

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, value):
        self.__data = bytes(value) 

    def next_header_class(self):
        if self.nextheader not in IPTypeClasses:
            raise Exception("No mapping for IP Protocol {} to a packet header class".format(self.protocol))
        cls = IPTypeClasses.get(self.protocol, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    def to_bytes(self):
        return struct.pack(IPv6ExtensionHeader.__PACKFMT__, self.nextheader.value, (self.hdrextlen // 8) - 1) + self.data

    def from_bytes(self, raw):
        if len(raw) < IPv6ExtensionHeader.__MINLEN__:
            raise Exception("Not enough data to unpack IPv6ExtensionHeader")

        self.nextheader = IPProtocol(raw[0])
        self.hdrextlen = (int(raw[1]) + 1) * 8
        if len(raw) < self.hdrextlen:
            raise Exception("Not enough data to unpack IPv6ExtensionHeader")

        self.__data = raw[:self.hdrextlen]
        return raw[self.hdrextlen:]

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()


class IPv6RouteOption(IPv6ExtensionHeader):
    __slots__ = ['__routingtype', '__segmentsleft','__addresses']
    def __init__(self):
        super().__init__()
        self.__routingtype = 0
        self.__addresses = []

    def __str__(self):
        return "{} ({} addresses)".format(self.__class__.__name__, len(self.__addresses))

    def from_bytes(self, raw):
        remain = super().from_bytes(raw)
        self.__routingtype = self.data[0]
        self.__segmentsleft = self.data[1]
        if self.__routingtype == 0:
            rawaddrs = self.data[8:]
            for i in range(0,len(rawaddrs),16):
                self.__addresses.append(IPv6Address(addrs[i:(i+16)]))
        return remain

class IPv6FragmentHeader(IPv6ExtensionHeader):
    __slots__ = ['__id','__offset','__morefragments']
    __PACKFMT__ = '!BBHI'
    __MINLEN__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        super().__init__()
        self.__id = self.__offset = 0
        self.__morefragments = False

    def __str__(self):
        return "{} (id: {} offset: {} mf: {})".format(self.__class__.__name__, self.__id, self.__offset, self.__morefragments)

    def from_bytes(self, raw):
        # can't call super for this one since it doesn't follow standard
        # nextheader/len format in first 2 bytes
        if len(raw) < IPv6FragmentHeader.__MINLEN__:
            raise Exception("Not enough bytes to unpack IPv6FragmentHeader")

        fields = struct.unpack(IPv6FragmentHeader.__PACKFMT__, raw[:IPv6FragmentHeader.__MINLEN__])
        self.nextheader = fields[0]
        self.exthdrlen = 8 # fake this out; the header is 8 bytes
        self.__offset = int(fields[2] >> 3)
        self.__mf = bool(fields[2] & 0x0001)
        self.__id = fields[3]
        return raw[IPv6FragmentHeader.__MINLEN__:]

class IPv6HopOption(IPv6ExtensionHeader):
    __slots__ = ['__options' ]

    def __init__(self):
        super().__init__()
        self.__options = []

    def __str__(self):
        return "{} ({} options)".format(self.__class__.__name__, len(self.__options))

    def from_bytes(self, raw):
        remain = super().from_bytes(raw)
        raw = self.data
        while len(raw):
            opttype = raw[0] 

            # if padding option, discard and continue
            if opttype == 0:
                raw = raw[1:]
                continue

            optlen = raw[1]
            optdata = raw[2:(optlen+2)]
            if opttype != 1:
                self.__options.append( (opttype, optlen, optdata) )
            raw = raw[(optlen+2):]
        return remain

IPv6DestinationOptions = IPv6HopOption

class IPv6NoNextHeader(IPv6ExtensionHeader):
    def __init__(self):
        super().__init__()
        self.data = b''

    def __str__(self):
        return "IPv6NoNextHeader"

    def from_bytes(self, raw):
        pass

class IPv6MobilityHeader(IPv6ExtensionHeader):
    def __init__(self):
        super().__init__()

    def __str__(self):
        return "IPv6NoNextHeader"

    def from_bytes(self, raw):
        raise Exception("Not implemented")

class IPv6Shim6(IPv6ExtensionHeader):
    def __init__(self):
        super().__init__()

    def __str__(self):
        return "IPv6Shim6"

    def from_bytes(self, raw):
        raise Exception("Not implemented")


IPTypeClasses = {
    IPProtocol.ICMP: ICMP,
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
    IPProtocol.IGMP: IGMP,
    IPProtocol.IPv6ICMP: ICMPv6,

    # IPv6 extension headers
    IPProtocol.IPv6HopOpt: IPv6HopOption,
    IPProtocol.IPv6Route: IPv6RouteOption,
    IPProtocol.IPv6Frag: IPv6FragmentHeader,
    IPProtocol.IPv6DestinationOptions: IPv6DestinationOptions,
    IPProtocol.IPv6NoNext: IPv6NoNextHeader,
    IPProtocol.IPv6Mobility: IPv6MobilityHeader,
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
