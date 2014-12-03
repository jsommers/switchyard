import struct
from ipaddress import IPv6Address
from abc import ABCMeta, abstractmethod

from switchyard.lib.common import log_warn
from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv6Addr,SpecialEthAddr
from switchyard.lib.packet.common import IPProtocol

from switchyard.lib.packet.icmpv6 import ICMPv6
from switchyard.lib.packet.tcp import TCP
from switchyard.lib.packet.udp import UDP
from switchyard.lib.packet.igmp import IGMP

'''
References:
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
    IETF RFC 6564 http://tools.ietf.org/html/rfc6564 (uniform format for ipv6 extension headers)
    IETF RFC 7045 http://tools.ietf.org/html/rfc7045 (transmission and processing of ipv6 extension headers)
    IETF RFC 6275 IPv6 mobility
    IETF RFC 5533 Shim6
'''

class IPv6ExtensionHeader(PacketHeaderBase):
    __slots__ = ['_nextheader','_optdatalen','_optlenmultiplier']
    _PACKFMT = '!BB'
    _MINLEN = 2

    def __init__(self, optlenmultiplier):
        self._nextheader = None
        self._optdatalen = 0
        # number of bytes represented by length field (should be 1 or 8, depending on ext hdr)
        assert(optlenmultiplier in (1,8))
        self._optlenmultiplier = optlenmultiplier

    def pre_serialize(self, raw, pkt, i):
        pass

    def size(self):
        return self._optdatalen

    @property
    def nextheader(self):
        return self._nextheader

    @nextheader.setter
    def nextheader(self, value):
        self._nextheader = IPProtocol(value)

    @property 
    def protocol(self):
        return self._nextheader

    @protocol.setter
    def protocol(self, value):
        self._nextheader = IPProtocol(value)

    def next_header_class(self):
        cls = IPTypeClasses.get(self.nextheader, None) 
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    def to_bytes(self):
        return struct.pack(IPv6ExtensionHeader._PACKFMT, 
            self.nextheader.value, self._optdatalen)

    def from_bytes(self, raw):
        if len(raw) < IPv6ExtensionHeader._MINLEN:
            raise Exception("Not enough data to unpack IPv6ExtensionHeader")

        self.nextheader = IPProtocol(raw[0])
        self._optdatalen = int(raw[1])

        if len(raw) < self._optdatalen * self._optlenmultiplier:
            raise Exception("Not enough data to unpack IPv6ExtensionHeader")
        return raw[IPv6ExtensionHeader._MINLEN:]

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()


class IPv6RouteOption(IPv6ExtensionHeader):
    '''
    IPv6 routing option.  Only supports type 2 (single address) option.
    '''
    __slots__ = ['_routingtype', '_segmentsleft','_address']
    def __init__(self, addr=SpecialIPv6Addr.UNDEFINED.value):
        super().__init__(8)
        self._routingtype = 2
        self._segmentsleft = 1
        self._address = IPv6Address(addr)
        self._optdatalen = 2 # RFC2460: len is number of 8 octet units, not including for 8 octets

    def __str__(self):
        return "{} (type {}, {})".format(self.__class__.__name__, self._routingtype, self._address)

    def to_bytes(self):
        common = super().to_bytes()
        payload = struct.pack('!BBI', self._routingtype, self._segmentsleft, 0) + self._address.packed
        return common + payload

    def from_bytes(self, raw):
        remain = super().from_bytes(raw)
        self._routingtype = remain[0]
        self._segmentsleft = remain[1]
        if self._routingtype == 2:
            rawaddr = remain[6:22]
            remain = remain[22:]
            self._address = IPv6Address(rawaddr)
        else:
            raise Exception("IPv6 routing option only supports type 2 (but I got type {})".format(self._routingtype))
        return remain

class IPv6Fragment(IPv6ExtensionHeader):
    __slots__ = ['_id','_offset','_morefragments']
    _PACKFMT = '!HI'
    _MINLEN = 6

    def __init__(self, xid=0, offset=0, mf=False):
        super().__init__(1)
        self._id = int(xid)
        self._offset = int(offset)
        self._morefragments = bool(mf)
        self._optdatalen = 0

    @property 
    def id(self):
        return self._id

    @property 
    def offset(self):
        return self._offset

    @property 
    def morefragments(self):
        return self._morefragments

    @property 
    def mf(self):
        return self.morefragments

    def __str__(self):
        return "{} (id: {} offset: {} mf: {})".format(self.__class__.__name__, self._id, self._offset, self._morefragments)

    def to_bytes(self):
        common = super().to_bytes()
        payload = struct.pack(IPv6Fragment._PACKFMT, self._offset << 3 | int(self._morefragments), self._id)
        return common + payload

    def from_bytes(self, raw):
        remain = super().from_bytes(raw)
        if len(remain) < IPv6Fragment._MINLEN:
            raise Exception("Not enough data to unpack IPv6Fragment extension header")
        offsetfield, xid = struct.unpack(IPv6Fragment._PACKFMT, remain[:IPv6Fragment._MINLEN])
        self._id = xid
        self._offset = offsetfield >> 3
        self._morefragments = bool(offsetfield & 0x1)
        remain = remain[IPv6Fragment._MINLEN:]
        return remain

class IPv6Option(metaclass=ABCMeta):
    def __init__(self):
        pass

    @abstractmethod
    def to_bytes(self):
        pass

    def __str__(self):
        return "{}".format(self.__class__.__name__)

class Pad1(IPv6Option):
    def __init__(self):
        pass

    def to_bytes(self):
        return b'\x00'

    @staticmethod
    def from_bytes(raw):
        return Pad1()

class PadN(IPv6Option):
    __slots__ = ('_n',)

    def __init__(self, n=0):
        self._n = n - 2

    def to_bytes(self):
        return struct.pack('BB', 1, self._n) + b'\x00' * self._n

    @staticmethod
    def from_bytes(raw):
        p = PadN()
        p._n = len(raw)
        return p

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__, self._n+2)

class JumboPayload(IPv6Option):
    __slots__ = ('_len',)
    def __init__(self, len):
        self._len = len

    def to_bytes(self):
        return struct.pack('!BBI', 0xc2, 4, self._len)

    @staticmethod
    def from_bytes(raw):
        assert(len(raw) == 4)
        fields = struct.unpack('!I', raw)
        return JumboPayload(fields[0])

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__, self._len)

class TunnelEncapsulationLimit(IPv6Option):
    __slots__ = ('_limit',)
    def __init__(self, limit):
        self._limit = int(limit)

    def to_bytes(self):
        return struct.pack('BBB', 4, 1, self._limit)

    @staticmethod
    def from_bytes(raw):
        assert(len(raw) == 1)
        return TunnelEncapsulationLimit(raw[0])

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__, self._limit)


class RouterAlert(IPv6Option):
    __slots__ = ('_value',)
    def __init__(self, value):
        self._value = value

    def to_bytes(self):
        return struct.pack('!BBH', 5, 2, self._value)

    @staticmethod
    def from_bytes(raw):
        assert(len(raw) == 2)
        fields = struct.unpack('!H', raw)
        return RouterAlert(fields[0])

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__, self._limit)

class HomeAddress(IPv6Option):
    __slots__ = ('_addr',)
    def __init__(self, addr):
        self._addr = IPv6Address(addr)

    def to_bytes(self):
        return struct.pack('!BB', 201, 16) + self._addr.packed

    @staticmethod
    def from_bytes(raw):
        assert(len(raw) == 16)
        return HomeAddress(raw)

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__, self._value)

class IPv6HopOption(IPv6ExtensionHeader):
    __slots__ = ['_options']
    _option_type_dict = {
        0: Pad1,
        1: PadN,
        194: JumboPayload,
        4: TunnelEncapsulationLimit,
        5: RouterAlert,
        201: HomeAddress 
    }

    def __init__(self):
        super().__init__(8)
        self._options = []

    def __str__(self):
        return "{}/{}".format(self.__class__.__name__, ' ; '.join([str(o) for o in self._options]))

    def to_bytes(self):
        xopt = b''.join([o.to_bytes() for o in self._options])
        hdrlen = len(xopt) + 2
        if hdrlen % 8 != 0:
            log_warn("Number of bytes in {} is not an even multiple of 8; " 
                     "padding must be explicitly added to correctly form the packet".format(self.__class__.__name__))
        self._optdatalen = hdrlen // 8 - 1
        common = super().to_bytes()
        return common + xopt

    def from_bytes(self, raw):
        if len(raw) % 8 != 0:
            log_warn("Trying to reconstruct {} that isn't a multiple of 8. This will end badly.".format(self.__class__.__name__))
        remain = super().from_bytes(raw)
        optbytes = (self._optdatalen + 1) * 8 - 2
        rawopt = remain[:optbytes]
        remain = remain[optbytes:]
        self._parseTLVOptions(rawopt)
        return remain

    def add_option(self, optobj):
        if not issubclass(optobj.__class__, IPv6Option):
            raise Exception("IPv6 option object isn't derived from IPv6Option class.")
        self._options.append(optobj)

    def _parseTLVOptions(self, raw):
        self._options = []
        while len(raw):
            xtype = raw[0]
            if xtype == 0:
                self._options.append(Pad1())
                raw = raw[1:]
            else:
                xlen = raw[1]
                if len(raw) < xlen+2:
                    raise Exception("Not enough data to unpack IPv6 TLV option (have {} bytes, need {} bytes for type {}".format(len(raw), xlen, xtype))
                data = raw[2:(2+xlen)]
                raw = raw[(2+xlen):]
                cls = IPv6HopOption._option_type_dict.get(xtype, None)
                if cls is None:
                    raise Exception("Bad IPv6 option type {}".format(xtype))
                self._options.append(cls.from_bytes(raw=data))

class IPv6DestinationOption(IPv6HopOption):
    pass

class IPv6NoNext(IPv6ExtensionHeader):
    def __init__(self):
        super().__init__()
        self.data = b''

    def __str__(self):
        return "IPv6NoNext"

    def from_bytes(self, raw):
        pass

class IPv6Mobility(IPv6ExtensionHeader):
    def __init__(self):
        super().__init__()

    def __str__(self):
        return "IPv6Mobility"

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
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
    IPProtocol.IGMP: IGMP,
    IPProtocol.ICMPv6: ICMPv6,

    # IPv6 extension headers
    IPProtocol.IPv6HopOption: IPv6HopOption,
    IPProtocol.IPv6RouteOption: IPv6RouteOption,
    IPProtocol.IPv6Fragment: IPv6Fragment,
    IPProtocol.IPv6DestinationOption: IPv6DestinationOption,
    IPProtocol.IPv6NoNext: IPv6NoNext,
    IPProtocol.IPv6Mobility: IPv6Mobility,
    IPProtocol.IPv6Shim6: IPv6Shim6,
}


class IPv6(PacketHeaderBase):
    __slots__ = ['_trafficclass','_flowlabel','_ttl',
                 '_nextheader','_payloadlen',
                 '_srcip','_dstip','_extheaders']
    _PACKFMT = '!BBHHBB16s16s'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        self.trafficclass = 0
        self.flowlabel = 0
        self.ttl = 255
        self.nextheader = IPProtocol.ICMP
        self._payloadlen = 0
        self.srcip = SpecialIPv6Addr.UNDEFINED.value
        self.dstip = SpecialIPv6Addr.UNDEFINED.value
        self._extheaders = []
        
    def size(self):
        return IPv6._MINLEN + 0 # FIXME extension headers

    def pre_serialize(self, raw, pkt, i):
        self._payloadlen = len(raw)

    def to_bytes(self):
        return struct.pack(IPv6._PACKFMT,
            6 << 4 | self.trafficclass >> 4,
            (self.trafficclass & 0x0f) << 4 | (self.flowlabel & 0xf0000) >> 16,
            self.flowlabel & 0x0ffff,
            self._payloadlen, self.nextheader.value,
            self.ttl, self.srcip.packed, self.dstip.packed)

    def from_bytes(self, raw):
        if len(raw) < IPv6._MINLEN:
            raise Exception("Not enough data to unpack IPv6 header (only {} bytes)".format(len(raw)))
        fields = struct.unpack(IPv6._PACKFMT, raw[:IPv6._MINLEN])
        ipversion = fields[0] >> 4
        if ipversion != 6:
            raise Exception("Trying to parse IPv6 header, but IP version is not 6! ({})".format(ipversion))
        self.trafficclass = (fields[0] & 0x0f) << 4 | (fields[1] >> 4)
        self.flowlabel = (fields[1] & 0x0f) << 16 | fields[2]
        self._payloadlen = fields[3]
        self.nextheader = IPProtocol(fields[4])
        self.ttl = fields[5]
        self.srcip = IPv6Address(fields[6])
        self.dstip = IPv6Address(fields[7])
        # FIXME
        return raw[IPv6._MINLEN:]

    def __eq__(self, other):
        return self._trafficclass == other._trafficclass and \
            self._flowlabel == other._flowlabel and \
            self._ttl == other._ttl and \
            self._nextheader == other._nextheader and \
            self._srcip == other._srcip and \
            self._dstip == other._dstip and \
            self._extheaders == other._extheaders

    def next_header_class(self):
        cls = IPTypeClasses.get(self.nextheader, None)
        if cls is None:
            print ("Warning: no class exists to parse next header type: {}".format(self.nextheader))
        return cls

    # accessors and mutators
    @property
    def trafficclass(self):
        return self._trafficclass

    @trafficclass.setter
    def trafficclass(self, value):
        self._trafficclass = value

    @property
    def flowlabel(self):
        return self._flowlabel

    @flowlabel.setter
    def flowlabel(self, value):
        self._flowlabel = value

    @property
    def nextheader(self):
        return self._nextheader

    @nextheader.setter
    def nextheader(self, value):
        self._nextheader = IPProtocol(value)

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        self._ttl = value

    @property
    def srcip(self):
        return self._srcip

    @srcip.setter
    def srcip(self, value):
        self._srcip = IPv6Address(value)

    @property
    def dstip(self):
        return self._dstip

    @dstip.setter
    def dstip(self, value):
        self._dstip = IPv6Address(value)

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.srcip, self.dstip, self.nextheader.name) 
