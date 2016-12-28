import struct
from ipaddress import IPv6Address
from abc import ABCMeta, abstractmethod
from enum import IntEnum

from ..logging import log_warn
from .packet import PacketHeaderBase,Packet
from ..address import EthAddr,IPAddr,SpecialIPv6Addr,SpecialEthAddr
from .common import IPProtocol, checksum
from ..exceptions import *

from .icmpv6 import ICMPv6
from .tcp import TCP
from .udp import UDP

'''
References:
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
    IETF RFC 2460 http://tools.ietf.org/html/rfc2460 (ipv6)
    IETF RFC 6564 http://tools.ietf.org/html/rfc6564 (uniform format for ipv6 extension headers)
    IETF RFC 7045 http://tools.ietf.org/html/rfc7045 (transmission and processing of ipv6 extension headers)
    IETF RFC 6275 IPv6 mobility
'''

class IPv6ExtensionHeader(PacketHeaderBase):
    __slots__ = ['_nextheader','_optdatalen','_optlenmultiplier']
    _PACKFMT = '!BB'
    _MINLEN = 2

    def __init__(self, optlenmultiplier, **kwargs):
        self._nextheader = None
        self._optdatalen = 0
        # number of bytes represented by length field (should be 1 or 8, depending on ext hdr)
        assert(optlenmultiplier in (1,8))
        self._optlenmultiplier = optlenmultiplier
        super().__init__(**kwargs)

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
        if cls is None and self.nextheader not in IPTypeClasses:
            log_warn("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    def to_bytes(self):
        return struct.pack(IPv6ExtensionHeader._PACKFMT, 
            self.nextheader.value, self._optdatalen)

    def from_bytes(self, raw):
        if len(raw) < IPv6ExtensionHeader._MINLEN:
            raise NotEnoughDataError("Not enough data to unpack IPv6ExtensionHeader")

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
    def __init__(self, **kwargs):
        self._routingtype = 2
        self._segmentsleft = 1
        self._address = SpecialIPv6Addr.UNDEFINED.value
        self._optdatalen = 2 # RFC2460: len is number of 8 octet units, not including for 8 octets
        super().__init__(8, **kwargs)

    def __str__(self):
        return "{} (type {}, {})".format(self.__class__.__name__, self._routingtype, self._address)

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = IPv6Address(value)

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
            raise ValueError("IPv6 routing option only supports type 2 (but I got type {})".format(self._routingtype))
        return remain

class IPv6Fragment(IPv6ExtensionHeader):
    __slots__ = ['_id','_offset','_morefragments']
    _PACKFMT = '!HI'
    _MINLEN = 6

    def __init__(self, **kwargs):
        self._id = 0
        self._offset = 0
        self._morefragments = False
        self._optdatalen = 0
        super().__init__(1, **kwargs)

    @property 
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

    @property 
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = int(value)

    @property 
    def mf(self):
        return self._morefragments

    @mf.setter
    def mf(self, value):
        self._morefragments = bool(value)

    def __str__(self):
        return "{} (id: {} offset: {} mf: {})".format(self.__class__.__name__, self._id, self._offset, self._morefragments)

    def to_bytes(self):
        common = super().to_bytes()
        payload = struct.pack(IPv6Fragment._PACKFMT, self._offset << 3 | int(self._morefragments), self._id)
        return common + payload

    def from_bytes(self, raw):
        remain = super().from_bytes(raw)
        if len(remain) < IPv6Fragment._MINLEN:
            raise NotEnoughDataError("Not enough data to unpack IPv6Fragment extension header")
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

    @property 
    def n(self):
        return self._n

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

    @property 
    def len(self):
        return self._len

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

    @property 
    def limit(self):
        return self._limit

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

    @property 
    def value(self):
        return self._value

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

    @property 
    def address(self):
        return self._addr

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

    def __init__(self, **kwargs):
        self._options = []
        super().__init__(8, **kwargs)

    def __str__(self):
        return "{}/{}".format(self.__class__.__name__, ' ; '.join([str(o) for o in self._options]))

    def to_bytes(self):
        xopt = b''.join([o.to_bytes() for o in self._options])
        hdrlen = len(xopt) + 2
        if hdrlen % 8 != 0:
            log_warn("Number of bytes in {} is not an even multiple of 8 ({}); " 
                     "padding must be explicitly added to correctly form the packet".format(self.__class__.__name__, hdrlen))
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

    def __getitem__(self, idx):
        if not isinstance(idx, int):
            raise TypeError("indexing in IPv6 option requires an int")
        if not 0 <= idx < len(self._options):
            raise IndexError("Bad index in IPv6 option access")
        return self._options[idx]

    def __len__(self):
        return len(self._options)

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
                    raise ValueError("Bad IPv6 option type {}".format(xtype))
                self._options.append(cls.from_bytes(raw=data))

class IPv6DestinationOption(IPv6HopOption):
    pass

class IPv6MobilityHeaderType(IntEnum):
    BindingRefreshRequest = 0
    HomeTestInit = 1
    CareOfTestInit = 2
    HomeTest = 3
    CareOfTest = 4
    BindingUpdate = 5
    BindingAcknowledgment = 6
    BindingError = 7

_IPv6MobilityHeaderStruct = {
    IPv6MobilityHeaderType.BindingRefreshRequest: '!H', # 2 reserved bytes, TLV options
    IPv6MobilityHeaderType.HomeTestInit: '!H8s', # 2 reserved bytes, 8 byte cookie, TLV options
    IPv6MobilityHeaderType.CareOfTestInit: '!H8s', # 2 reserved bytes, 8 byte cookie, TLV options
    IPv6MobilityHeaderType.HomeTest: '!H8s8s', # 2 byte nonce, 8 byte cookie, 8 byte keygen token, TLV options
    IPv6MobilityHeaderType.CareOfTest: '!H8s8s', # 2 byte nonce, 8 byte cookie, 8 byte keygen token, TLV options
    IPv6MobilityHeaderType.BindingUpdate: '!H4B', # 2 byte seq, 4 more bytes (bitfields, etc.), TLV options
    IPv6MobilityHeaderType.BindingAcknowledgment: '!2BHH', # 2 byte status/reserved, 2 byte seq, 2 byte lifetime, TLV options
    IPv6MobilityHeaderType.BindingError: '!BB16s', # status(1), reserved(1), homeaddr(16), TLV options
}


# Mobility Options: Pad1, PadN, BindingRefreshAdvice (type = 2), Alternate CoA (type = 3),
# Nonce Indices (type=4), Binding Authz Data (type=5)


class IPv6Mobility(IPv6ExtensionHeader):
    '''
    IPv6Mobility packet header.

    This header is incomplete, but *should* sufficiently parse any valid
    MIPv6 header.  In particular, there is no special handling of the
    header type elements apart from simply making sure that all the data
    are encoded/decoded in the right byte sizes (see IPv6MobilityHeaderType 
    enumeration, above).  
    '''

    __slots__ = ('_mhtype','_checksum','_data','_src','_dst')
    _PACKFMT = '!BBH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._nextheader = IPProtocol.IPv6NoNext
        self._optdatalen = 0 #FIXME
        self._mhtype = IPv6MobilityHeaderType(0)
        self._data = (0,)
        self._src = self._dst = SpecialIPv6Addr.UNDEFINED.value
        super().__init__(8, **kwargs)

    def pre_serialize(self, raw, pkt, i):
        ipv6hdr = pkt.get_header(IPv6)
        self._src = ipv6hdr.src
        self._dst = ipv6hdr.dst

    def __str__(self):
        return "IPv6Mobility ({})".format(self._mhtype.name)

    def _compute_checksum(self):
        # FIXME: computed on IPv6 pseudoheader + full mobility header (starting with ext header)
        # pseudoheader: srcaddr(16),dstaddr(16),len of mobility header (4), 000 next header(4)
        self._checksum = 0
        exthdr = self.to_bytes(computecsum=False)
        self._checksum = checksum(struct.pack('16s16sIxxxB',
                                  self._src.packed,
                                  self._dst.packed,
                                  len(exthdr), IPProtocol.IPv6Mobility.value) +
            exthdr)
        return self._checksum

    def _parse_tlv(self, raw):
        pass

    def to_bytes(self, computecsum=True):
        if computecsum:
            self._compute_checksum()
        exthdr = super().to_bytes()
        mobhdr = struct.pack(IPv6Mobility._PACKFMT, self._mhtype.value, 0, self._checksum)
        remain = struct.pack(_IPv6MobilityHeaderStruct[self._mhtype], *self._data)
        return exthdr + mobhdr + remain

    def from_bytes(self, raw):
        super().from_bytes(raw)
        remain = raw[2:]
        if len(remain) < IPv6Mobility._MINLEN:
            raise NotEnoughDataError("Not enough data to unpack IPv6Mobility header")
        mhtype,reserved,checksum = struct.unpack(IPv6Mobility._PACKFMT, 
                                                 remain[:IPv6Mobility._MINLEN])
        self._mhtype = IPv6MobilityHeaderType(mhtype)
        self._checksum = checksum
        mobheaderstruct = _IPv6MobilityHeaderStruct[self._mhtype]
        structsize = struct.calcsize(mobheaderstruct)
        self._data = struct.unpack(mobheaderstruct, remain[IPv6Mobility._MINLEN:(IPv6Mobility._MINLEN+structsize)])
        return raw[(IPv6Mobility._MINLEN + structsize):]


IPTypeClasses = {
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
    IPProtocol.ICMPv6: ICMPv6,

    # IPv6 extension headers
    IPProtocol.IPv6HopOption: IPv6HopOption,
    IPProtocol.IPv6RouteOption: IPv6RouteOption,
    IPProtocol.IPv6Fragment: IPv6Fragment,
    IPProtocol.IPv6DestinationOption: IPv6DestinationOption,
    IPProtocol.IPv6NoNext: None,
    IPProtocol.IPv6Mobility: IPv6Mobility,
}


class IPv6(PacketHeaderBase):
    __slots__ = ['_trafficclass','_flowlabel','_ttl',
                 '_nextheader','_payloadlen',
                 '_src','_dst','_extheaders']
    _PACKFMT = '!BBHHBB16s16s'
    _MINLEN = struct.calcsize(_PACKFMT)
    _next_header_map = IPTypeClasses
    _next_header_class_key = '_nextheader'

    def __init__(self, **kwargs):
        self.trafficclass = 0
        self.flowlabel = 0
        self.ttl = 128
        self.nextheader = IPProtocol.ICMP
        self._payloadlen = 0
        self.src = SpecialIPv6Addr.UNDEFINED.value
        self.dst = SpecialIPv6Addr.UNDEFINED.value
        self._extheaders = []
        super().__init__(**kwargs)
        
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
            self.ttl, self.src.packed, self.dst.packed)

    def from_bytes(self, raw):
        if len(raw) < IPv6._MINLEN:
            raise NotEnoughDataError("Not enough data to unpack IPv6 header (only {} bytes)".format(len(raw)))
        fields = struct.unpack(IPv6._PACKFMT, raw[:IPv6._MINLEN])
        ipversion = fields[0] >> 4
        if ipversion != 6:
            raise ValueError("Trying to parse IPv6 header, but IP version is not 6! ({})".format(ipversion))
        self.trafficclass = (fields[0] & 0x0f) << 4 | (fields[1] >> 4)
        self.flowlabel = (fields[1] & 0x0f) << 16 | fields[2]
        self._payloadlen = fields[3]
        self.nextheader = IPProtocol(fields[4])
        self.ttl = fields[5]
        self.src = IPv6Address(fields[6])
        self.dst = IPv6Address(fields[7])
        # FIXME: extension headers
        return raw[IPv6._MINLEN:]

    def __eq__(self, other):
        return self._trafficclass == other._trafficclass and \
            self._flowlabel == other._flowlabel and \
            self._ttl == other._ttl and \
            self._nextheader == other._nextheader and \
            self._src == other._src and \
            self._dst == other._dst and \
            self._extheaders == other._extheaders

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
        self._ttl = int(value)

    @property 
    def hopcount(self):
        return self.ttl

    @hopcount.setter
    def hopcount(self, value):
        self.ttl = value

    @property
    def src(self):
        return self._src 

    @src.setter
    def src(self, value):
        self._src = value

    @property
    def dst(self):
        return self._dst

    @dst.setter
    def dst(self, value):
        self._dst = value

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.src, self.dst, self.nextheader.name) 
