import struct
from ipaddress import IPv6Address,IPv6Network
from abc import ABCMeta
from math import ceil

from .icmp import ICMP, ICMPData, ICMPEchoRequest, ICMPEchoReply, ICMPDestinationUnreachable
from .packet import PacketHeaderBase
from .common import ICMPv6Type, ICMPv6TypeCodeMap, ICMPv6OptionNumber
from .common import checksum as csum
from ..address import EthAddr
from ..exceptions import *
from ..logging import log_warn
from sys import byteorder


'''
References:
    http://tools.ietf.org/html/rfc4443  (Neighbor Discovery)
    http://tools.ietf.org/html/rfc2710  (Mulicast Listener Discovery)
    Stevens, Fall, TCP/IP Illustrated, Vol 1., 2nd Ed.
'''


class ICMPv6(ICMP):
    __slots__ = ('_type', '_code', '_icmpdata', '_valid_types', 
                 '_valid_codes_map', '_classtype_from_icmptype', 
                 '_icmptype_from_classtype', '_checksum')
    _PACKFMT = '!BBH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._valid_types = ICMPv6Type
        self._valid_codes_map = ICMPv6TypeCodeMap
        self._classtype_from_icmptype = ICMPv6ClassFromType
        self._icmptype_from_classtype = ICMPv6TypeFromClass
        self._type = self._valid_types.EchoRequest
        self._code = self._valid_codes_map[self._type].EchoRequest
        self._icmpdata = ICMPv6ClassFromType(self._type)()
        self._checksum = 0

        # make sure that icmptype is set first; this has the
        # side-effect of also creating the "right" icmpdata object.
        # as a convenience, allow kw syntax to set icmpdata values
        popattr = []
        for attr,val in kwargs.items():
            if hasattr(self.icmpdata, attr):
                setattr(self.icmpdata, attr, val)
                popattr.append(attr)
        for pattr in popattr:
            kwargs.pop(pattr)
        # don't explicitly call init in parent ICMPv4 class;
        # it will set classtype map incorrectly back to v4
        PacketHeaderBase.__init__(self, **kwargs)

    def checksum(self):
        return self._checksum

    def _compute_checksum(self, src, dst, raw):
        sep = b''
        databytes = self._icmpdata.to_bytes()
        icmpsize = ICMP._MINLEN+len(databytes)
        self._checksum = csum(sep.join((src.packed, dst.packed,
                                       struct.pack('!I3xBBB',
                                                   ICMP._MINLEN+len(databytes),
                                                   58,
                                                   self._type.value,
                                                   self._code.value),
                                       databytes)))

    def pre_serialize(self, raw, pkt, i):
        ip6hdr = pkt.get_header('IPv6')
        assert(ip6hdr is not None)
        self._compute_checksum(ip6hdr.src, ip6hdr.dst, raw)

    @property
    def icmp6type(self):
        return self.icmptype

    @icmp6type.setter
    def icmp6type(self, value):
        self.icmptype = value

    @property
    def icmp6code(self):
        return self.icmpcode

    @icmp6code.setter
    def icmp6code(self, value):
        self.icmpcode = value


class ICMPv6Option(object, metaclass=ABCMeta):
    __slots__ = ['_optnum']

    def __init__(self, optnum):
        self._optnum = ICMPv6OptionNumber(optnum)

    @property
    def optnum(self):
        return self._optnum

    def __len__(self):
        return len(self.to_bytes())

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        return "{}".format(self.__class__.__name__)


class _ICMPv6OptionLinkLayerAddress(ICMPv6Option):
    __slots__ = ['_ethaddr']
    _PACKFMT = '!BB6s'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, optnum, address=None):
        super().__init__(optnum)
        self.ethaddr = address

    def to_bytes(self):
        tl = struct.pack('!BB', self.optnum, 1)
        return tl + self.ethaddr.packed

    def from_bytes(self, raw):
        if len(raw) < _ICMPv6OptionLinkLayerAddress._MINLEN:
            raise NotEnoughDataError("Insufficient data to reconstruct {} (have {} need {})".format(self.__class__.__name__, length_, len(EthAddr)))
        fields = struct.unpack(_ICMPv6OptionLinkLayerAddress._PACKFMT, raw)
        assert(fields[0] == self.optnum)
        assert(fields[1] == 1)
        self.ethaddr = EthAddr(fields[2])
        return _ICMPv6OptionLinkLayerAddress._MINLEN

    @property
    def ethaddr(self):
        return self._ethaddr
    
    @ethaddr.setter
    def ethaddr(self, value):
        self._ethaddr = EthAddr(value)

    def __str__(self):
        return "{} {}".format(super().__str__(), self.ethaddr)


class ICMPv6OptionTargetLinkLayerAddress(_ICMPv6OptionLinkLayerAddress):
    def __init__(self, address=None):
        super().__init__(ICMPv6OptionNumber.TargetLinkLayerAddress)


class ICMPv6OptionSourceLinkLayerAddress(_ICMPv6OptionLinkLayerAddress):
    def __init__(self, address=None):
        super().__init__(ICMPv6OptionNumber.SourceLinkLayerAddress, address)


class ICMPv6OptionPrefixInformation(ICMPv6Option):
    __slots__ = ['_l', '_a', '_valid_lifetime', '_preferred_lifetime', '_prefix']
    _PACKFMT = '!BBBBIIxxxx16s'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        super().__init__(ICMPv6OptionNumber.PrefixInformation)
        self._l = 1
        self._a = 1
        self._valid_lifetime = 25920000
        self._preferred_lifetime = 604800
        self._prefix = IPv6Network('::/64')
        for k,v in kwargs.items():
            setattr(self, k, v)

    def to_bytes(self):
        flags = ((self._l << 7| self._a << 6)) & 0xff
        return struct.pack(ICMPv6OptionPrefixInformation._PACKFMT, self.optnum, 4,
            self.prefix.prefixlen, flags, self.valid_lifetime, self.preferred_lifetime,
            self.prefix.network_address.packed)
        return ICMPv6OptionPrefixInformation._MINLEN

    def from_bytes(self, raw):
        if len(raw) < ICMPv6OptionPrefixInformation._MINLEN:
            raise NotEnoughDataError("Insufficient data to reconstruct {}: need {} have {}".format(self.__class__.__name__, ICMPv6OptionPrefixInformation._MINLEN, len(raw)))
        fields = struct.unpack(ICMPv6OptionPrefixInformation._PACKFMT, raw)
        assert(fields[0] == self.optnum)
        assert(fields[1] == 4)
        pfxlen = fields[2]
        flags = fields[3]
        self.l = flags >> 7
        self.a = flags >> 6
        self.valid_lifetime = fields[4]
        self.preferred_lifetime = fields[5]
        addr = IPv6Address(fields[-1])
        self._prefix = IPv6Network("{}/{}".format(addr, pfxlen))
        
    @property
    def prefix_length(self):
        return self._prefix.prefixlen

    @prefix_length.setter
    def prefix_length(self, value):
        _addr = self._prefix.network_address
        self._prefix = IPv6Network("{}/{}".format(_addr, value))

    @property
    def l(self):
        return self._l

    @l.setter
    def l(self, value):
        self._l = int(value) & 0x1

    @property
    def a(self):
        return self._a

    @a.setter
    def a(self, value):
        self._a = int(value) & 0x1

    @property 
    def valid_lifetime(self):
        return self._valid_lifetime

    @valid_lifetime.setter
    def valid_lifetime(self, value):
        if value < 0:
            raise ValueError("valid_lifetime must be non-negative")
        self._valid_lifetime = int(value)

    @property
    def preferred_lifetime(self):
        return self._preferred_lifetime

    @preferred_lifetime.setter
    def preferred_lifetime(self, value):
        if value < 0:
            raise ValueError("preferred_lifetime must be non-negative")
        self._preferred_lifetime = int(value)

    @property
    def prefix(self):
        return self._prefix

    @prefix.setter
    def prefix(self, value):
        self._prefix = IPv6Network(value, strict=False)

    def __str__(self):
        return "{} pfxlen {} l {} a {} valid lifetime {} preferred lifetime {} prefix {}".format(self.__class__.__name__, self.prefix.prefixlen, self.l, self.a, self.valid_lifetime, self.preferred_lifetime, self.prefix.network_address)


class ICMPv6OptionMTU(ICMPv6Option):
    __slots__ = ['_mtu']
    _PACKFMT = '!BBxxI'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, mtu=1500):
        super().__init__(ICMPv6OptionNumber.MTU)
        self.mtu = mtu

    def to_bytes(self):
        return struct.pack(ICMPv6OptionMTU._PACKFMT, self.optnum, 1, self.mtu)

    def from_bytes(self, raw):
        if len(raw) < ICMPv6OptionMTU._MINLEN:
            raise NotEnoughDataError("Insufficient data to reconstruct {}: have {} need {}".format(self.__class__.__name__, len(raw), ICMPv6OptionMTU._MINLEN))
        fields = struct.unpack(ICMPv6OptionMTU._PACKFMT, raw)
        assert(fields[0] == self.optnum)
        assert(fields[1] == 1)
        self.mtu = fields[2]
        return ICMPv6OptionMTU._MINLEN 

    @property
    def mtu(self):
        return self._mtu

    @mtu.setter
    def mtu(self, value):
        self._mtu = int(value)

    def __str__(self):
        return "{} {}".format(super().__str__(), self.mtu)


class ICMPv6OptionRedirectedHeader(ICMPv6Option):
    __slots__ = ['_header']
    _PACKFMT = '!BB'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, header=None):
        super().__init__(ICMPv6OptionNumber.RedirectedHeader)
        if header is None:
            header = b''
        assert(isinstance(header, bytes))
        self.header = header

    def to_bytes(self):
        _len = int(ceil((len(self.header) + 2)/8))
        rv = struct.pack(ICMPv6OptionRedirectedHeader._PACKFMT, self.optnum, _len)
        return rv + self._header

    def from_bytes(self, raw):
        if len(raw) < ICMPv6OptionRedirectedHeader._MINLEN:
            raise NotEnoughDataError("Insufficient data to reconstruct {}".format(self.__class__.__name))
        tl = struct.unpack(ICMPv6OptionRedirectedHeader._PACKFMT, raw[:2])
        assert(tl[0] == self.optnum)
        bytelen = tl[1] * 8
        if len(raw) < bytelen:
            raise NotEnoughDataError("Insufficient data to reconstruct {}".format(self.__class__.__name__))
        self.header = raw[2:bytelen]
        return bytelen
    
    @property
    def header(self):
        return self._header

    @header.setter
    def header(self, value):
        assert(isinstance(value, bytes))
        padbytes = 8 - (len(value) + 2 % 8)
        value += b'\x00' * padbytes
        self._header = value

    def __str__(self):
        return "{} redirected packet ({} bytes)".format(
                super().__str__(), len(self._header))


ICMPv6OptionClasses = {
    ICMPv6OptionNumber.SourceLinkLayerAddress:
        ICMPv6OptionSourceLinkLayerAddress,
    ICMPv6OptionNumber.TargetLinkLayerAddress:
        ICMPv6OptionTargetLinkLayerAddress,
    ICMPv6OptionNumber.PrefixInformation: ICMPv6OptionPrefixInformation,
    ICMPv6OptionNumber.RedirectedHeader: ICMPv6OptionRedirectedHeader,
    ICMPv6OptionNumber.MTU: ICMPv6OptionMTU
}


class ICMPv6OptionList(object):
    __slots__ = ['_options']
    def __init__(self, *args):
        self._options = []
        for arg in args:
            assert(isinstance(arg, ICMPv6Option))
            self._options.append(arg)

    @staticmethod
    def from_bytes(raw):
        '''
        Takes a byte string as a parameter and returns a list of
        ICMPv6Option objects.
        '''
        icmpv6opts = ICMPv6OptionList()
        while len(raw) >= 8:
            opttype = raw[0]
            optlen = raw[1]
            olen = optlen * 8
            optdata = raw[:olen]
            raw = raw[olen:]
            try:
                optnum = ICMPv6OptionNumber(opttype)
            except ValueError:
                log_warn("Unimplemented ICMPv6 Option {}".format(opttype))
                continue
            obj = ICMPv6OptionClasses[optnum]()
            obj.from_bytes(optdata)
            icmpv6opts.append(obj)
        return icmpv6opts

    def to_bytes(self):
        '''
        Takes a list of ICMPv6Option objects and returns a packed byte string
        of options, appropriately padded if necessary.
        '''
        return b''.join([opt.to_bytes() for opt in self._options])

    def append(self, opt):
        if isinstance(opt, ICMPv6Option):
            self._options.append(opt)
        else:
            raise TypeError("Option to be added must be an ICMPv6Option " +
                            "object ( is {} )".format(type(opt)))

    def __len__(self):
        return len(self._options)

    def __getitem__(self, i):
        if isinstance(i, int):
            if i < 0:
                i = len(self._options) + i
            if 0 <= i < len(self._options):
                return self._options[i]
            raise IndexError("Invalid IP option index")
        elif issubclass(i, ICMPv6Option):
            for obj in self._options:
                if obj.__class__ == i:
                    return obj
            raise IndexError("option class {} doesn't exist in options list".format(i))
        else:
            raise IndexError("IP option index must be int or ICMPv6Option class")

    def __setitem__(self, i, val):
        if i < 0:
            i = len(self._options) + i
        if not issubclass(val.__class__, ICMPv6Option):
            raise ValueError("Assigned value must be of type ICMPv6Option, " +
                             "but {} is not.".format(val.__class__.__name__))
        if 0 <= i < len(self._options):
            self._options[i] = val
        else:
            raise IndexError("Invalid IP option index")

    def __delitem__(self, i):
        if i < 0:
            i = len(self._options) + i
        if 0 <= i < len(self._options):
            del self._options[i]
        else:
            raise IndexError("Invalid IP option index")

    def raw_length(self):
        return len(self.to_bytes())

    def size(self):
        return len(self._options)

    def __eq__(self, other):
        if not isinstance(other, ICMPv6OptionList):
            return False
        if len(self._options) != len(other._options):
            return False
        return self._options == other._options

    def __str__(self):
        return "{} ({})".format(
            self.__class__.__name__,
            ", ".join([str(opt) for opt in self._options]))


class ICMPv6Data(ICMPData):
    '''
    Parent class for ICMPv6 informational message data types 
    '''
    def __init__(self, **kwargs):
        self._options = ICMPv6OptionList()
        _opts = kwargs.pop('options', None)
        super().__init__(**kwargs)
        if _opts is not None:
            for o in _opts:
                self._options.append(o)

    @property
    def options(self):
        return self._options

    def __str__(self):
        return self.__class__.__name__


class ICMPv6EchoRequest(ICMPEchoRequest):
    pass


class ICMPv6EchoReply(ICMPEchoReply):
    pass


class ICMPv6DestinationUnreachable(ICMPDestinationUnreachable):
    pass


class ICMPv6Version2MulticastListenerReport(ICMPv6Data):
    pass


class ICMPv6MulticastListenerQuery(ICMPv6Data):
    pass


class ICMPv6MulticastListenerReport(ICMPv6Data):
    pass


class ICMPv6MulticastListenerDone(ICMPv6Data):
    pass


class ICMPv6RouterSolicitation(ICMPv6Data):
    _PACKFMT = '!xxxx'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def to_bytes(self):
        return b''.join((struct.pack(ICMPv6RouterSolicitation._PACKFMT),
            self._options.to_bytes()))
    
    def from_bytes(self, raw):
        if len(raw) < ICMPv6RouterSolicitation._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack {}".format(
                self.__class__.__name__))
        optionbytes = raw[ICMPv6RouterSolicitation._MINLEN:]
        _ = struct.unpack(ICMPv6RouterSolicitation._PACKFMT,
                          raw[:ICMPv6RouterSolicitation._MINLEN])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    def __str__(self):
        s = self.__class__.__name__
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s


class ICMPv6RouterAdvertisement(ICMPv6Data):
    __slots__ = ['_curhoplimit', '_m', '_o', '_h', '_p',
                 '_router_lifetime', '_reachable_time', '_retrans_timer']
    _PACKFMT = '!BBHII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._curhoplimit = 64
        self._m = self._o = self._h = self._p = 0
        self._router_lifetime = 1800
        self._reachable_time = 0
        self._retrans_timer = 0
        super().__init__(**kwargs)

    def to_bytes(self):
        flags = ((self._m << 7) | (self._o << 6) | (self._h << 5) | (self._p << 4)) & 0xff
        return b''.join((
            struct.pack(ICMPv6RouterAdvertisement._PACKFMT,
                        self._curhoplimit,
                        flags,
                        self._router_lifetime, self._reachable_time,
                        self._retrans_timer),
            self._options.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMPv6RouterAdvertisement._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack {}".format(
                self.__class__.__name__))
        optionbytes = raw[ICMPv6RouterAdvertisement._MINLEN:]
        fields = struct.unpack(ICMPv6RouterAdvertisement._PACKFMT,
                               raw[:ICMPv6RouterAdvertisement._MINLEN])
        self.curhoplimit = fields[0]
        flags = fields[1]
        self.m = (flags & 0x8) >> 7
        self.o = (flags & 0x4) >> 6
        self.h = (flags & 0x2) >> 5
        self.p = (flags & 0x1) >> 4
        self.router_lifetime = fields[2]
        self.reachable_time = fields[3]
        self.retrans_timer = fields[4]
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    @property
    def curhoplimit(self):
        return self._curhoplimit

    @curhoplimit.setter
    def curhoplimit(self, value):
        if value < 0:
            raise ValueError("Invalid curhoplimit: must be non-negative")
        self._curhoplimit = value

    @property
    def m(self):
        return bool(self._m)

    @m.setter
    def m(self, value):
        self._m = bool(int(value) & 0x1)

    @property
    def o(self):
        return bool(self._o)

    @o.setter
    def o(self, value):
        self._o = bool(int(value) & 0x1)

    @property
    def h(self):
        return bool(self._h)

    @h.setter
    def h(self, value):
        self._h = bool(int(value) & 0x1)

    @property
    def p(self):
        return bool(self._p)

    @p.setter
    def p(self, value):
        self._p = bool(int(value) & 0x1)

    @property
    def router_lifetime(self):
        return self._router_lifetime

    @router_lifetime.setter
    def router_lifetime(self, value):
        if value < 0:
            raise ValueError("Invalid router_lifetime must be non-negative")
        self._router_lifetime = value

    @property
    def reachable_time(self):
        return self._reachable_time

    @reachable_time.setter
    def reachable_time(self, value):
        if value < 0:
            raise ValueError("Invalid reachable_time must be non-negative")
        self._reachable_time = value

    @property
    def retrans_timer(self):
        return self._retrans_timer

    @retrans_timer.setter
    def retrans_timer(self, value):
        if value < 0:
            raise ValueError("Invalid retrans_timer must be non-negative")
        self._retrans_timer = value

    def __str__(self):
        s = "{}: curr hop limit {} m {} o {} h {} p {} router lifetime {} reachable time {} retrans timer {}".format(self.__class__.__name__, self._curhoplimit, self._m, self._o, self._h, self._p, self._router_lifetime, self._reachable_time, self._retrans_time)
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s


class ICMPv6NeighborSolicitation(ICMPv6Data):
    __slots__ = ['_targetaddr']
    _PACKFMT = "!xxxx16s"
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        super().__init__(**kwargs)

    def to_bytes(self):
        return b''.join((
            struct.pack(ICMPv6NeighborSolicitation._PACKFMT,
                        self._targetaddr.packed),
            self._options.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMPv6NeighborSolicitation._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack " +
                                     "ICMPv6NeighborSolicitation object")
        optionbytes = raw[ICMPv6NeighborSolicitation._MINLEN:]
        fields = struct.unpack(ICMPv6NeighborSolicitation._PACKFMT,
                               raw[:ICMPv6NeighborSolicitation._MINLEN])
        self._targetaddr = IPv6Address(fields[0])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        self._targetaddr = IPv6Address(value)

    def __str__(self):
        s = "{}: target address {}".format(self.__class__.__name__, self._targetaddr)
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s


class ICMPv6NeighborAdvertisement(ICMPv6Data):
    __slots__ = ['_R_S_O', '_r', '_s', '_o', '_targetaddr']
    _PACKFMT = "!cxxx16s"
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        self._r = 0
        self._s = 0
        self._o = 0
        super().__init__(**kwargs)

    def to_bytes(self):
        return b''.join((
            struct.pack(ICMPv6NeighborAdvertisement._PACKFMT,
                        self.get_rso_byte(),
                        self._targetaddr.packed),
            self._options.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < self._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack " +
                                     "ICMPv6NeighborAdvertisement object")
        optionbytes = raw[ICMPv6NeighborAdvertisement._MINLEN:]
        fields = struct.unpack(
            ICMPv6NeighborAdvertisement._PACKFMT,
            raw[:ICMPv6NeighborAdvertisement._MINLEN])
        rso = int.from_bytes(fields[0], byteorder=byteorder, signed=False)
        self._r = (rso & 0x80) >> 7
        self._s = (rso & 0x40) >> 6
        self._o = (rso & 0x20) >> 5
        self._targetaddr = IPv6Address(fields[1])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    def get_rso_byte(self):
        rso = self._r << 7 | \
              self._s << 6 | \
              self._o << 5
        return int.to_bytes(rso, length=1, byteorder=byteorder, signed=False)

    def get_rso_str(self):
        s = ''
        if self.r:
            s += 'R'
        if self.s:
            s += 'S'
        if self.o:
            s += 'O'
        return s

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        self._targetaddr = IPv6Address(value)

    @property
    def r(self):
        return bool(self._r)

    @property
    def s(self):
        return bool(self._s)

    @property
    def o(self):
        return bool(self._o)

    @r.setter
    def r(self, value):
        assert isinstance(value, bool)
        self._r = int(value)

    @s.setter
    def s(self, value):
        assert isinstance(value, bool)
        self._s = int(value)

    @o.setter
    def o(self, value):
        assert isinstance(value, bool)
        self._o = int(value)

    def __str__(self):
        s = "Target address: {} flags: {} ({})".format(
            self._targetaddr,
            hex(int.from_bytes(self.get_rso_byte(),
                byteorder=byteorder, signed=False)),
            self.get_rso_str())
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s


class ICMPv6RedirectMessage(ICMPv6Data):
    __slots__ = ['_targetaddr', '_destaddr']
    _PACKFMT = "!xxxx16s16s"
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        self._destaddr = IPv6Address("::0")
        super().__init__(**kwargs)

    def to_bytes(self):
        return b''.join((struct.pack(
            ICMPv6RedirectMessage._PACKFMT,
            self._targetaddr.packed, self._destaddr.packed),
            self._options.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < self._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack " +
                                     "ICMPv6RedirectMessage object")
        optionbytes = raw[self._MINLEN:]
        fields = struct.unpack(
            ICMPv6RedirectMessage._PACKFMT,
            raw[:ICMPv6RedirectMessage._MINLEN])
        self._targetaddr = IPv6Address(fields[0])
        self._destaddr = IPv6Address(fields[1])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        self._targetaddr = IPv6Address(value)

    @property
    def destaddr(self):
        return self._destaddr

    @destaddr.setter
    def destaddr(self, value):
        self._destaddr = IPv6Address(value)

    def __str__(self):
        s = "{} Target: {} Destination: {}".format(
            self.__class__.__name__,
            self._targetaddr,
            self._targetaddr)
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s


def construct_icmpv6_class_map():
    clsmap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
        except:
            cls = None
        clsmap[xtype] = cls

    def inner(icmptype):
        icmptype = ICMPv6Type(icmptype)
        return clsmap.get(icmptype, None)
    return inner


def construct_icmpv6_type_map():
    typemap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
            typemap[cls] = xtype
        except:
            pass

    def inner(icmpcls):
        return typemap.get(icmpcls, None)
    return inner


ICMPv6ClassFromType = construct_icmpv6_class_map()
ICMPv6TypeFromClass = construct_icmpv6_type_map()
