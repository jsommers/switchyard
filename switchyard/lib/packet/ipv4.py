import struct
from abc import ABCMeta, abstractmethod
from ipaddress import IPv4Address
from collections import namedtuple

from .packet import PacketHeaderBase,Packet
from ..address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
from ..logging import log_warn
from .common import IPProtocol,IPFragmentFlag,IPOptionNumber, checksum
from .icmp import ICMP
from .udp import UDP
from .tcp import TCP
from ..exceptions import *

'''
References:
    RFC791, INTERNET PROTOCOL.  DARPA INTERNET PROGRAM PROTOCOL SPECIFICATION.
        September 1981.
    RFC 1063, MTU discovery options.
    RFC 2113, Router alert option.
'''



class IPOption(object, metaclass=ABCMeta):
    _PACKFMT = 'B'
    __slots__ = ['_optnum']
    def __init__(self, optnum):
        self._optnum = IPOptionNumber(optnum)

    @property
    def optnum(self):
        return self._optnum

    def length(self):
        return struct.calcsize(IPOption._PACKFMT)

    def to_bytes(self):
        return struct.pack(IPOption._PACKFMT, self._optnum.value)

    def from_bytes(self, raw):
        return self.length()

    def __eq__(self, other):
        return self._optnum == other._optnum

    def __str__(self):
        return "{}".format(self.__class__.__name__)


class IPOptionNoOperation(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.NoOperation)

 
class IPOptionEndOfOptionList(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.EndOfOptionList)


class IPOptionXRouting(IPOption):
    _PACKFMT = 'BBB'
    __slots__ = ['_routedata','_ptr']
    def __init__(self, ipoptnum, numaddrs=9):
        super().__init__(ipoptnum)
        if numaddrs < 1 or numaddrs > 9:
            raise Exception("Invalid number of addresses for IP routing-type option (must be 1-9)")
        self._routedata = [IPv4Address("0.0.0.0")] * numaddrs
        self._ptr = 4

    def length(self):
        return struct.calcsize(IPOptionXRouting._PACKFMT)+len(self._routedata)*4

    def __len__(self):
        return len(self._routedata)

    def to_bytes(self):
        raw = struct.pack(IPOptionXRouting._PACKFMT,self.optnum.value,self.length(), self._ptr)
        for ipaddr in self._routedata:
            raw += ipaddr.packed
        return raw

    def from_bytes(self, raw):
        xtype = raw[0]
        length = raw[1]
        pointer = raw[2]
        numaddrs = ((length - 3) // 4)
        self._routedata = []
        for i in range(numaddrs):
            self._routedata.append(IPv4Address(raw[(3+(i*4)):(7+(i*4))]))
        self.pointer = pointer
        return length

    @property
    def pointer(self):
        return self._ptr

    @pointer.setter
    def pointer(self, value):
        xval = value // 4 - 1
        if not 0 <= xval < len(self._routedata):
            raise ValueError("Invalid pointer value")
        self._ptr = value

    def num_addrs(self):
        return len(self._routedata)

    def __getitem__(self, index):
        if index < 0:
            index = len(self._routedata) + index
        if not 0 <= index < len(self._routedata):
            raise IndexError("Index out of range")
        return self._routedata[index]

    def __setitem__(self, index, addr):
        if not isinstance(addr, (str,IPv4Address)):
            raise ValueError("Value must be IPv4Address or str")
        if index < 0:
            index = len(self._routedata) + index
        if not 0 <= index < len(self._routedata):
            raise IndexError("Index out of range")
        self._routedata[index] = IPv4Address(addr)

    def __delitem__(self, index):
        if index < 0:
            index = len(self._routedata) + index
        if not 0 <= index < len(self._routedata):
            raise IndexError("Index out of range")
        del self._routedata[index] 

    def __eq__(self, other):
        return self.optnum == other.optnum and \
            self._ptr == other._ptr and \
            self._routedata == other._routedata

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__,
            ', '.join([str(addr) for addr in self._routedata]))


class IPOptionLooseSourceRouting(IPOptionXRouting):
    def __init__(self, numaddrs=9):
        super().__init__(IPOptionNumber.LooseSourceRouting, numaddrs)


class IPOptionStrictSourceRouting(IPOptionXRouting):
    def __init__(self, numaddrs=9):
        super().__init__(IPOptionNumber.StrictSourceRouting, numaddrs)


class IPOptionRecordRoute(IPOptionXRouting):
    def __init__(self, numaddrs=9):
        super().__init__(IPOptionNumber.RecordRoute, numaddrs)


TimestampEntry = namedtuple('TimestampEntry', ['ipv4addr','timestamp'])

class IPOptionTimestamp(IPOption):
    __slots__ = ['_entries','_ptr','_flag']

    def __init__(self):
        super().__init__(IPOptionNumber.Timestamp)
        self._entries = [TimestampEntry(IPv4Address("0.0.0.0"), 0)] * 4
        self._ptr = 5
        # flags: 0x0 only timestamps, 0x1 ipaddr and timestamp, 0x3 optlist initialized
        # with up to 4 pairs of ipaddr and 0 timestamps
        self._flag = 0x1

    def length(self):
        entrysize = 8
        if self._flag == 0: entrysize = 4
        return 4 + len(self._entries)*entrysize

    @property
    def flag(self):
        return self._flag

    @flag.setter
    def flag(self, value):
        self._flag = int(value)

    def to_bytes(self):
        raw = struct.pack('!BBBB', 0x40 | self.optnum.value, self.length(),
            self._ptr, self._flag)
        for i in range(len(self._entries)):
            if self._flag > 0:
                raw += self._entries[i].ipv4addr.packed
            raw += struct.pack('!I', self._entries[i].timestamp)
        return raw

    def from_bytes(self, raw):
        fields = struct.unpack('!BBBB', raw[:4])
        self._ptr = fields[2]
        self._flag = fields[3]&0x0f
        self._entries = []
        xlen = fields[1]
        if xlen > len(raw):
            raise NotEnoughDataError("Not enough data to unpack raw {}: need {} but only have {}".format(self.__class__.__name__, xlen, len(raw)))
        raw = raw[4:xlen]
        haveipaddr = self._flag != 0
        unpackfmt = '!II'
        if not haveipaddr:
            unpackfmt = '!I' 
        for tstup in struct.iter_unpack(unpackfmt, raw):
            if haveipaddr:
                ts = TimestampEntry(IPv4Address(tstup[0]), tstup[1])
            else:
                ts = TimestampEntry(None, tstup[0])
            self._entries.append(ts)
        return xlen

    def num_timestamps(self):
        return len(self._entries)
        
    def timestamp_entry(self, index):
        return self._entries[index]

    def __eq__(self, other):
        return isinstance(other, IPOptionTimestamp) and \
            self._entries == other._entries and \
            self._flag == other._flag

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__,
            ", ".join([str(e) for e in self._entries]))


class IPOption4Bytes(IPOption):
    __slots__ = ['_value', '_copyflag']
    _PACKFMT = '!BBH'

    def __init__(self, optnum, value=0, copyflag=False):
        super().__init__(optnum)
        self._value = value
        self._copyflag = 0
        if copyflag:
            self._copyflag = 0x80
    
    def length(self):
        return struct.calcsize(IPOption4Bytes._PACKFMT)

    def from_bytes(self, raw):
        fields = struct.unpack(IPOption4Bytes._PACKFMT, raw[:4])
        self._value = fields[2]
        return self.length()

    def to_bytes(self):
        return struct.pack(IPOption4Bytes._PACKFMT, 
            self._copyflag | self.optnum.value, self.length(), self._value)

    def __eq__(self, other):
        return self.optnum == other.optnum and \
            self._value == other._value and \
            self._copyflag == other._copyflag    


class IPOptionRouterAlert(IPOption4Bytes):
    def __init__(self):
        super().__init__(IPOptionNumber.RouterAlert, copyflag=True)


class IPOptionMTUProbe(IPOption4Bytes):
    def __init__(self):
        super().__init__(IPOptionNumber.MTUProbe, value=1500, copyflag=False)


class IPOptionMTUReply(IPOption4Bytes):
    def __init__(self):
        super().__init__(IPOptionNumber.MTUReply, value=1500, copyflag=False)


IPOptionClasses = {
    IPOptionNumber.EndOfOptionList: IPOptionEndOfOptionList,
    IPOptionNumber.NoOperation: IPOptionNoOperation,
    IPOptionNumber.LooseSourceRouting: IPOptionLooseSourceRouting,
    IPOptionNumber.Timestamp: IPOptionTimestamp,
    IPOptionNumber.RecordRoute: IPOptionRecordRoute,
    IPOptionNumber.StrictSourceRouting: IPOptionStrictSourceRouting,
    IPOptionNumber.MTUProbe: IPOptionMTUProbe,
    IPOptionNumber.MTUReply: IPOptionMTUReply,
    IPOptionNumber.RouterAlert: IPOptionRouterAlert,
}

class IPOptionList(object):
    def __init__(self):
        self._options = []

    @staticmethod
    def from_bytes(rawbytes):
        '''
        Takes a byte string as a parameter and returns a list of
        IPOption objects.
        '''
        ipopts = IPOptionList()

        i = 0
        while i < len(rawbytes):
            opttype = rawbytes[i]
            optcopied = opttype >> 7         # high order 1 bit
            optclass = (opttype >> 5) & 0x03 # next 2 bits
            optnum = opttype & 0x1f          # low-order 5 bits are optnum
            optnum = IPOptionNumber(optnum)
            obj = IPOptionClasses[optnum]()
            eaten = obj.from_bytes(rawbytes[i:])
            i += eaten
            ipopts.append(obj)
        return ipopts

    def to_bytes(self):
        '''
        Takes a list of IPOption objects and returns a packed byte string
        of options, appropriately padded if necessary.
        '''
        raw = b''
        if not self._options:
            return raw
        for ipopt in self._options:
            raw += ipopt.to_bytes()
        padbytes = 4 - (len(raw) % 4)
        raw += b'\x00'*padbytes
        return raw
    
    def append(self, opt):
        if isinstance(opt, IPOption):
            self._options.append(opt)
        else:
            raise Exception("Option to be added must be an IPOption object")

    def __len__(self):
        return len(self._options)

    def __getitem__(self, i):
        if i < 0:
            i = len(self._options) + i
        if 0 <= i < len(self._options):
            return self._options[i]
        raise IndexError("Invalid IP option index")

    def __setitem__(self, i, val):
        if i < 0:
            i = len(self._options) + i
        if not issubclass(val.__class__, IPOption):
            raise ValueError("Assigned value must be of type IPOption, but {} is not.".format(val.__class__.__name__))
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
        if not isinstance(other, IPOptionList):
            return False
        if len(self._options) != len(other._options):
            return False
        return self._options == other._options

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__,
            ", ".join([str(opt) for opt in self._options]))


IPTypeClasses = {
    IPProtocol.ICMP: ICMP,
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
}

class IPv4(PacketHeaderBase):
    __slots__ = ['_tos','_totallen','_ttl',
                 '_ipid','_flags','_fragoffset',
                 '_protocol','_csum',
                 '_src','_dst','_options']
    _PACKFMT = '!BBHHHBBH4s4s'
    _MINLEN = struct.calcsize(_PACKFMT)
    _next_header_map = IPTypeClasses
    _next_header_class_key = '_protocol'

    def __init__(self, **kwargs):
        # fill in fields with (essentially) zero values
        self.tos = 0x00
        self._totallen = IPv4._MINLEN
        self.ipid = 0x0000
        self.ttl = 0
        self._flags = IPFragmentFlag.NoFragments
        self._fragoffset = 0
        self.protocol = IPProtocol.ICMP
        self._csum = 0x0000
        self.src = SpecialIPv4Addr.IP_ANY.value
        self.dst = SpecialIPv4Addr.IP_ANY.value
        self._options = IPOptionList()
        super().__init__(**kwargs)
        
    def size(self):
        return struct.calcsize(IPv4._PACKFMT) + self._options.raw_length()

    def pre_serialize(self, raw, pkt, i):
        self._totallen = self.size() + len(raw)

    def to_bytes(self):
        iphdr = struct.pack(IPv4._PACKFMT,
            4 << 4 | self.hl, self.tos, self._totallen,
            self.ipid, self._flags.value << 13 | self.fragment_offset,
            self.ttl, self.protocol.value, self.checksum,
            self.src.packed, self.dst.packed)
        return iphdr + self._options.to_bytes()

    def from_bytes(self, raw):
        if len(raw) < 20:
            raise NotEnoughDataError("Not enough data to unpack IPv4 header (only {} bytes)".format(len(raw)))
        headerfields = struct.unpack(IPv4._PACKFMT, raw[:20])
        v = headerfields[0] >> 4
        if v != 4:
            raise ValueError("Version in raw bytes for IPv4 isn't 4!")
        hl = (headerfields[0] & 0x0f) * 4
        if len(raw) < hl:
            raise NotEnoughDataError("Not enough data to unpack IPv4 header (only {} bytes, but header length field claims {})".format(len(raw), hl))
        optionbytes = raw[20:hl]
        self.tos = headerfields[1]        
        self._totallen = headerfields[2]
        self.ipid = headerfields[3]
        self.flags = IPFragmentFlag(headerfields[4] >> 13)
        self.fragment_offset = headerfields[4] & 0x1fff
        self.ttl = headerfields[5]
        self.protocol = IPProtocol(headerfields[6])
        self._csum = headerfields[7]
        self.src = headerfields[8]
        self.dst = headerfields[9]
        self._options = IPOptionList.from_bytes(optionbytes)
        return raw[hl:]

    def __eq__(self, other):
        return self.tos == other.tos and \
                self.ipid == other.ipid and \
                self.flags == other.flags and \
                self.fragment_offset == other.fragment_offset and \
                self.ttl == other.ttl and \
                self.protocol == other.protocol and \
                self.src == other.src and \
                self.dst == other.dst

    # accessors and mutators
    @property
    def options(self):
        return self._options

    @property
    def total_length(self):
        return self._totallen

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        value = int(value) 
        if not (0 <= value <= 255):
            raise ValueError("Invalid TTL value {}".format(value))
        self._ttl = value

    @property
    def tos(self):
        return self._tos

    @tos.setter
    def tos(self, value):
        if not (0 <= value < 256):
            raise ValueError("Invalid type of service value; must be 0-255")
        self._tos = value

    @property
    def dscp(self):
        return self._tos >> 2

    @property
    def ecn(self):
        return (self._tos & 0x03)

    @dscp.setter
    def dscp(self, value):
        if not (0 <= value < 64):
            raise ValueError("Invalid DSCP value; must be 0-63")
        self._tos = (self._tos & 0x03) | value << 2

    @ecn.setter
    def ecn(self, value):
        if not (0 <= value < 4):
            raise ValueError("Invalid ECN value; must be 0-3")
        self._tos = (self._tos & 0xfa) | value

    @property
    def ipid(self):
        return self._ipid

    @ipid.setter
    def ipid(self, value):
        if not (0 <= value < 65536):
            raise ValueError("Invalid IP ID value; must be 0-65535")
        self._ipid = value

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = IPProtocol(value)

    @property
    def src(self):
        return self._src

    @src.setter
    def src(self, value):
        self._src = IPAddr(value)

    @property
    def dst(self):
        return self._dst

    @dst.setter
    def dst(self, value):
        self._dst = IPAddr(value)

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        self._flags = IPFragmentFlag(value)

    @property
    def fragment_offset(self):
        return self._fragoffset

    @fragment_offset.setter
    def fragment_offset(self, value):
        if not (0 <= value < 2**13):
            raise ValueError("Invalid fragment offset value")
        self._fragoffset = value
    
    @property
    def hl(self):
        return self.size() // 4

    @property
    def checksum(self):
        data = struct.pack(IPv4._PACKFMT,
                    (4 << 4) + self.hl, self.tos,
                    self._totallen, self.ipid,
                    (self.flags.value << 13) | self.fragment_offset, 
                    self.ttl,
                    self.protocol.value, 0, self.src.packed, self.dst.packed)
        data += self._options.to_bytes()
        self._csum = checksum(data, 0)
        return self._csum

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.src, self.dst, self.protocol.name)

