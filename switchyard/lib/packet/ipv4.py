import struct
from abc import ABCMeta, abstractmethod
import pdb
from ipaddress import IPv4Address
from collections import namedtuple

from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
from switchyard.lib.packet.common import IPProtocol,IPFragmentFlag,IPOptionCopy,IPOptionClass,IPOptionNumber, checksum
from switchyard.lib.packet.udp import UDP
from switchyard.lib.packet.tcp import TCP
from switchyard.lib.packet.icmp import ICMP

'''
References:
    "RFC791", INTERNET PROTOCOL.  DARPA INTERNET PROGRAM PROTOCOL SPECIFICATION.
        September 1981.
    http://en.wikipedia.org/wiki/IPv4
'''

IPTypeClasses = {
    IPProtocol.ICMP: ICMP,
    IPProtocol.TCP: TCP,
    IPProtocol.UDP: UDP,
}


class IPOption(object, metaclass=ABCMeta):
    __slots__ = ['__optnum']
    def __init__(self, optnum):
        self.__optnum = IPOptionNumber(optnum)

    @property
    def optnum(self):
        return self.__optnum

    @abstractmethod
    def length(self):
        return 0

    @abstractmethod
    def to_bytes(self):
        return b''

    @abstractmethod
    def from_bytes(self, raw):
        return self.length()


class IPOptionEndOfOptionList(IPOption):
    __PACKFMT__ = 'B'

    def __init__(self):
        super().__init__(IPOptionNumber.EndOfOptionList)

    def length(self):
        return struct.calcsize(__PACKFMT__)

    def to_bytes(self):
        return struct.pack(__PACKFMT__, self.optnum.value)

    def from_bytes(self, raw):
        return self.length()

class IPOptionNoOperation(IPOption):
    __PACKFMT__ = 'B'

    def __init__(self):
        super().__init__(IPOptionNumber.NoOperation)

    def length(self):
        return struct.calcsize(__PACKFMT__)

    def to_bytes(self):
        return struct.pack(__PACKFMT__, self.optnum.value)

    def from_bytes(self, raw):
        return self.length()

class IPOptionSecurity(IPOption):
    __PACKFMT__ = '!BBHHHBBB'
    __slots__ = ['secfield','compartments','handling_restrictions','transmission_control_code']

    def __init__(self):
        super().__init__(IPOptionNumber.Security)
        self.secfield = 0x0000
        self.compartments = 0x0000
        self.handling_restrictions = 0x0000
        self.transmission_control_code = 0x000000

    def length(self):
        return struct.calcsize(__PACKFMT__)

    def to_bytes(self):
        return struct.pack(IPOptionSecurity.__PACKFMT__, 0x82, 0x0b, 
            self.secfield & 0xffff, self.compartments & 0xffff, 
            self.handling_restrictions & 0xffff, 
            (self.transmission_control_code >> 16) & 0xff,
            (self.transmission_control_code >> 8) & 0xff,
            (self.transmission_control_code) & 0xff)

    def from_bytes(self, raw):
        if len(raw) < self.length():
            raise Exception("Not enough data to unpack {} (need {})".format(self.__class__.__name__, self.length()))

        fields = struct.unpack(IPOptionSecurity.__PACKFMT__,
            raw[0], raw[1], raw[2:4], raw[4:6], raw[6:8],
            raw[8], raw[9], raw[10])
        self.secfield = fields[2]
        self.compartments = fields[3]
        self.handling_restrictions = fields[4]
        self.transmission_control_code = (fields[5] << 16) | (fields[6] << 8) | fields[7]
        return self.length()

class IPOptionXRouting(IPOption):
    __slots__ = ['__routedata','__ptr']
    def __init__(self, ipoptnum):
        super().__init__(ipoptnum)
        self.__routedata = []

    def length(self):
        return 3+len(self.__routedata)*4

    def to_bytes(self):
        raw = struct.pack('!BBB',(0x80|self.optnum.value),self.length())
        for ipaddr in self.__routedata:
            raw += ipaddr.packed
        return raw

    def from_bytes(self, raw):
        xtype = raw[0]
        length = raw[1]
        pointer = raw[2]
        numaddrs = (length - 3 // 4)
        for i in range(numaddrs):
            self.__routedata.append(IPV4Address(raw[(3+(i*4)):(7+(i*4))]))
        self.__ptr = (pointer // 4) - 1
        return length

    @property
    def pointer(self):
        return self.__ptr

    @pointer.setter
    def pointer(self, value):
        if not (0 <= value < len(self.__routedata)):
            raise Exception("Invalid pointer value; must be 0..{}".format(len(self.__routedata)-1))
        self.__ptr = value

    def route_data(self, index):
        return self.__routedata[index]

class IPOptionLooseSourceRouting(IPOptionXRouting):
    def __init__(self):
        super().__init__(IPOptionNumber.LooseSourceRouting)

class IPOptionStrictSourceRouting(IPOptionXRouting):
    def __init__(self):
        super().__init__(IPOptionNumber.StrictSourceRouting)

class IPOptionRecordRoute(IPOptionXRouting):
    def __init__(self):
        super().__init__(IPOptionNumber.RecordRoute)

class IPOptionStreamId(IPOption):
    __PACKFMT__ = '!BBH'
    __slots__ = ['__streamid']

    def __init__(self):
        super().__init__(IPOptionNumber.StreamID)

    def length(self):
        return struct.calcsize(IPOptionStreamID.__PACKFMT__)

    def to_bytes(self):
        return struct.pack(IPOptionStreamID.__PACKFMT__,
            (self.optnum | 0x80), 4, self.__streamid)

    def from_bytes(self, raw):
        fields = struct.unpack(IPOptionStreamID.__PACKFMT__, raw[:4])
        self.__streamid = fields[2]
        return self.length()

    @property
    def streamid(self):
        return self.__streamid

    @streamid.setter
    def streamid(self, value):
        self.__streamid = value

TimestampEntry = namedtuple('TimestampEntry', ['ipv4addr','timestamp'])

class IPOptionTimestamp(IPOption):
    __slots__ = ['__entries','__ptr','__flag']

    def __init__(self):
        super().__init__(IPOptionNumber.Timestamp)
        self.__entries = []
        self.__ptr = 5
        self.__flag = 0x1

    def length(self):
        entrysize = 2
        if self.__flag == 0: entrysize = 1
        return 4 + len(self.__entries)*entrysize

    def to_bytes(self):
        raw = struct.pack('!BBBB', 0x40 | self.optnum, self.length(),
            self.__ptr, self.__flag)

    def from_bytes(self, raw):
        fields = struct.unpack('!BBBB', raw[:4])
        self.__ptr = fields[2]
        self.__flags = fields[3]&0x0f
        xlen = fields[1]
        if xlen > len(raw):
            raise Exception("Not enough data to unpack raw {}: need {} but only have {}".format(self.__class__.__name__, xlen, len(raw)))
        raw = raw[4:xlen]
        haveipaddr = self.__flags != 0
        unpackfmt = '!II'
        if not haveipaddr:
            unpackfmt = '!I' 
        for tstup in struct.iter_unpack(unpackfmt, raw):
            if haveipaddr:
                ts = TimestampEntry(*tstup)
            else:
                ts = TimestampEntry(None, tstup[0])
            self.__entries.append(ts)

        return xlen

    def timestamp(self, index):
        return self.__entries[index]


IPOptionClasses = {
    IPOptionNumber.EndOfOptionList: IPOptionEndOfOptionList,
    IPOptionNumber.NoOperation: IPOptionNoOperation,
    IPOptionNumber.Security: IPOptionSecurity,
    IPOptionNumber.LooseSourceRouting: IPOptionLooseSourceRouting,
    IPOptionNumber.StrictSourceRouting: IPOptionStrictSourceRouting,
    IPOptionNumber.RecordRoute: IPOptionRecordRoute,
    IPOptionNumber.StreamId: IPOptionStreamId,
    IPOptionNumber.Timestamp: IPOptionTimestamp
}

class IPOptionList(object):
    def __init__(self):
        self.__options = []

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
            ipopts.add_option(obj)
        return ipopts

    def to_bytes(self):
        '''
        Takes a list of IPOption objects and returns a packed byte string
        of options, appropriately padded if necessary.
        '''
        raw = b''
        for ipopt in self.__options:
            raw += ipopt.to_bytes()
        padbytes = len(raw) % 4
        raw += b'\x00'*padbytes
        return raw
    
    def add_option(self, opt):
        if isinstance(opt, IPOption):
            self.__options.append(opt)
        else:
            raise Exception("Option to be added must be an IPOption object")

    def raw_length(self):
        return len(self.to_bytes())

    def size(self):
        return len(self.__options)


class IPv4(PacketHeaderBase):
    __slots__ = ['__tos','__totallen','__ttl',
                 '__ipid','__flags','__fragoffset',
                 '__protocol','__csum',
                 '__srcip','__dstip','__options']
    __PACKFMT__ = '!BBHHHBBH4s4s'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        # fill in fields with (essentially) zero values
        self.tos = 0x00
        self.__totallen = IPv4.__MINSIZE__
        self.ipid = 0x0000
        self.ttl = 0
        self.__flags = IPFragmentFlag.NoFragments
        self.__fragoffset = 0
        self.protocol = IPProtocol.ICMP
        self.__csum = 0x0000
        self.srcip = SpecialIPv4Addr.IP_ANY.value
        self.dstip = SpecialIPv4Addr.IP_ANY.value
        self.__options = IPOptionList()
        
    def size(self):
        return struct.calcsize(IPv4.__PACKFMT__) + self.__options.raw_length()

    def tail_serialized(self, raw):
        self.__totallen = self.size() + len(raw)

    def to_bytes(self):
        iphdr = struct.pack(IPv4.__PACKFMT__,
            4 << 4 | self.hl, self.tos, self.__totallen,
            self.ipid, self.__flags.value << 13 | self.fragment_offset,
            self.ttl, self.protocol.value, self.checksum,
            self.srcip.packed, self.dstip.packed)
        return iphdr + self.__options.to_bytes()

    def from_bytes(self, raw):
        if len(raw) < 20:
            raise Exception("Not enough data to unpack IPv4 header (only {} bytes)".format(len(raw)))
        headerfields = struct.unpack(IPv4.__PACKFMT__, raw[:20])
        v = headerfields[0] >> 4
        if v != 4:
            raise Exception("Version in raw bytes for IPv4 isn't 4!")
        hl = (headerfields[0] & 0x0f) * 4
        if len(raw) < hl:
            raise Exception("Not enough data to unpack IPv4 header (only {} bytes, but header length field claims {})".format(len(raw), hl))
        optionbytes = raw[20:hl]
        self.tos = headerfields[1]        
        self.__totallen = headerfields[2]
        self.ipid = headerfields[3]
        self.flags = IPFragmentFlag(headerfields[4] >> 13)
        self.fragment_offset = headerfields[4] & 0x1fff
        self.ttl = headerfields[5]
        self.protocol = IPProtocol(headerfields[6])
        self.__csum = headerfields[7]
        self.srcip = headerfields[8]
        self.dstip = headerfields[9]
        self.__options = IPOptionList.from_bytes(optionbytes)
        return raw[hl:]

    def __eq__(self, other):
        return self.tos == other.tos and \
                self.ipid == other.ipid and \
                self.flags == other.flags and \
                self.fragment_offset == other.fragment_offset and \
                self.ttl == other.ttl and \
                self.protocol == other.protocol and \
                self.checksum == other.checksum and \
                self.srcip == other.srcip and \
                self.dstip == other.dstip

    def next_header_class(self):
        if self.protocol not in IPTypeClasses:
            raise Exception("No mapping for IP Protocol {} to a packet header class".format(self.protocol))
        cls = IPTypeClasses.get(self.protocol, None)
        if cls is None:
            print ("Warning: no class exists to parse next protocol type: {}".format(self.protocol))
        return cls

    # accessors and mutators
    def options(self):
        return self.__options

    @property
    def total_length(self):
        return self.__totallen

    @property
    def ttl(self):
        return self.__ttl

    @ttl.setter
    def ttl(self, value):
        value = int(value) 
        if not (0 <= value <= 255):
            raise ValueError("Invalid TTL value {}".format(value))
        self.__ttl = value

    @property
    def tos(self):
        return self.__tos

    @tos.setter
    def tos(self, value):
        if not (0 <= value < 256):
            raise Exception("Invalid type of service value; must be 0-255")
        self.__tos = value

    @property
    def dscp(self):
        return self.__tos >> 2

    @property
    def ecn(self):
        return (self.__tos & 0x03)

    @dscp.setter
    def dscp(self, value):
        if not (0 <= value < 64):
            raise Exception("Invalid DSCP value; must be 0-63")
        self.__tos = (self.__tos & 0x03) | value << 2

    @ecn.setter
    def ecn(self, value):
        if not (0 <= value < 4):
            raise Exeption("Invalid ECN value; must be 0-3")
        self.__tos = (self.__tos & 0xfa) | value

    @property
    def ipid(self):
        return self.__ipid

    @ipid.setter
    def ipid(self, value):
        if not (0 <= value < 65536):
            raise Exception("Invalid IP ID value; must be 0-65535")
        self.__ipid = value

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, value):
        self.__protocol = IPProtocol(value)

    @property
    def srcip(self):
        return self.__srcip

    @srcip.setter
    def srcip(self, value):
        self.__srcip = IPAddr(value)

    @property
    def dstip(self):
        return self.__dstip

    @dstip.setter
    def dstip(self, value):
        self.__dstip = IPAddr(value)

    @property
    def flags(self):
        return self.__flags

    @flags.setter
    def flags(self, value):
        self.__flags = IPFragmentFlag(value)

    @property
    def fragment_offset(self):
        return self.__fragoffset

    @fragment_offset.setter
    def fragment_offset(self, value):
        if not (0 <= value < 2**13):
            raise Exception("Invalid fragment offset value")
        self.__fragoffset = value
    
    @property
    def hl(self):
        return self.size() // 4

    @property
    def checksum(self):
        data = struct.pack(IPv4.__PACKFMT__,
                    (4 << 4) + self.hl, self.tos,
                    self.__totallen, self.ipid,
                    (self.flags.value << 13) | self.fragment_offset, 
                    self.ttl,
                    self.protocol.value, 0, self.srcip.packed, self.dstip.packed)
        self.__csum = checksum(data, 0)
        return self.__csum

    def __str__(self):
        return '{} {}->{} {}'.format(self.__class__.__name__, self.srcip, self.dstip, self.protocol)

