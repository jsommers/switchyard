import struct
from abc import ABCMeta, abstractmethod
import pdb

from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
from switchyard.lib.packet.common import IPProtocol,IPFragmentFlag,IPOptionCopy,IPOptionClass,IPOptionNumber, checksum

'''
References:
    "RFC791", INTERNET PROTOCOL.  DARPA INTERNET PROGRAM PROTOCOL SPECIFICATION.
        September 1981.
    http://en.wikipedia.org/wiki/IPv4
'''

IPTypeClasses = {
    IPProtocol.ICMP: None,
    IPProtocol.TCP: None,
    IPProtocol.UDP: None,
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

    @staticmethod
    def from_bytes(raw):
        raise Exception("Not implemented yet")


class IPOptionEndOfOptionList(IPOption):
    __PACKFMT__ = 'B'

    def __init__(self):
        super().__init__(IPOptionNumber.EndOfOptionList)

    def length(self):
        return struct.calcsize(__PACKFMT__)

    def to_bytes(self):
        return struct.pack(__PACKFMT__, self.optnum.value)


class IPOptionNoOperation(IPOption):
    __PACKFMT__ = 'B'

    def __init__(self):
        super().__init__(IPOptionNumber.NoOperation)

    def length(self):
        return struct.calcsize(__PACKFMT__)

    def to_bytes(self):
        return struct.pack(__PACKFMT__, self.optnum.value)

class IPOptionSecurity(IPOption):
    __PACKFMT__ = ''
    def __init__(self):
        super().__init__(IPOptionNumber.Security)

    

class IPOptionLooseSourceRouting(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.LooseSourceRouting)

class IPOptionStrictSourceRouting(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.StrictSourceRouting)

class IPOptionRecordRoute(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.RecordRoute)

class IPOptionStreamID(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.StreamID)

class IPOptionTimestamp(IPOption):
    def __init__(self):
        super().__init__(IPOptionNumber.Timestamp)


class IPOptionList(object):
    def __init__(self):
        self.__options = []

    @staticmethod
    def from_bytes(rawbytes):
        '''
        Takes a byte string as a parameter and returns a list of
        IPOption objects.
        '''
        # FIXME
        return IPOptionList() 

    def to_bytes(optionlist):
        '''
        Takes a list of IPOption objects and returns a packed byte string
        of options, appropriately padded if necessary.
        '''
        # FIXME
        return b''
    
    def add_option(self, opt):
        if isinstance(opt, IPOption):
            self.__options.append(opt)
        else:
            raise Exception("Option to be added must be an IPOption object")

    def raw_length(self):
        # FIXME
        return 0

    def size(self):
        return len(self.__options)


class IPv4(PacketHeaderBase):
    __slots__ = ['__tos','__totallen','__ttl',
                 '__ipid','__flags','__fragoffset',
                 '__protocol','__csum',
                 '__srcip','__dstip','__options']
    __PACKFMT__ = '!BBHHHBBHII'
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
                    self.protocol.value, 0, int(self.srcip), int(self.dstip))
        self.__csum = checksum(data, 0)
        return self.__csum

