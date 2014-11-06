from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.packet.common import checksum, ICMPType, ICMPTypeCodeMap
import struct
from enum import Enum
from ipaddress import IPv4Address

'''
References: https://www.ietf.org/rfc/rfc792.txt
            https://tools.ietf.org/html/rfc4884 (extension parameters)
TCP/IP Illustrated, Vol 1.
'''


class ICMP(PacketHeaderBase):
    '''
    A base class for all ICMP message types.  This class isn't normally instantiated, but rather
    its subclasses are.
    '''
    __slots__ = ('_type', '_code', '_icmpdata', '_valid_types', 
                 '_valid_codes_map', '_classtype_from_icmptype', 
                 '_icmptype_from_classtype', '_checksum')
    __PACKFMT__ = '!BBH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self._valid_types = ICMPType
        self._valid_codes_map = ICMPTypeCodeMap
        self._classtype_from_icmptype = ICMPClassFromType
        self._icmptype_from_classtype = ICMPTypeFromClass
        self._type = self._valid_types.EchoRequest
        self._code = self._valid_codes_map[self._type].EchoRequest
        self._icmpdata = ICMPEchoRequest()
        self._checksum = 0

    def size(self):
        return struct.calcsize(ICMP.__PACKFMT__) + len(self._icmpdata.to_bytes())

    def checksum(self):
        self._checksum = checksum(b''.join( (struct.pack(ICMP.__PACKFMT__, self._type.value, self._code.value, 0), self._icmpdata.to_bytes())))
        return self._checksum

    def to_bytes(self, dochecksum=True):
        '''
        Return packed byte representation of the UDP header.
        '''
        csum = 0
        if dochecksum:
            csum = self.checksum()
        return b''.join((struct.pack(ICMP.__PACKFMT__, self._type.value, self._code.value, csum), self._icmpdata.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMP.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an ICMP object".format(len(raw)))
        fields = struct.unpack(ICMP.__PACKFMT__, raw[:ICMP.__MINSIZE__])
        self._type = self._valid_types(fields[0])
        self._code = self._valid_codes_map[self.icmptype](fields[1])
        csum = fields[2]
        self._icmpdata = self._classtype_from_icmptype(self._type)()
        self._icmpdata.from_bytes(raw[ICMP.__MINSIZE__:])
        if csum != self.checksum():
            print ("Checksum in raw ICMP packet does not match calculated checksum ({} versus {})".format(csum, self.checksum()))
        return raw[self.size():]

    def __eq__(self, other):
        return self.icmptype == other.icmptype and \
            self.icmpcode == other.icmpcode and \
            self.icmpdata == other.icmpdata

    @property
    def icmptype(self):
        return self._type

    @property
    def icmpcode(self):
        return self._code

    @icmptype.setter
    def icmptype(self,value):
        if not isinstance(value, self._valid_types):
            raise ValueError("ICMP type must be an {} enumeration".format(type(self._valid_types)))
        cls = self._classtype_from_icmptype(value)
        if not issubclass(self.icmpdata.__class__, cls):
            self.icmpdata = cls()
        self._type = value
        codes = self._valid_codes_map[value]
        for code in codes:
            if code.value == 0:
                self._code = code
                break

    @icmpcode.setter
    def icmpcode(self,value):
        if issubclass(value.__class__, Enum):
            validcodes = self._valid_codes_map[self._type]
            if value not in validcodes:
                raise ValueError("Invalid code {} for type {}".format(value, self._type))
            self._code = value
        elif isinstance(value, int):
            self._code = self._valid_codes_map[self.icmptype](value)

    def __str__(self):
        typecode = self.icmptype.name
        if self.icmptype.name != self.icmpcode.name:
            typecode = '{}:{}'.format(self.icmptype.name, self.icmpcode.name)
        return '{} {} {}'.format(self.__class__.__name__, typecode, str(self.icmpdata))

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    @property
    def icmpdata(self):
        return self._icmpdata

    @icmpdata.setter
    def icmpdata(self, dataobj):
        if not issubclass(dataobj.__class__, ICMPPacketData):
            raise Exception("ICMP data must be subclass of ICMPPacketData (you gave me {})".format(dataobj.__class__.__name__))
        self._icmpdata = dataobj
        self.icmptype = self._icmptype_from_classtype(dataobj.__class__)

class ICMPPacketData(PacketHeaderBase):
    __slots__ = ['_rawip'] 
    def __init__(self):
        super().__init__()
        self._rawip = b''

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return 4 + len(self._rawip)

    def to_bytes(self):
        return b'\x00\x00\x00\x00' + self._rawip

    def from_bytes(self, raw):
        self._rawip = raw[4:]

    @property
    def data(self):
        return self._rawip

    @data.setter
    def data(self, value):
        self._rawip = bytes(value)

    def __eq__(self, other):
        return self.data == other.data

    def __hash__(self):
        return sum(self._rawip)

    def __str__(self):
        return '{} bytes of IPv4 ({})'.format(len(self.__rawip), self.__rawip[:10])

class ICMPSourceQuench(ICMPPacketData):
    pass

class ICMPRedirect(ICMPPacketData):
    __slots__ = ['_redirectto']
    def __init__(self):
        super().__init__()

    def to_bytes(self):
        return b''.join( (self.__redirectto.packed,super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!I', raw[:4])
        self._redirectto = IPv4Address(fields[0])
        super().from_bytes(raw)

    def __str__(self):
        return '{} RedirectAddress: {}'.format(super().__str__(), self._redirectto)
    
class ICMPDestinationUnreachable(ICMPPacketData):
    __slots__ = ('_origdgramlen', '_nexthopmtu')
    def __init__(self):
        super().__init__()
        self.__nexthopmtu = 0
        self.__origdgramlen = 0

    def to_bytes(self):
        return b''.join( (struct.pack('!xBH', self._origdgramlen, self._nexthopmtu), super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!xBH', raw[:4])
        self._origdgramlen = fields[0]
        self._nexthopmtu = fields[1]
        super().from_bytes(raw)

    def __str__(self):
        return '{} NextHopMTU: {}'.format(super().__str__(), self._nexthopmtu)
    

class ICMPEchoRequest(ICMPPacketData):
    __slots__ = ['_identifier','_sequence','_data']
    __PACKFMT__ = '!HH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)
    
    def __init__(self):
        super().__init__()
        self._identifier = 0
        self._sequence = 0
        self._data = b''

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return self.__MINSIZE__ + len(self.__data)

    def from_bytes(self, raw):
        fields = struct.unpack(ICMPEchoRequest.__PACKFMT__, 
            raw[:ICMPEchoRequest.__MINSIZE__])
        self._identifier = fields[0]
        self._sequence = fields[1]
        self._data = raw[ICMPEchoRequest.__MINSIZE__:]
        return b''

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPEchoRequest.__PACKFMT__,
            self._identifier, self._sequence), self._data ) )

    def __str__(self):
        return '{} {} ({} data bytes)'.format(self._identifier, self._sequence, len(self._data))

    def __eq__(self, other):
        return self.identifier == other.identifier and \
            self.sequence == other.sequence and \
            self.data == other.data

    @property
    def identifier(self):
        return self._identifier

    @property
    def sequence(self):
        return self._sequence

    @property
    def data(self):
        return self._data

    @identifier.setter
    def identifier(self, value):
        self._identifier = value

    @sequence.setter
    def sequence(self, value):
        self._sequence = value

    @data.setter
    def data(self, value):
        if not isinstance(value, bytes):
            self._data = bytes(value, 'utf8')
        else:
            self._data = value

class ICMPEchoReply(ICMPEchoRequest):
    pass

class ICMPTimeExceeded(ICMPPacketData):
    __slots__ = ('__nexthopmtu','__origdgramlen',)
    def __init__(self):
        super().__init__()
        self.__origdgramlen = 0

    def to_bytes(self):
        return b''.join( (struct.pack('!xBH', self.__origdgramlen, 0), super().to_bytes()) )
        # FIXME: origdgram len should be padded to 4 bytes for v4, and 8 bytes for v6

    def from_bytes(self, raw):
        fields = struct.unpack('!xBH', raw[:4])
        self.__origdgramlen = fields[0]
        self.__nexthopmtu = fields[1]
        super().from_bytes(raw)

    @property
    def origdgramlen(self):
        return self.__origdgramlen

    @origdgramlen.setter
    def origdgramlen(self, value):
        self.__origdgramlen = int(value)

    def __str__(self):
        return '{} OrigDgramLen: {}'.format(super().__str__(), self.__origdgramlen)

class ICMPAddressMaskRequest(ICMPPacketData):
    __slots__ = ['__identifier','__sequence','__addrmask']
    __PACKFMT__ = '!HHI'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        super().__init__()
        self.__identifier = 0
        self.__sequence = 0
        self.__addrmask = IPv4Address('0.0.0.0')

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return ICMPAddressMaskRequest.__MINSIZE__

    def to_bytes(self):
        return struct.pack(ICMPAddressMaskRequest.__PACKFMT__, 
            self.__identifier, self.__sequence, self.__addrmask.packed)

    def from_bytes(self, raw):
        fields = struct.unpack(ICMPAddressMaskRequest.__PACKFMT__, raw)
        self.__identifier = fields[0]
        self.__sequence = fields[1]
        self.__addrmask = IPv4Address(fields[2])
        return b''

    def __str__(self):
        return '{} {} {}'.format(self.__identifier, self.__sequence, self.__addrmask)


class ICMPAddressMaskReply(ICMPAddressMaskRequest):
    pass

class ICMPInformationRequest(ICMPPacketData):
    pass

class ICMPInformationReply(ICMPPacketData):
    pass

class ICMPRouterAdvertisement(ICMPPacketData):
    pass

class ICMPRouterSolicitation(ICMPPacketData):
    pass

class ICMPParameterProblem(ICMPPacketData):
    pass

class ICMPTimestamp(ICMPPacketData):
    pass

class ICMPTimestampReply(ICMPPacketData):
    pass


def construct_icmp_class_map():
    clsmap = {}
    for xtype in ICMPType:
        clsname = "ICMP{}".format(xtype.name)
        cls = eval(clsname)
        clsmap[xtype] = cls
    def inner(icmptype):
        icmptype = ICMPType(icmptype)
        return clsmap.get(icmptype, None)
    return inner

def construct_icmp_type_map():
    typemap = {}
    for xtype in ICMPType:
        clsname = "ICMP{}".format(xtype.name)
        cls = eval(clsname)
        typemap[cls] = xtype
    def inner(icmpcls):
        return typemap.get(icmpcls, None)
    return inner    

ICMPClassFromType = construct_icmp_class_map()
ICMPTypeFromClass = construct_icmp_type_map()
