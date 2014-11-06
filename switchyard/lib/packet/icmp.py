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
        if not issubclass(dataobj.__class__, ICMPData):
            raise Exception("ICMP data must be subclass of ICMPData (you gave me {})".format(dataobj.__class__.__name__))
        self._icmpdata = dataobj
        self.icmptype = self._icmptype_from_classtype(dataobj.__class__)


class ICMPData(PacketHeaderBase):
    __slots__ = ('_rawpayload',)

    def __init__(self):
        super().__init__()
        self._rawpayload = b''

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return len(self._rawpayload)

    def to_bytes(self):
        return self._rawpayload

    def from_bytes(self, raw):
        self._rawpayload = bytes(raw)

    @property
    def data(self):
        return self._rawpayload

    @data.setter
    def data(self, value):
        if not isinstance(value, bytes):
            self._data = bytes(value, 'utf8')
        else:
            self._data = value

    def __eq__(self, other):
        return self.data == other.data

    def __hash__(self):
        return sum(self._rawpayload)

    def __str__(self):
        return '{} bytes of raw payload ({})'.format(len(self._rawpayload), self._rawpayload[:10])


class ICMPSourceQuench(ICMPData):
    __MINSIZE__ = 4

    def __init__(self):
        super().__init__()

    def size(self):
        return 4 + super().size()

    def to_bytes(self):
        return b''.join((b'\x00' * 4, super().to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMPSourceQuench.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct ICMPSourceQuench data object".format(len(raw)))
        super().from_bytes(raw[4:])       

class ICMPRedirect(ICMPData):
    __slots__ = ['_redirectto']
    def __init__(self):
        super().__init__()
        self._redirectto = IPv4Address('0.0.0.0')

    def to_bytes(self):
        return b''.join( (self._redirectto.packed,super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!I', raw[:4])
        self._redirectto = IPv4Address(fields[0])
        super().from_bytes(raw[4:])

    def __str__(self):
        return '{} RedirectAddress: {}'.format(super().__str__(), self._redirectto)

    @property
    def redirectto(self):
        return self._redirectto

    @redirectto.setter
    def redirectto(self, value):
        self._redirectto = IPv4Address(value) 

    
class ICMPDestinationUnreachable(ICMPData):
    __slots__ = ('_origdgramlen', '_nexthopmtu')
    def __init__(self):
        super().__init__()
        self._nexthopmtu = 0
        self._origdgramlen = 0

    def to_bytes(self):
        return b''.join( (struct.pack('!xBH', self._origdgramlen, self._nexthopmtu), super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!xBH', raw[:4])
        self._origdgramlen = fields[0]
        self._nexthopmtu = fields[1]
        super().from_bytes(raw[4:])

    def __str__(self):
        return '{} NextHopMTU: {}'.format(super().__str__(), self._nexthopmtu)
    

class ICMPEchoRequest(ICMPData):
    __slots__ = ['_identifier','_sequence']
    __PACKFMT__ = '!HH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)
    
    def __init__(self):
        super().__init__()
        self._identifier = 0
        self._sequence = 0

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return self.__MINSIZE__ + super().size()

    def from_bytes(self, raw):
        fields = struct.unpack(ICMPEchoRequest.__PACKFMT__, 
            raw[:ICMPEchoRequest.__MINSIZE__])
        self._identifier = fields[0]
        self._sequence = fields[1]
        super().from_bytes(raw[4:])
        return b''

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPEchoRequest.__PACKFMT__,
            self._identifier, self._sequence), super().to_bytes() ) )

    def __str__(self):
        return '{} {} ({} data bytes)'.format(self._identifier, self._sequence, len(self.data))

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
   
    @identifier.setter
    def identifier(self, value):
        self._identifier = value

    @sequence.setter
    def sequence(self, value):
        self._sequence = value

class ICMPEchoReply(ICMPEchoRequest):
    pass

class ICMPTimeExceeded(ICMPData):
    __slots__ = ('_nexthopmtu','_origdgramlen',)
    def __init__(self):
        super().__init__()
        self._origdgramlen = 0

    def to_bytes(self):
        return b''.join( (struct.pack('!xBH', self._origdgramlen, 0), super().to_bytes()) )
        # FIXME: origdgram len should be padded to 4 bytes for v4, and 8 bytes for v6

    def from_bytes(self, raw):
        fields = struct.unpack('!xBH', raw[:4])
        self._origdgramlen = fields[0]
        self._nexthopmtu = fields[1]
        super().from_bytes(raw[4:])

    @property
    def origdgramlen(self):
        return self._origdgramlen

    @origdgramlen.setter
    def origdgramlen(self, value):
        self._origdgramlen = int(value)

    def __str__(self):
        return '{} OrigDgramLen: {}'.format(super().__str__(), self._origdgramlen)

class ICMPAddressMaskRequest(ICMPData):
    __slots__ = ['_identifier','_sequence','_addrmask']
    __PACKFMT__ = '!HH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        super().__init__()
        self._identifier = 0
        self._sequence = 0
        self._addrmask = IPv4Address('0.0.0.0')

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return ICMPAddressMaskRequest.__MINSIZE__

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPAddressMaskRequest.__PACKFMT__, 
            self._identifier, self._sequence), self._addrmask.packed))

    def from_bytes(self, raw):
        if len(raw) < ICMPAddressMaskRequest.__MINSIZE__:
            raise Exception("Not enough bytes to unpack ICMPAddressMaskRequest object")
        fields = struct.unpack(ICMPAddressMaskRequest.__PACKFMT__, raw[:4])
        self._identifier = fields[0]
        self._sequence = fields[1]
        self._addrmask = IPv4Address(raw[4:8])
        return b''

    @property
    def addrmask(self):
        return self._addrmask

    @addrmask.setter
    def addrmask(self, value):
        self._addrmask = IPv4Address(value)

    @property
    def identifier(self):
        return self._identifier

    @identifier.setter
    def identifier(self, value):
        self._identifier = int(value)

    @property
    def sequence(self):
        return self._sequence

    @sequence.setter
    def sequence(self, value):
        self._sequence = int(value)

    def __str__(self):
        return '{} {} {}'.format(self._identifier, self._sequence, self._addrmask)


class ICMPAddressMaskReply(ICMPAddressMaskRequest):
    pass

class ICMPInformationRequest(ICMPData):
    pass

class ICMPInformationReply(ICMPData):
    pass

class ICMPRouterAdvertisement(ICMPData):
    pass

class ICMPRouterSolicitation(ICMPData):
    pass

class ICMPParameterProblem(ICMPData):
    pass

class ICMPTimestamp(ICMPData):
    pass

class ICMPTimestampReply(ICMPData):
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
