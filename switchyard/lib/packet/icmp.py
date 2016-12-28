import struct
from enum import IntEnum
from ipaddress import IPv4Address

from .packet import PacketHeaderBase,Packet
from .common import checksum, ICMPType, ICMPTypeCodeMap
from ..exceptions import *

'''
References: https://www.ietf.org/rfc/rfc792.txt
            https://tools.ietf.org/html/rfc4884 (extension parameters)
TCP/IP Illustrated, Vol 1.
'''


class ICMP(PacketHeaderBase):
    '''
    A mother class for all ICMP message types.  It holds a reference
    to another object that contains the specific ICMP data (icmpdata), 
    given a particular ICMP type.  Just setting the icmptype causes the
    data object to change (the change happens automatically when you
    set the icmptype).  The icmpcode field will also change, but
    it only changes to some valid code given the new icmptype.
    '''
    __slots__ = ('_type', '_code', '_icmpdata', '_valid_types', 
                 '_valid_codes_map', '_classtype_from_icmptype', 
                 '_icmptype_from_classtype', '_checksum')
    _PACKFMT = '!BBH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._valid_types = ICMPType
        self._valid_codes_map = ICMPTypeCodeMap
        self._classtype_from_icmptype = ICMPClassFromType
        self._icmptype_from_classtype = ICMPTypeFromClass
        self._type = self._valid_types.EchoRequest
        self._code = self._valid_codes_map[self._type].EchoRequest
        self._icmpdata = ICMPEchoRequest()
        self._checksum = 0
        # make sure that icmptype is set first; this has the
        # side-effect of also creating the "right" icmpdata object.
        if 'icmptype' in kwargs:
            self.icmptype = kwargs.pop('icmptype')
        # as a convenience, allow kw syntax to set icmpdata values
        popattr = []
        for attr,val in kwargs.items():
            if hasattr(self.icmpdata, attr):
                setattr(self.icmpdata, attr, val)
                popattr.append(attr)
        for pattr in popattr:
            kwargs.pop(pattr)
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(ICMP._PACKFMT) + len(self._icmpdata.to_bytes())

    def checksum(self):
        self._checksum = checksum(b''.join( (struct.pack(ICMP._PACKFMT, self._type.value, self._code.value, 0), self._icmpdata.to_bytes())))
        return self._checksum

    def to_bytes(self, dochecksum=True):
        '''
        Return packed byte representation of the UDP header.
        '''
        csum = 0
        if dochecksum:
            csum = self.checksum()
        return b''.join((struct.pack(ICMP._PACKFMT, self._type.value, self._code.value, csum), self._icmpdata.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMP._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct an ICMP object".format(len(raw)))
        fields = struct.unpack(ICMP._PACKFMT, raw[:ICMP._MINLEN])
        self._type = self._valid_types(fields[0])
        self._code = self._valid_codes_map[self.icmptype](fields[1])
        self._checksum = fields[2]
        self._icmpdata = self._classtype_from_icmptype(self._type)()
        self._icmpdata.from_bytes(raw[ICMP._MINLEN:])
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
    def icmptype(self, value):
        if not isinstance(value, self._valid_types):
            value = self._valid_types(value)
            # JS: revised following line as above; too restrictive
            # raise ValueError("ICMP type must be an {} enumeration".format(type(self._valid_types)))

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
        if issubclass(value.__class__, IntEnum):
            validcodes = self._valid_codes_map[self._type]
            self._check_typecode_consistency(value) 
            self._code = value
        elif isinstance(value, int):
            self._code = self._valid_codes_map[self.icmptype](value)

    def _check_typecode_consistency(self, xcode):
        validcodes = self._valid_codes_map[self._type]
        if xcode not in validcodes:
            raise ValueError("Invalid code {} for type {}".format(xcode, self._type.name, self._type))

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

    def __init__(self, **kwargs):
        self._rawpayload = b''
        super().__init__(**kwargs)

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
            self._rawpayload = bytes(value, 'utf8')
        else:
            self._rawpayload = value

    def __eq__(self, other):
        return self.data == other.data

    def __str__(self):
        return '{} bytes of raw payload ({})'.format(len(self._rawpayload), self._rawpayload[:10])


class ICMPSourceQuench(ICMPData):
    _MINLEN = 4

    def __init__(self):
        super().__init__()

    def size(self):
        return 4 + super().size()

    def to_bytes(self):
        return b''.join((b'\x00' * 4, super().to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMPSourceQuench._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct ICMPSourceQuench data object".format(len(raw)))
        super().from_bytes(raw[4:])       

class ICMPRedirect(ICMPData):
    __slots__ = ['_redirectto']
    def __init__(self):
        super().__init__()
        self._redirectto = IPv4Address('0.0.0.0')

    def to_bytes(self):
        return b''.join( (self._redirectto.packed,super().to_bytes()) )

    def from_bytes(self, raw):
        if len(raw) < 4:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct ICMPRedirect data object".format(len(raw)))
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
        if len(raw) < 4:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct ICMPDestinationUnreachable data object".format(len(raw)))
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

    @property
    def nexthopmtu(self):
        return self._nexthopmtu

    @nexthopmtu.setter
    def nexthopmtu(self, value):
        self._nexthopmtu = int(value)

    def __str__(self):
        return '{} NextHopMTU: {}'.format(super().__str__(), self._nexthopmtu)
    

class ICMPEchoRequest(ICMPData):
    __slots__ = ['_identifier','_sequence']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)
    
    def __init__(self):
        super().__init__()
        self._identifier = 0
        self._sequence = 0

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        return

    def size(self):
        return self._MINLEN + super().size()

    def from_bytes(self, raw):
        if len(raw) < 4:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct {} data object".format(len(raw)))
        fields = struct.unpack(ICMPEchoRequest._PACKFMT, 
            raw[:ICMPEchoRequest._MINLEN])
        self._identifier = fields[0]
        self._sequence = fields[1]
        super().from_bytes(raw[4:])
        return b''

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPEchoRequest._PACKFMT,
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
        self._identifier = int(value)

    @sequence.setter
    def sequence(self, value):
        self._sequence = int(value)

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
        if len(raw) < 4:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct ICMPTimeExceeded data object".format(len(raw)))
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
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

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
        return ICMPAddressMaskRequest._MINLEN

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPAddressMaskRequest._PACKFMT, 
            self._identifier, self._sequence), self._addrmask.packed))

    def from_bytes(self, raw):
        if len(raw) < ICMPAddressMaskRequest._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack ICMPAddressMaskRequest object")
        fields = struct.unpack(ICMPAddressMaskRequest._PACKFMT, raw[:4])
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
