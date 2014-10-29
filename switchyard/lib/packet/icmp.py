from switchyard.lib.packet.packet import PacketHeaderBase,Packet
from switchyard.lib.packet.common import checksum, ICMPType
import struct
from enum import Enum
from ipaddress import IPv4Address

'''
References: https://www.ietf.org/rfc/rfc792.txt
TCP/IP Illustrated, Vol 1.
'''


ICMPTypeCodeMap = {
    ICMPType.EchoReply: Enum('EchoReply', {'EchoReply': 0}),
    ICMPType.DestinationUnreachable: Enum('DestinationUnreachable', {
        'NetworkUnreachable': 0, 
        'HostUnreachable': 1, 
        'ProtocolUnreachable': 2, 
        'PortUnreachable': 3, 
        'FragmentationRequiredDFSet': 4, 
        'SourceRouteFailed': 5, 
        'DestinationNetworkUnknown': 6,
        'DestinationHostUnknown': 7,
        'SourceHostIsolated': 8,
        'NetworkAdministrativelyProhibited': 9,
        'HostAdministrativelyProhibited': 10,
        'NetworkUnreachableForTOS': 11,
        'HostUnreachableForTOS': 12,
        'CommunicationAdministrativelyProhibited': 13,
        'HostPrecedenceViolation': 14,
        'PrecedenceCutoffInEffect': 15,
    }),
    ICMPType.SourceQuench: Enum('SourceQuench', { 'SourceQuench': 0 }),
    ICMPType.Redirect: Enum('Redirect', {
        'RedirectForNetwork': 0,
        'RedirectForHost': 1,
        'RedirectForTOSAndNetwork': 2,
        'RedirectForTOSAndHost': 3
    }),
    ICMPType.EchoRequest: Enum('EchoRequest', { 'EchoRequest': 0 }),
    ICMPType.RouterAdvertisement: Enum('RouterAdvertisement', { 'RouterAdvertisement': 0 }),
    ICMPType.RouterSolicitation: Enum('RouterSolicitation', { 'RouterSolicitation': 0 }),
    ICMPType.TimeExceeded: Enum('TimeExceeded', {
        'TTLExpired': 0,
        'FragmentReassemblyTimeExceeded': 1,
    }),
    ICMPType.ParameterProblem: Enum('BadIPHeader', { 
        'PointerIndicatesError': 0,
        'MissingRequiredOption': 1,
        'BadLength': 2
    }),
    ICMPType.Timestamp: Enum('Timestamp', { 'Timestamp': 0 }),
    ICMPType.TimestampReply: Enum('TimestampReply', { 'TimestampReply': 0 }),
    ICMPType.InformationRequest: Enum('InformationRequest', { 'InformationRequest': 0 }),
    ICMPType.InformationReply: Enum('InformationReply', { 'InformationReply': 0 }),
    ICMPType.AddressMaskRequest: Enum('AddressMaskRequest', { 'AddressMaskRequest': 0 }),
    ICMPType.AddressMaskReply: Enum('AddressMaskReply', { 'AddressMaskReply': 0 }),
}

class ICMP(PacketHeaderBase):
    '''
    A base class for all ICMP message types.  This class isn't normally instantiated, but rather
    its subclasses are.
    '''
    __slots__ = ['__type','__code','__icmpdata']
    __PACKFMT__ = '!BBH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.__type = ICMPType.EchoRequest
        self.__code = ICMPTypeCodeMap[self.__type].EchoRequest
        self.__icmpdata = ICMPEchoRequest()

    def size(self):
        return struct.calcsize(ICMP.__PACKFMT__) + len(self.__icmpdata.to_bytes())

    def checksum(self):
        return checksum(b''.join( (struct.pack(ICMP.__PACKFMT__, self.__type.value, self.__code.value, 0),
                                   self.__icmpdata.to_bytes())))

    def to_bytes(self, dochecksum=True):
        '''
        Return packed byte representation of the UDP header.
        '''
        csum = 0
        if dochecksum:
            csum = self.checksum()
        return b''.join((struct.pack(ICMP.__PACKFMT__, self.__type.value, self.__code.value, csum),
                         self.__icmpdata.to_bytes()))

    def from_bytes(self, raw):
        if len(raw) < ICMP.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an ICMP object".format(len(raw)))
        fields = struct.unpack(ICMP.__PACKFMT__, raw[:ICMP.__MINSIZE__])
        self.__type = ICMPType(fields[0])
        self.__code = ICMPTypeCodeMap[self.icmptype](fields[1])
        csum = fields[2]
        self.__icmpdata = ICMPClassFromType(self.__type)()
        self.__icmpdata.from_bytes(raw[ICMP.__MINSIZE__:])
        if csum != self.checksum():
            print ("Checksum in raw ICMP packet does not match calculated checksum ({} versus {})".format(csum, self.checksum()))
        return raw[self.size():]

    def __eq__(self, other):
        return self.icmptype == other.icmptype and \
            self.icmpcode == other.icmpcode and \
            self.icmpdata == other.icmpdata

    @property
    def icmptype(self):
        return self.__type

    @property
    def icmpcode(self):
        return self.__code

    @icmptype.setter
    def icmptype(self,value):
        if not isinstance(value, ICMPType):
            raise ValueError("ICMP type must be an ICMPType enumeration")
        cls = ICMPClassFromType(value)
        if not isinstance(self.__icmpdata, cls):
            self.__icmpdata = cls()
        self.__type = value

    @icmpcode.setter
    def icmpcode(self,value):
        if not issubclass(value.__class__, Enum):
            raise ValueError("ICMP code must be an enumerated type")
        self.__code = value

    def __str__(self):
        return '{} {}:{} {}'.format(self.__class__.__name__, self.icmptype, self.icmpcode, str(self.icmpdata))

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return

    @property
    def icmpdata(self):
        return self.__icmpdata

    @icmpdata.setter
    def icmpdata(self, dataobj):
        if not issubclass(dataobj, ICMPPacketData):
            raise Exception("ICMP data must be subclass of ICMPPacketData (you gave me {})".format(dataobj.__class__.__name__))
        self.__icmpdata = dataobj
        self.__code = ICMPTypeFromClass(dataobj.__class__)


class ICMPPacketData(PacketHeaderBase):
    __slots__ = ['__rawip'] 
    def __init__(self):
        super().__init__()
        self.__rawip = b''

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return

    def size(self):
        return 4 + len(self.__rawip)

    def to_bytes(self):
        return b'\x00\x00\x00\x00' + self.__rawip

    def from_bytes(self, raw):
        self.__rawip = raw[4:]

    @property
    def data(self):
        return self.__rawip

    @data.setter
    def data(self, value):
        self.__rawip = bytes(value)

    def __eq__(self, other):
        return self.data == other.data

    def __str__(self):
        return '{} {} bytes of IPv4 ({})'.format(self.__class__.__name__, 
            len(self.__rawip), self.__rawip[:10])

class ICMPSourceQuench(ICMPPacketData):
    pass

class ICMPRedirect(ICMPPacketData):
    __slots__ = ['__redirectto']
    def __init__(self):
        super().__init__()

    def to_bytes(self):
        return b''.join( (self.__redirectto.packed,super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!I', raw[:4])
        self.__redirectto = IPv4Address(fields[0])
        super().from_bytes(raw)

    def __str__(self):
        return '{} RedirectAddress: {}'.format(super().__str__(), self.__redirectto)
    
class ICMPDestinationUnreachable(ICMPPacketData):
    __slots__ = ['__nexthopmtu']
    def __init__(self):
        super().__init__()
        self.__nexthopmtu = 0

    def to_bytes(self):
        return b''.join( (struct.pack('!HH', self.__nexthopmtu, 0), super().to_bytes()) )

    def from_bytes(self, raw):
        fields = struct.unpack('!HH', raw[:4])
        self.__nexthopmtu = fields[1]
        super().from_bytes(raw)

    def __str__(self):
        return '{} NextHopMTU: {}'.format(super().__str__(), self.__nexthopmtu)
    

class ICMPEchoRequest(PacketHeaderBase):
    __slots__ = ['__identifier','__sequence','__data']
    __PACKFMT__ = '!HH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)
    
    def __init__(self):
        super().__init__()
        self.__identifier = 0
        self.__sequence = 0
        self.__data = b''

    def next_header_class(self):
        return None

    def tail_serialized(self, raw):
        return

    def size(self):
        return self.__MINSIZE__ + len(self.__data)

    def from_bytes(self, raw):
        fields = struct.unpack(ICMPEchoRequest.__PACKFMT__, 
            raw[:ICMPEchoRequest.__MINSIZE__])
        self.__identifier = fields[0]
        self.__sequence = fields[1]
        self.__data = raw[ICMPEchoRequest.__MINSIZE__:]
        return b''

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPEchoRequest.__PACKFMT__,
            self.__identifier, self.__sequence), self.__data) )

    def __str__(self):
        return '{} {} {} ({} data bytes)'.format(self.__class__.__name__,
            self.__identifier, self.__sequence, len(self.__data))

    def __eq__(self, other):
        return self.identifier == other.identifier and \
            self.sequence == other.sequence and \
            self.data == other.data

    @property
    def identifier(self):
        return self.__identifier

    @property
    def sequence(self):
        return self.__sequence

    @property
    def data(self):
        return self.__data

    @identifier.setter
    def identifier(self, value):
        self.__identifier = value

    @sequence.setter
    def sequence(self, value):
        self.__sequence = value

    @data.setter
    def data(self, value):
        self.__data = value


class ICMPEchoReply(ICMPEchoRequest):
    def __str__(self):
        return '{} {} {} ({} data bytes, starts with: {})'.format(self.__class__.__name__,
            self.identifier, self.sequence, len(self.data), self.data[:2])

class ICMPTimeExceeded(ICMPPacketData):
    pass

class ICMPAddressMaskRequest(PacketHeaderBase):
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

    def tail_serialized(self, raw):
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
        return '{} {} {} {}'.format(self.__class__.__name__, self.__identifier, self.__sequence, self.__addrmask)


class ICMPAddressMaskReply(ICMPAddressMaskRequest):
    pass

class ICMPInformationRequest(PacketHeaderBase):
    pass

class ICMPInformationReply(PacketHeaderBase):
    pass

class ICMPRouterAdvertisement(PacketHeaderBase):
    pass

class ICMPRouterSolicitation(PacketHeaderBase):
    pass

class ICMPParameterProblem(PacketHeaderBase):
    pass

class ICMPTimestamp(PacketHeaderBase):
    pass

class ICMPTimestampReply(PacketHeaderBase):
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
