import struct
from ipaddress import IPv6Address
from enum import Enum

from switchyard.lib.packet.packet import PacketHeaderBase,Packet

'''
References:
    http://en.wikipedia.org/wiki/ICMPv6
'''


class ICMPv6Type(Enum):
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    PrivateExperimentation1 = 100,
    PrivateExperimentation2 = 101,
    EchoRequest = 128,
    EchoReply = 129
    MulticastListenerQuery = 130
    MulticastListenerReport = 131
    MulticastListenerDone = 132
    RouterSolicitation = 133
    RouterAdvertisement = 134
    NeighborSolicitation = 135
    NeighborAdvertisement = 136
    RedirectMessage = 137
    RouterRenumbering = 138
    ICMPNodeInformationQuery = 139
    ICMPNodeInformationResponse = 140
    InverseNeighborDiscoverySolicitationMessage = 141
    InverseNeighborDiscoveryAdvertisementMessage = 142
    Version2MulticastListenerReport = 143
    HomeAgentAddressDiscoveryRequestMessage = 144
    HomeAgentAddressDiscoveryReplyMessage = 145
    MobilePrefixSolicitation = 146
    MobilePrefixAdvertisement = 147
    CertificationPathSolicitationMessage = 148
    CertificationPathAdvertisementMessage = 149
    ICMPmessagesutilizedbyexperimentalmobilityprotocolssuchasSeamoby = 150
    MulticastRouterAdvertisement = 151
    MulticastRouterSolicitation = 152
    MulticastRouterTermination = 153
    FMIPv6Messages = 154
    RPLControlMessage = 155
    ILNPv6LocatorUpdateMessage = 156
    DuplicateAddressRequest = 157
    DuplicateAddressConfirmation = 158
    Privateexperimentation3 = 200
    Privateexperimentation4 = 201

class ICMPv6(PacketHeaderBase):
    __slots__ = ['__type', '__code','__csum','__body' ]
    __PACKFMT__ = '!BBH'
    __MINLEN__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.icmptype = ICMPv6Type.EchoRequest
        self.icmpcode = 0
        self.__csum = 0
        self.__body = b''

    @property
    def icmptype(self):
        return self.__type

    @icmptype.setter
    def icmptype(self, value):
        self.__type = ICMPv6Type(value)

    @property
    def icmpcode(self):
        return self.__code

    @icmpcode.setter
    def icmpcode(self, value):
        self.__code = int(value)

    @property
    def body(self):
        return self.__body

    def to_bytes(self):
        raise Exception("Not implemented")

    def tail_serialized(self, raw):
        return

    def size(self):
        raise Exception("Not implemented")

    def __eq__(self, other):
        raise Exception("Not implemented") # FIXME

    def __str__(self):
        return "{} {}:{} (bodylen {})".format(self.__class__.__name__, self.icmptype, self.icmpcode, len(self.__body))

    def next_header_class(self):
        return None

    def from_bytes(self, raw):
        if len(raw) < ICMPv6.__MINLEN__:
            raise Exception("Not enough data to unpack ICMPv6")

        self.icmptype = raw[0]
        self.icmpcode = raw[1]
        self.__csum = raw[2:4]
        self.__body = raw[4:]
        return b''

