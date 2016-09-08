import struct
import array
from enum import IntEnum
from socket import ntohs

class EtherType(IntEnum):
    NoType = 0xFFFF
    IP = 0x0800
    IPv4 = 0x0800
    ARP = 0x0806
    x8021Q = 0x8100
    Vlan = 0x8100
    VLAN = 0x8100
    IPv6 = 0x86dd
    SLOW = 0x8809
    MPLS = 0x8847
    x8021AD = 0x88a8
    LLDP = 0x88cc
    x8021AH = 0x88e7
    IEEE8023 = 0x05dc

class ArpHwType(IntEnum):
    Ethernet = 1

class ArpOperation(IntEnum):
    Request = 1
    Reply = 2
    RequestReverse = 3
    ReplyReverse = 4

class IPProtocol(IntEnum):
    IPv6HopOption = 0
    ICMP = 1
    IGMP = 2
    IPinIP = 4
    TCP = 6
    UDP = 17
    IPv6Encap = 41
    IPv6RouteOption = 43
    IPv6Fragment = 44
    RSVP = 46
    GRE = 47
    EncapsulatingSecurityPayload = 50
    AuthenticationHeader = 51
    IPMobility = 55
    TLSP = 56
    ICMPv6 = 58
    IPv6NoNext = 59
    IPv6DestinationOption = 60
    EIGRP = 88
    OSPF = 89
    IPIP = 94
    EtherIP = 97
    SCTP = 132
    IPv6Mobility = 135
    MPLSinIP = 137
    IPv6Shim6 = 140

class IPFragmentFlag(IntEnum):
    NoFragments = 0
    DontFragment = 2
    MoreFragments = 4

class IPOptionNumber(IntEnum):
    EndOfOptionList = 0
    NoOperation = 1
    LooseSourceRouting = 3
    Timestamp = 4
    RecordRoute = 7
    StrictSourceRouting = 9
    MTUProbe = 11
    MTUReply = 12
    RouterAlert = 20

class ICMPType(IntEnum):
    EchoReply = 0
    DestinationUnreachable = 3
    SourceQuench = 4
    Redirect = 5
    EchoRequest = 8
    RouterAdvertisement = 9
    RouterSolicitation = 10
    TimeExceeded = 11
    ParameterProblem = 12  
    Timestamp = 13
    TimestampReply = 14
    InformationRequest = 15
    InformationReply = 16
    AddressMaskRequest = 17
    AddressMaskReply = 18

class ICMPCodeEchoReply(IntEnum):
    EchoReply = 0

class ICMPCodeDestinationUnreachable(IntEnum):
    NetworkUnreachable = 0 
    HostUnreachable = 1 
    ProtocolUnreachable = 2 
    PortUnreachable = 3 
    FragmentationRequiredDFSet = 4 
    SourceRouteFailed = 5 
    DestinationNetworkUnknown = 6
    DestinationHostUnknown = 7
    SourceHostIsolated = 8
    NetworkAdministrativelyProhibited = 9
    HostAdministrativelyProhibited = 10
    NetworkUnreachableForTOS = 11
    HostUnreachableForTOS = 12
    CommunicationAdministrativelyProhibited = 13
    HostPrecedenceViolation = 14
    PrecedenceCutoffInEffect = 15

class ICMPCodeSourceQuench(IntEnum):
    SourceQuench = 0

class ICMPCodeRedirect(IntEnum):
    RedirectForNetwork = 0
    RedirectForHost = 1
    RedirectForTOSAndNetwork = 2
    RedirectForTOSAndHost = 3
    
class ICMPCodeEchoRequest(IntEnum):
    EchoRequest = 0

class ICMPCodeRouterAdvertisement(IntEnum):
    RouterAdvertisement = 0

class ICMPCodeRouterSolicitation(IntEnum):
    RouterSolicitation = 0

class ICMPCodeTimeExceeded(IntEnum):
    TTLExpired = 0
    FragmentReassemblyTimeExceeded = 1

class ICMPCodeParameterProblem(IntEnum):
    PointerIndictatesError = 0
    MissingRequiredOption = 1
    BadLength = 2

class ICMPCodeTimestamp(IntEnum):
    Timestamp = 0

class ICMPCodeTimestampReply(IntEnum):
    TimestampReply = 0

class ICMPCodeInformationRequest(IntEnum):
    InformationRequest = 0

class ICMPCodeInformationReply(IntEnum):
    InformationReply = 0

class ICMPCodeAddressMaskRequest(IntEnum):
    AddressMaskRequest = 0

class ICMPCodeAddressMaskReply(IntEnum):
    AddressMaskReply = 0

ICMPTypeCodeMap = {
    ICMPType.EchoReply: ICMPCodeEchoReply,
    ICMPType.DestinationUnreachable: ICMPCodeDestinationUnreachable,
    ICMPType.SourceQuench: ICMPCodeSourceQuench,
    ICMPType.Redirect: ICMPCodeRedirect,
    ICMPType.EchoRequest: ICMPCodeEchoRequest,
    ICMPType.RouterAdvertisement: ICMPCodeRouterAdvertisement,
    ICMPType.RouterSolicitation: ICMPCodeRouterSolicitation,
    ICMPType.TimeExceeded: ICMPCodeTimeExceeded,
    ICMPType.ParameterProblem: ICMPCodeParameterProblem,
    ICMPType.Timestamp: ICMPCodeTimestamp,
    ICMPType.TimestampReply: ICMPCodeTimestampReply,
    ICMPType.InformationRequest: ICMPCodeInformationRequest,
    ICMPType.InformationReply: ICMPCodeInformationReply,
    ICMPType.AddressMaskRequest: ICMPCodeAddressMaskRequest,
    ICMPType.AddressMaskReply: ICMPCodeAddressMaskReply
}

class ICMPv6Type(IntEnum):
    DestinationUnreachable = 1
    PacketTooBig = 2
    TimeExceeded = 3
    ParameterProblem = 4
    PrivateExperimentation1 = 100
    PrivateExperimentation2 = 101
    EchoRequest = 128
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

ICMPv6TypeCodeMap = {
   ICMPv6Type.EchoRequest: ICMPCodeEchoRequest,
   ICMPv6Type.EchoReply: ICMPCodeEchoReply
}

# the following checksum function was taken from the POX openflow controller

# Copyright 2011,2012 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is derived from the packet library in NOX, which was
# developed by Nicira, Inc.


def checksum (data, start = 0, skip_word = None):
  """
  Calculate standard internet checksum over data starting at start'th byte

  skip_word: If specified, it's the word offset of a word in data to "skip"
             (as if it were zero).  The purpose is when data is received
             data which contains a computed checksum that you are trying to
             verify -- you want to skip that word since it was zero when
             the checksum was initially calculated.
  """
  if len(data) % 2 != 0:
    arr = array.array('H', data[:-1])
  else:
    arr = array.array('H', data)

  if skip_word is not None:
    for i in range(0, len(arr)):
      if i == skip_word:
        continue
      start +=  arr[i]
  else:
    for i in range(0, len(arr)):
      start +=  arr[i]

  if len(data) % 2 != 0:
    start += struct.unpack('H', data[-1:]+b'\x00')[0] # Specify order?

  start  = (start >> 16) + (start & 0xffff)
  start += (start >> 16)
  #while start >> 16:
  #  start = (start >> 16) + (start & 0xffff)

  return ntohs(~start & 0xffff)

