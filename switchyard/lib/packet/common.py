import struct
import array
from enum import Enum
from socket import ntohs

class EtherType(Enum):
    NoType = 0xFFFF
    IP = 0x0800
    IPv4 = 0x0800
    ARP = 0x0806
    x8021Q = 0x8100
    IPv6 = 0x86dd
    SLOW = 0x8809
    MPLS = 0x8847
    x8021AD = 0x88a8
    LLDP = 0x88cc
    x8021AH = 0x88e7
    IEEE8023 = 0x05dc

class ArpHwType(Enum):
    Ethernet = 1

class ArpOperation(Enum):
    Request = 1
    Reply = 2
    RequestReverse = 3
    ReplyReverse = 4

class IPProtocol(Enum):
    IPv6HopOpt = 0
    ICMP = 1
    IGMP = 2
    IPinIP = 4
    TCP = 6
    UDP = 17
    IPv6Encap = 41
    IPv6Route = 43
    IPv6Frag = 44
    RSVP = 46
    GRE = 47
    EncapsulatingSecurityPayload = 50
    AuthenticationHeader = 51
    IPMobility = 55
    TLSP = 56
    IPv6ICMP = 58
    IPv6NoNext = 59
    IPv6DestinationOptions = 60
    EIGRP = 88
    OSPF = 89
    IPIP = 94
    EtherIP = 97
    SCTP = 132
    IPv6Mobility = 135
    MPLSinIP = 137
    IPv6Shim6 = 140

class IPFragmentFlag(Enum):
    NoFragments = 0
    DontFragment = 2
    MoreFragments = 4

class IPOptionCopy(Enum):
    NotCopied = 0
    Copied = 1

class IPOptionClass(Enum):
    Control = 0
    Reserved1 = 1
    DebuggingMeasurement = 2
    Reserved3 = 3

class IPOptionNumber(Enum):
    EndOfOptionList = 0
    NoOperation = 1
    Security = 2
    LooseSourceRouting = 3
    Timestamp = 4
    RecordRoute = 7
    StreamId = 8
    StrictSourceRouting = 9
    MTUProbe = 11
    MTUReply = 12
    Traceroute = 18
    RouterAlert = 20


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
    start += struct.unpack('H', data[-1]+'\0')[0] # Specify order?

  start  = (start >> 16) + (start & 0xffff)
  start += (start >> 16)
  #while start >> 16:
  #  start = (start >> 16) + (start & 0xffff)

  return ntohs(~start & 0xffff)

