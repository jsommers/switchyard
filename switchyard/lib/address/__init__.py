__author__ = 'jsommers@colgate.edu'

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from enum import Enum

import struct
import socket

# EthAddr class modified from POX code, license below.

# Copyright 2011,2012,2013 James McCauley
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

class EthAddr (object):
    """
    An Ethernet (MAC) address type.
    """
    __slots__ = ['__value']

    def __init__ (self, addr=None):
      """
      Understands Ethernet address is various forms.  Hex strings, raw byte
      strings, etc.
      """
      # Always stores as a bytes object of length 6
      self.__value = None

      if isinstance(addr, bytes):
          self.__value = bytes(addr[:6])
      elif isinstance(addr, EthAddr):
          self.__value = addr.raw
      elif addr is None:
          self.__value = b'\x00' * 6
      elif isinstance(addr, str):
          possible_separators = (':','-')
          for sep in possible_separators:
              if addr.count(sep) == 5:
                  self.__value = bytes([ int(val,base=16) for val in addr.split(sep)])
                  break

      if not self.__value:
          raise RuntimeError("Expected ethernet address string to be 6 raw " 
                               "bytes or some hex")
  
    def isBridgeFiltered (self):
        """
        Checks if address is an IEEE 802.1D MAC Bridge Filtered MAC Group Address

        This range is 01-80-C2-00-00-00 to 01-80-C2-00-00-0F. MAC frames that
        have a destination MAC address within this range are not relayed by
        bridges conforming to IEEE 802.1D
        """
        return  ((self.__value[0] == 0x01)
    	    and (self.__value[1] == 0x80)
    	    and (self.__value[2] == 0xC2)
    	    and (self.__value[3] == 0x00)
    	    and (self.__value[4] == 0x00)
    	    and (self.__value[5] <= 0x0F))

    @property
    def is_bridge_filtered (self):
        return self.isBridgeFiltered()

    def isGlobal (self):
        """
        Returns True if this is a globally unique (OUI enforced) address.
        """
        return not self.isLocal()

    def isLocal (self):
        """
        Returns True if this is a locally-administered (non-global) address.
        """
        return True if (self.__value[0] & 2) else False

    @property
    def is_local (self):
        return self.isLocal()

    @property
    def is_global (self):
        return self.isGlobal()

    def isMulticast (self):
        """
        Returns True if this is a multicast address.
        """
        return True if (self.__value[0] & 1) else False

    @property
    def is_multicast (self):
        return self.isMulticast()

    def toRaw (self):
        return self.raw

    @property
    def raw (self):
        """
        Returns the address as a 6-long bytes object.
        """
        return self.__value

    @property
    def packed(self):
        return self.raw

    def toTuple (self):
        """
        Returns a 6-entry long tuple where each entry is the numeric value
        of the corresponding byte of the address.
        """
        return tuple(self.__value)

    def toStr (self, separator = ':'):
        """
        Returns the address as string consisting of 12 hex chars separated
        by separator.
        """
        return separator.join(('{:02x}'.format(x) for x in self.__value))

    def __str__ (self):
        return self.toStr()

    def __eq__(self, other):
        other = EthAddr(other)
        return self.raw == other.raw

    def __lt__(self, other):
        other = EthAddr(other)
        return self.raw < other.raw

    def __hash__ (self):
        return hash(self.__value)

    def __repr__ (self):
        return self.__class__.__name__ + "('" + self.toStr() + "')"

    def __len__ (self):
        return 6


ethaddr = EthAddr
macaddr = EthAddr


class SpecialIPv6Addr(Enum):
    UNDEFINED = ip_address('::')
    ALL_NODES_LINK_LOCAL = ip_address('ff02::1')
    ALL_ROUTERS_LINK_LOCAL = ip_address('ff02::2')
    ALL_NODES_INTERFACE_LOCAL = ip_address('ff01::1')
    ALL_ROUTERS_INTERFACE_LOCAL = ip_address('ff01::2')

#ff02::1:3 link local multicast name resolution
#ff02::1:ff00:0/104 solicited-node
#ff02::2:ff00:0/104 node information query


class SpecialIPv4Addr(Enum):
    IP_ANY = ip_address("0.0.0.0")
    IP_BROADCAST = ip_address("255.255.255.255")


class SpecialEthAddr(Enum):
    ETHER_ANY            = EthAddr(b'\x00\x00\x00\x00\x00\x00')
    ETHER_BROADCAST      = EthAddr(b'\xff\xff\xff\xff\xff\xff')
    BRIDGE_GROUP_ADDRESS = EthAddr(b'\x01\x80\xC2\x00\x00\x00')
    LLDP_MULTICAST       = EthAddr(b'\x01\x80\xc2\x00\x00\x0e')
    PAE_MULTICAST        = EthAddr(b'\x01\x80\xc2\x00\x00\x03') 
                                                   # 802.1x Port Access Entity
    NDP_MULTICAST        = EthAddr(b'\x01\x23\x20\x00\x00\x01') 
                                                   # Nicira discovery multicast
