__author__ = 'jsommers@colgate.edu'

from ipaddress import ip_address
from enum import Enum

# make aliases for built-in ip_address class
IPAddr = IPAddress = ip_address

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
  __slots__ = ['_value']

  def __init__ (self, addr):
    """
    Understands Ethernet address is various forms.  Hex strings, raw byte
    strings, etc.
    """
    # Always stores as a 6 character string
    if isinstance(addr, bytes) or isinstance(addr, basestring):
      if len(addr) == 6:
        # raw
        pass
      elif len(addr) == 17 or len(addr) == 12 or addr.count(':') == 5:
        # hex
        if len(addr) == 17:
          if addr[2::3] != ':::::' and addr[2::3] != '-----':
            raise RuntimeError("Bad format for ethernet address")
          # Address of form xx:xx:xx:xx:xx:xx
          # Pick out the hex digits only
          addr = ''.join((addr[x*3:x*3+2] for x in xrange(0,6)))
        elif len(addr) == 12:
          pass
        else:
          # Assume it's hex digits but they may not all be in two-digit
          # groupings (e.g., xx:x:x:xx:x:x). This actually comes up.
          addr = ''.join(["%02x" % (int(x,16),) for x in addr.split(":")])
        # We should now have 12 hex digits (xxxxxxxxxxxx).
        # Convert to 6 raw bytes.
        addr = b''.join((chr(int(addr[x*2:x*2+2], 16)) for x in range(0,6)))
      else:
        raise RuntimeError("Expected ethernet address string to be 6 raw "
                           "bytes or some hex")
      self._value = addr
    elif isinstance(addr, EthAddr):
      self._value = addr.toRaw()
    elif type(addr) == list or (hasattr(addr, '__len__') and len(addr) == 6
          and hasattr(addr, '__iter__')):
      self._value = b''.join( (chr(x) for x in addr) )
    elif addr is None:
      self._value = b'\x00' * 6
    else:
      raise RuntimeError("Expected ethernet address to be a string of 6 raw "
                         "bytes or some hex")

  def isBridgeFiltered (self):
    """
    Checks if address is an IEEE 802.1D MAC Bridge Filtered MAC Group Address

    This range is 01-80-C2-00-00-00 to 01-80-C2-00-00-0F. MAC frames that
    have a destination MAC address within this range are not relayed by
    bridges conforming to IEEE 802.1D
    """
    return  ((self._value[0] == 0x01)
    	and (self._value[1] == 0x80)
    	and (self._value[2] == 0xC2)
    	and (self._value[3] == 0x00)
    	and (self._value[4] == 0x00)
    	and (self._value[5] <= 0x0F))

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
    return True if (self._value[0] & 2) else False

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
    return True if (self._value[0] & 1) else False

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
    return self._value

  def toTuple (self):
    """
    Returns a 6-entry long tuple where each entry is the numeric value
    of the corresponding byte of the address.
    """
    return tuple(self._value)

  def toStr (self, separator = ':'):
    """
    Returns the address as string consisting of 12 hex chars separated
    by separator.
    """
    return separator.join(('{:02x}'.format(x) for x in self._value))

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    try:
      if isinstance(other, EthAddr):
        other = other._value
      elif isinstance(other, bytes):
        pass
      else:
        other = EthAddr(other)._value
      if self._value == other:
        return 0
      if self._value < other:
        return -1
      if self._value > other:
        return -1
      raise RuntimeError("Objects can not be compared?")
    except:
      return -other.__cmp__(self)

  def __hash__ (self):
    return self._value.__hash__()

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

class SpecialIPv4Addr(Enum):
    IP_ANY = ip_address("0.0.0.0")
    IP_BROADCAST = ip_address("255.255.255.255")

class SpecialEthAddr(Enum):
    ETHER_ANY            = EthAddr(b"\x00\x00\x00\x00\x00\x00")
    ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")
    BRIDGE_GROUP_ADDRESS = EthAddr(b"\x01\x80\xC2\x00\x00\x00")
    LLDP_MULTICAST       = EthAddr(b"\x01\x80\xc2\x00\x00\x0e")
    PAE_MULTICAST        = EthAddr(b'\x01\x80\xc2\x00\x00\x03') # 802.1x Port
                                                                #  Access Entity
    NDP_MULTICAST        = EthAddr(b'\x01\x23\x20\x00\x00\x01') # Nicira discovery
                                                                #  multicast

#ff02::1:3 link local multicast name resolution
#ff02::1:ff00:0/104 solicited-node
#ff02::2:ff00:0/104 node information query


def netmask_to_cidr (dq):
  """
  Takes a netmask as either an IPAddr or a string, and returns the number
  of network bits.  e.g., 255.255.255.0 -> 24
  Raise exception if subnet mask is not CIDR-compatible.
  """
  if isinstance(dq, str):
    dq = IPAddr(dq)
  v = int(dq)
  c = 0
  while v & 0x80000000:
    c += 1
    v <<= 1
  v = v & 0xffFFffFF
  if v != 0:
    raise RuntimeError("Netmask %s is not CIDR-compatible" % (dq,))
  return c


def cidr_to_netmask (bits):
  """
  Takes a number of network bits, and returns the corresponding netmask
  as an IPAddr.  e.g., 24 -> 255.255.255.0
  """
  v = (1 << bits) - 1
  v = v << (32-bits)
  return IPAddr(v)


def parse_cidr (addr, infer=True, allow_host=False):
  """
  Takes a CIDR address or plain dotted-quad, and returns a tuple of address
  and count-of-network-bits.
  Can infer the network bits based on network classes if infer=True.
  Can also take a string in the form 'address/netmask', as long as the
  netmask is representable in CIDR.

  FIXME: This function is badly named.
  """
  def check (r0, r1):
    a = int(r0)
    b = r1
    if (not allow_host) and (a & ((1<<b)-1)):
      raise RuntimeError("Host part of CIDR address is not zero (%s)"
                         % (addr,))
    return (r0,32-r1)
  addr = addr.split('/', 2)
  if len(addr) == 1:
    if infer is False:
      return check(IPAddr(addr[0]), 0)
    addr = IPAddr(addr[0])
    b = 32-infer_netmask(addr)
    m = (1<<b)-1
    if (int(addr) & m) == 0:
      # All bits in wildcarded part are 0, so we'll use the wildcard
      return check(addr, b)
    else:
      # Some bits in the wildcarded part are set, so we'll assume it's a host
      return check(addr, 0)
  try:
    wild = 32-int(addr[1])
  except:
    # Maybe they passed a netmask
    m = int(IPAddr(addr[1]))
    b = 0
    while m & (1<<31):
      b += 1
      m <<= 1
    if m & 0x7fffffff != 0:
      raise RuntimeError("Netmask " + str(addr[1]) + " is not CIDR-compatible")
    wild = 32-b
    assert wild >= 0 and wild <= 32
    return check(IPAddr(addr[0]), wild)
  assert wild >= 0 and wild <= 32
  return check(IPAddr(addr[0]), wild)


def infer_netmask (addr):
  """
  Uses network classes to guess the number of network bits
  """
  addr = int(addr)
  if addr == 0:
    # Special case -- default network
    return 32-32 # all bits wildcarded
  if (addr & (1 << 31)) == 0:
    # Class A
    return 32-24
  if (addr & (3 << 30)) == 2 << 30:
    # Class B
    return 32-16
  if (addr & (7 << 29)) == 6 << 29:
    # Class C
    return 32-8
  if (addr & (15 << 28)) == 14 << 28:
    # Class D (Multicast)
    return 32-0 # exact match
  # Must be a Class E (Experimental)
    return 32-0

if __name__ == '__main__':
    assert (infer_netmask(IPAddr("10.0.0.1")) == 8)
    assert (infer_netmask(IPAddr("192.168.1.24")) == 24)
    assert (str(cidr_to_netmask(24)) == "255.255.255.0")
    print (parse_cidr("149.43.80.25/22", allow_host=True))
    assert (netmask_to_cidr("255.255.0.0") == 16)
    print (list(SpecialIPv6Addr))
    print (list(SpecialIPv4Addr))
    print (list(SpecialEthAddr))
