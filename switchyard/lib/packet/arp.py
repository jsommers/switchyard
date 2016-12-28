from .packet import PacketHeaderBase,Packet
from ..address import EthAddr,IPAddr,SpecialIPv4Addr,SpecialEthAddr
import struct
from .common import EtherType, ArpHwType, ArpOperation
from ..exceptions import *

'''
References:
    Plummer. 
        "RFC826", An Ethernet Address Resolution Protocol.
    Finlayson, Mann, Mogul, and Theimer. 
        "RFC903", A Reverse Address Resolution Protocol.
    http://en.wikipedia.org/wiki/Address_Resolution_Protocol
'''

class Arp(PacketHeaderBase):
    __slots__ = ['_hwtype','_prototype','_hwaddrlen','_protoaddrlen',
                 '_operation','_senderhwaddr','_senderprotoaddr',
                 '_targethwaddr','_targetprotoaddr']
    _PACKFMT = '!HHBBH6s4s6s4s'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._hwtype = ArpHwType.Ethernet
        self._prototype = EtherType.IP
        self._hwaddrlen = 6
        self._protoaddrlen = 4
        self.operation = ArpOperation.Request
        self.senderhwaddr = SpecialEthAddr.ETHER_ANY.value
        self.senderprotoaddr = SpecialIPv4Addr.IP_ANY.value
        self.targethwaddr = SpecialEthAddr.ETHER_BROADCAST.value
        self.targetprotoaddr = SpecialIPv4Addr.IP_ANY.value
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(Arp._PACKFMT)

    def pre_serialize(self, raw, pkt, i):
        pass

    def to_bytes(self):
        '''
        Return packed byte representation of the ARP header.
        '''
        return struct.pack(Arp._PACKFMT, self._hwtype.value, self._prototype.value, self._hwaddrlen, self._protoaddrlen, self._operation.value, self._senderhwaddr.packed, self._senderprotoaddr.packed, self._targethwaddr.packed, self._targetprotoaddr.packed)

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < Arp._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct an Arp object".format(len(raw)))
        fields = struct.unpack(Arp._PACKFMT, raw[:Arp._MINLEN])
        try:
            self._hwtype = ArpHwType(fields[0])
            self._prototype = EtherType(fields[1])
            self._hwaddrlen = fields[2]
            self._protoaddrlen = fields[3]
            self.operation = ArpOperation(fields[4])
            self.senderhwaddr = EthAddr(fields[5])
            self.senderprotoaddr = IPAddr(fields[6])
            self.targethwaddr = EthAddr(fields[7])
            self.targetprotoaddr = IPAddr(fields[8])
        except Exception as e:
            raise Exception("Error constructing Arp packet object from raw bytes: {}".format(str(e)))
        return raw[Arp._MINLEN:]

    def __eq__(self, other):
        return self.hardwaretype == other.hardwaretype and \
               self.protocoltype == other.protocoltype and \
               self.operation == other.operation and \
               self.senderhwaddr == other.senderhwaddr and \
               self.senderprotoaddr == other.senderprotoaddr and \
               self.targethwaddr == other.targethwaddr and \
               self.targetprotoaddr == other.targetprotoaddr 

    @property
    def hardwaretype(self):
        return self._hwtype

    @property
    def protocoltype(self):
        return self._prototype

    @property
    def operation(self):
        return self._operation

    @operation.setter
    def operation(self, value):
        self._operation = ArpOperation(value)

    @property
    def senderhwaddr(self):
        return self._senderhwaddr

    @senderhwaddr.setter
    def senderhwaddr(self, value):
        self._senderhwaddr = EthAddr(value)

    @property
    def senderprotoaddr(self):
        return self._senderprotoaddr

    @senderprotoaddr.setter
    def senderprotoaddr(self, value):
        self._senderprotoaddr = IPAddr(value)

    @property
    def targethwaddr(self):
        return self._targethwaddr

    @targethwaddr.setter
    def targethwaddr(self, value):
        self._targethwaddr = EthAddr(value)

    @property
    def targetprotoaddr(self):
        return self._targetprotoaddr

    @targetprotoaddr.setter
    def targetprotoaddr(self, value):
        self._targetprotoaddr = IPAddr(value)

    def next_header_class(self):
        '''
        No other headers should follow ARP.
        '''
        return None

    def __str__(self):
        return '{} {}:{} {}:{}'.format(self.__class__.__name__, 
            self.senderhwaddr, self.senderprotoaddr,
            self.targethwaddr, self.targetprotoaddr)
