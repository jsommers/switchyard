import struct
from enum import IntEnum
from ipaddress import IPv4Network

from .packet import PacketHeaderBase,Packet,RawPacketContents
from ..address import SpecialIPv4Addr, IPv4Address
from ..logging import log_warn
from ..exceptions import *

'''
References:
    IETF RFC 2453
'''

class RIPCommand(IntEnum):
    Request = 1
    Reply = 2

class RIPRouteEntry(object):
    __slots__ = ('_family','_tag','_addr','_nexthop','_metric')
    _PACKFMT = '!HHIIII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, address=SpecialIPv4Addr.IP_ANY.value, mask='255.255.255.255', nexthop='255.255.255.255', metric=16, tag=0):
        self._family = 2
        self._tag = tag
        self._addr = IPv4Network("{}/{}".format(address,mask), strict=False)
        self._nexthop = IPv4Address(nexthop)
        self._metric = int(metric)

    @staticmethod
    def size():
        return RIPRouteEntry._MINLEN

    def __str__(self):
        return "{} -> {} {}".format(self._addr, self._nexthop, self._metric)

    def to_bytes(self):
        return struct.pack(RIPRouteEntry._PACKFMT, self._family, self.tag,
                           int(self._addr.network_address), int(self._addr.netmask), int(self.nexthop),
                           self.metric)

    @staticmethod
    def from_bytes(raw):
        if len(raw) != RIPRouteEntry._MINLEN:
            raise NotEnoughDataError("Wrong number of bytes to reconstruct RIP Route Entry")
        fields = struct.unpack(RIPRouteEntry._PACKFMT, raw)            
        entry = RIPRouteEntry()
        entry._family = int(fields[0])
        entry._tag = int(fields[1])
        xaddr = IPv4Address(fields[2]) 
        xmask = IPv4Address(fields[3]) 
        entry._addr = IPv4Network("{}/{}".format(str(xaddr), str(xmask)), strict=False)
        entry._nexthop = IPv4Address(fields[4])
        entry._metric = int(fields[5])
        return entry

    @property 
    def tag(self):
        return self._tag

    @property 
    def address(self):
        return self._addr.network_address

    @property 
    def netmask(self):
        return self._addr.netmask

    @property 
    def nexthop(self):
        return self._nexthop

    @property 
    def metric(self):
        return self._metric

    def __eq__(self, other):
        return isinstance(other, RIPRouteEntry) and \
            self.to_bytes() == other.to_bytes()


class RIPv2(PacketHeaderBase):
    __slots__ = ('_command','_domain','_routes')
    _PACKFMT = '!BBH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, raw=None, **kwargs):
        self.command = RIPCommand.Request
        self.domain = 0
        self._routes = []
        if raw:
            self.from_bytes(raw)
        super().__init__(**kwargs)

    def size(self):
        return len(self.to_bytes())

    def to_bytes(self):
        '''
        Return packed byte representation of the UDP header.
        '''
        hdr = struct.pack(RIPv2._PACKFMT, self.command.value, self.version, self.domain)
        routes = b''.join([r.to_bytes() for r in self._routes])
        return hdr + routes

    def from_bytes(self, raw):
        if isinstance(raw, RawPacketContents):
            raw = raw.to_bytes()
        if len(raw) < RIPv2._MINLEN:
            raise NotEnoughDataError("Not enough bytes to reconstruct RIPv2 header")
        fields = struct.unpack(RIPv2._PACKFMT, raw[:RIPv2._MINLEN])
        self.command = fields[0]
        self.domain = fields[2]
        remain = raw[RIPv2._MINLEN:]
        esize = RIPRouteEntry.size()
        numroutes = len(remain) // esize
        extra = len(remain) % esize
        if extra > 0:
            log_warn("RIPv2 payload isn't of expected size (i.e., an integral number of route entries).  Continuing anyway.")
        for i in range(numroutes):
            self._routes.append(RIPRouteEntry.from_bytes(remain[(i*esize):((i+1)*esize)]))

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        rdata = ' ({} routes: {})'.format(len(self._routes), ', '.join([str(r) for r in self._routes]))
        if self.command == RIPCommand.Request:
            rdata = ''
        return "{} {}{}".format(self.__class__.__name__, self.command.name, rdata)

    def __len__(self):
        return len(self._routes)

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("Indexing in RIPv2 requires an int")
        if index < 0:
            index = len(self._routes) + index
        if not 0 <= index < len(self._routes):
            raise IndexError("Bad index in RIPv2 route entry access")
        return self._routes[index]

    def __setitem__(self, index, routeentry):
        if not isinstance(routeentry, RIPRouteEntry):
            raise ValueError("Value must be an RIPRouteEntry object")
        if index < 0:
            index = len(self._routes) + index
        if not 0 <= index < len(self._routes):
            raise IndexError("Index out of range")
        self._routes[index] = routeentry

    def append(self, routeentry):
        if not isinstance(routeentry, RIPRouteEntry):
            raise ValueError("Value must be an RIPRouteEntry object")
        self._routes.append(routeentry)

    @property 
    def command(self):
        return self._command

    @command.setter 
    def command(self, value):
        self._command = RIPCommand(value)

    @property
    def version(self):
        return 2

    @property 
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, value):
        self._domain = int(value)

    def next_header_class(self):
        return None

    def pre_serialize(self, raw, pkt, i):
        pass
