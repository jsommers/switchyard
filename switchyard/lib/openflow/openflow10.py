from enum import IntEnum
import struct
from math import ceil
from ipaddress import ip_network, ip_address

from ..packet import PacketHeaderBase, Packet, IPProtocol, \
    EtherType, Ethernet, Vlan, IPv6, IPv4, ICMP, ICMPv6, TCP, UDP, Arp
from ..address import EthAddr, IPv4Address
from ..logging import log_debug

def _make_bitmap(xset):
    '''
    Given a set of enumerated values, build an integer (32 bit)
    bitmap of the enum values.
    '''
    val = 0x00000000
    for enumval in xset:
        val |= enumval.value
    return val

def _unpack_bitmap(bitmap, xenum):
    '''
    Given an integer bitmap and an enumerated type, build
    a set that includes zero or more enumerated type values
    corresponding to the bitmap.
    '''
    unpacked = set()
    for enval in xenum:
        if enval.value & bitmap == enval.value:
            unpacked.add(enval)
    return unpacked


class OpenflowType(IntEnum):
    Hello = 0
    Error = 1
    EchoRequest = 2
    EchoReply = 3
    Vendor = 4
    FeaturesRequest = 5
    FeaturesReply = 6
    GetConfigRequest = 7
    GetConfigReply = 8
    SetConfig = 9
    PacketIn = 10
    FlowRemoved = 11
    PortStatus = 12
    PacketOut = 13
    FlowMod = 14
    PortMod = 15
    StatsRequest = 16
    StatsReply = 17
    BarrierRequest = 18
    BarrierReply = 19
    QueueGetConfigRequest = 20
    QueueGetConfigReply = 21


class OpenflowPort(IntEnum):
    Max = 0xff00
    InPort = 0xfff8
    Table = 0xfff9
    Normal = 0xfffa
    Flood = 0xfffb
    All = 0xfffc
    Controller = 0xfffd
    Local = 0xfffe
    NoPort = 0xffff  # Can't use None!


def _get_port(value):
    value = int(value)
    try:
        value = OpenflowPort(value)
        return value
    except ValueError:
        if 0 <= value < OpenflowPort.Max:
            return value
        else:
            raise ValueError("Invalid port number")        


class OpenflowPortState(IntEnum):
    NoState = 0
    LinkDown = 1 << 0
    StpListen = 0 << 8
    StpLearn = 1 << 8
    StpForward = 2 << 8
    StpBlock = 3 << 8
    StpMask = 3 << 8


class OpenflowPortConfig(IntEnum):
    NoConfig = 0
    Down = 1 << 0
    NoStp = 1 << 1
    NoRecv = 1 << 2
    NoRecvStp = 1 << 3
    NoFlood = 1 << 4
    NoFwd = 1 << 5
    NoPacketIn = 1 << 6


class OpenflowPortFeatures(IntEnum):
    NoFeatures = 0
    e10Mb_Half = 1 << 0
    e10Mb_Full = 1 << 1
    e100Mb_Half = 1 << 2
    e100Mb_Full = 1 << 3
    e1Gb_Half = 1 << 4
    e1Gb_Full = 1 << 5
    e10Gb_Full = 1 << 6
    Copper = 1 << 7
    Fiber = 1 << 8
    AutoNeg = 1 << 9
    Pause = 1 << 10
    PauseAsym = 1 << 11


class OpenflowCapabilities(IntEnum):
    NoCapabilities = 0
    FlowStats = 1 << 0
    TableStats = 1 << 1
    PortStats = 1 << 2
    Stp = 1 << 3
    Reserved = 1 << 4
    IpReasm = 1 << 5
    QueueStats = 1 << 6
    ArpMatchIp = 1 << 7


class OpenflowStruct(PacketHeaderBase):

    def __init__(self, **kwargs):
        PacketHeaderBase.__init__(self, **kwargs)

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def next_header_class(self):
        pass

    def pre_serialize(self, *args):
        pass


class OpenflowPhysicalPort(OpenflowStruct):
    __slots__ = ['_portnum', '_hwaddr', '_name', '_config',
                 '_state', '_curr', '_advertised', '_supported', '_peer']
    _PACKFMT = '!H6s16sIIIIII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, portnum=0, hwaddr='', name=''):
        OpenflowStruct.__init__(self)
        self._portnum = portnum
        if hwaddr:
            self._hwaddr = EthAddr(hwaddr)
        else:
            self._hwaddr = EthAddr()
        self._name = name
        self._config = set()
        self._state = set()
        self._curr = set()
        self._advertised = set()
        self._supported = set()
        self._peer = set()

    def to_bytes(self):
        return struct.pack(OpenflowPhysicalPort._PACKFMT,
                           self._portnum, self._hwaddr.raw, self._name.encode(
                               'utf8'),
                           _make_bitmap(self._config), _make_bitmap(self._state), 
                           _make_bitmap(self._curr), _make_bitmap(self._advertised),
                           _make_bitmap(self._supported), _make_bitmap(self._peer))

    def from_bytes(self, raw):
        if len(raw) < OpenflowPhysicalPort._MINLEN:
            raise Exception(
                "Not enough raw data to unpack OpenflowPhysicalPort object")
        fields = struct.unpack(
            OpenflowPhysicalPort._PACKFMT, raw[:OpenflowPhysicalPort._MINLEN])
        self.portnum = fields[0]
        self.hwaddr = fields[1]
        self.name = fields[2].decode('utf8')

        self._config = _unpack_bitmap(fields[3], OpenflowPortConfig)
        self._state = _unpack_bitmap(fields[4], OpenflowPortState)
        self._curr = _unpack_bitmap(fields[5], OpenflowPortFeatures)
        self._advertised = _unpack_bitmap(fields[6], OpenflowPortFeatures)
        self._supported = _unpack_bitmap(fields[7], OpenflowPortFeatures)
        self._peer = _unpack_bitmap(fields[8], OpenflowPortFeatures)

        return raw[OpenflowPhysicalPort._MINLEN:]

    def size(self):
        return OpenflowPhysicalPort._MINLEN

    @property
    def portnum(self):
        return self._portnum

    @portnum.setter
    def portnum(self, value):
        self._portnum = int(value)

    @property
    def hwaddr(self):
        return self._hwaddr

    @hwaddr.setter
    def hwaddr(self, value):
        self._hwaddr = EthAddr(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)
        if len(value) > 16:
            raise ValueError("Name can't be longer than 16 characters")

    @property
    def config(self):
        return _make_bitmap(self._config)

    def get_config(self):
        return self._config

    def add_config(self, value):
        self._config.add(OpenflowPortConfig(value))

    def clear_config(self):
        self._config.clear()

    @property
    def state(self):
        return _make_bitmap(self._state)

    def get_state(self):
        return self._state

    def add_state(self, value):
        self._state.add(OpenflowPortState(value))

    def clear_state(self):
        self._state.clear()

    @property
    def curr(self):
        return _make_bitmap(self._curr)

    def get_curr(self):
        return self._curr

    def add_curr(self, value):
        self._curr.add(OpenflowPortFeatures(value))

    def clear_curr(self):
        self._curr.clear()

    @property
    def advertised(self):
        return _make_bitmap(self._advertised)

    def get_advertised(self):
        return self._advertised

    def add_advertised(self, value):
        self._advertised.add(OpenflowPortFeatures(value))

    def clear_advertised(self):
        self._advertised.clear()

    @property
    def supported(self):
        return _make_bitmap(self._supported)

    def get_supported(self):
        return self._supported

    def add_supported(self, value):
        self._supported.add(OpenflowPortFeatures(value))

    def clear_supported(self):
        self._supported.clear()

    @property
    def peer(self):
        return _make_bitmap(self._peer)

    def get_peer(self):
        return self._peer

    def add_peer(self, value):
        self._peer.add(OpenflowPortFeatures(value))

    def clear_peer(self):
        self._peer.clear()


class OpenflowQueuePropertyTypes(IntEnum):
    NoProperty = 0
    MinRate = 1


class OpenflowQueueMinRateProperty(OpenflowStruct):
    __slots__ = ['_rate']
    _PACKFMT = '!HH4xH6x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, rate=0):
        self._rate = int(rate)

    @property
    def rate(self):
        return self._rate

    @rate.setter
    def rate(self, value):
        self._rate = int(value)
    
    def size(self):
        return OpenflowQueueMinRateProperty._MINLEN

    def to_bytes(self):
        return struct.pack(OpenflowQueueMinRateProperty._PACKFMT,
            OpenflowQueuePropertyTypes.MinRate.value, OpenflowQueueMinRateProperty._MINLEN,
            self._rate)

    def from_bytes(self, raw):
        if len(raw) < OpenflowQueueMinRateProperty._MINLEN:
            raise Exception("Not enough data to unpack OpenflowQueueMinRateProperty")
        fields = struct.unpack(OpenflowQueueMinRateProperty._PACKFMT, 
            raw[:OpenflowQueueMinRateProperty._MINLEN])
        assert(fields[0] == OpenflowQueuePropertyTypes.MinRate.value)
        assert(fields[1] == OpenflowQueueMinRateProperty._MINLEN)
        self.rate = fields[2]


_QueuePropertyTypeClassMap = {
    OpenflowQueuePropertyTypes.MinRate: OpenflowQueueMinRateProperty,
}


class OpenflowPacketQueue(OpenflowStruct):
    __slots__ = ['_queue_id', '_properties']
    _PACKFMT = '!IHxx'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, queue_id=0):
        OpenflowStruct.__init__(self)
        self._queue_id = queue_id
        self._properties = []

    @property
    def queue_id(self):
        return self._queue_id

    @queue_id.setter
    def queue_id(self, value):
        self._queue_id = int(value)

    @property
    def properties(self):
        return self._properties

    def size(self):
        return len(self.to_bytes())        

    def to_bytes(self):
        rawprops = b''.join(p.to_bytes() for p in self._properties)
        return struct.pack(OpenflowPacketQueue._PACKFMT, self._queue_id,
            len(rawprops) + OpenflowPacketQueue._MINLEN) + rawprops

    def from_bytes(self, raw):
        if len(raw) < OpenflowPacketQueue._MINLEN:
            raise Exception("Not enough data to unpack OpenflowPacketQueue")
        fields = struct.unpack(OpenflowPacketQueue._PACKFMT, raw[:OpenflowPacketQueue._MINLEN])
        self.queue_id = fields[0]
        raw = raw[OpenflowPacketQueue._MINLEN:]
        self._properties = []
        while len(raw) > 0:
            prop, proplen = struct.unpack('!HH', raw[:4])
            prop = OpenflowQueuePropertyTypes(prop)
            propobj = _QueuePropertyTypeClassMap.get(prop)()
            propobj.from_bytes(raw[:proplen])
            self._properties.append(propobj)
            raw = raw[proplen:]


class OpenflowMatch(OpenflowStruct):
    __slots__ = ['_wildcards', '_nw_src_wildcard', '_nw_dst_wildcard',
                 '_in_port', '_dl_src', '_dl_dst',
                 '_dl_vlan', '_dl_vlan_pcp', '_dl_type',
                 '_nw_tos', '_nw_proto', '_nw_src', '_nw_dst',
                 '_tp_src', '_tp_dst']
    _PACKFMT = '!IH6s6sHBxHBB2x4s4sHH'
    _MINLEN = struct.calcsize(_PACKFMT)

    _match_field_to_packet = {
        'dl_src': ((Ethernet, 'src'),),
        'dl_dst': ((Ethernet, 'dst'),),
        'dl_vlan': ((Vlan, 'vlan'),),
        'dl_vlan_pcp': ((Vlan, 'pcp'),),
        'dl_type': ((Vlan, 'ethertype'), (Ethernet, 'ethertype')),
        'nw_proto': ((IPv4, 'protocol'),(IPv6, 'protocol'), (Arp, 'protocoltype')),
        'nw_tos': ((IPv4, 'tos'), (IPv6, 'trafficclass')),
        'nw_src': ((IPv4, 'src'), (IPv6, 'src'), (Arp, 'senderprotoaddr')),
        'nw_dst': ((IPv4, 'dst'), (IPv6, 'dst'), (Arp, 'targetprotoaddr')),
        'tp_src': ((TCP, 'src'), (UDP, 'src'), (ICMP, 'icmptype'), (ICMPv6, 'icmptype')),
        'tp_dst': ((TCP, 'dst'), (TCP, 'dst'), (ICMP, 'icmpcode'), (ICMPv6, 'icmpcode')),
    }

    def __init__(self, **kwargs):
        self._wildcards = set()
        self._in_port = 0
        self._dl_src = EthAddr()
        self._dl_dst = EthAddr()
        self._dl_vlan = 0
        self._dl_vlan_pcp = 0
        self._dl_type = EtherType.IP
        self._nw_tos = 0
        self._nw_proto = IPProtocol.ICMP
        self._nw_src_wildcard = 0
        self._nw_dst_wildcard = 0
        self._nw_src = IPv4Address(0)
        self._nw_dst = IPv4Address(0)
        self._tp_src = 0
        self._tp_dst = 0
        OpenflowStruct.__init__(self, **kwargs)

    @staticmethod
    def size(*args):
        return OpenflowMatch._MINLEN

    def to_bytes(self):
        wildbits = _make_bitmap(self._wildcards)
        return struct.pack(OpenflowMatch._PACKFMT,
                           wildbits, self.in_port,  self.dl_src.raw, self.dl_dst.raw,
                           self.dl_vlan, self.dl_vlan_pcp, self.dl_type.value,
                           self.nw_tos, self.nw_proto.value, self.nw_src.packed,
                           self.nw_dst.packed, self.tp_src, self.tp_dst)

    def from_bytes(self, raw):
        if len(raw) < OpenflowMatch._MINLEN:
            raise Exception("Not enough data to unpack OpenflowMatch")
        fields = struct.unpack(
            OpenflowMatch._PACKFMT, raw[:OpenflowMatch._MINLEN])
        self._wildcards = set()
        if fields[0] == OpenflowWildcard.All.value:
            self.wildcard_all()
            self.nwsrc_wildcard = 32
            self.nwdst_wildcard = 32
        else:
            for v in OpenflowWildcard:
                if not v.name.endswith('All') and \
                   not v.name.endswith('Mask') and \
                   v.value & fields[0] == v.value:
                    self.add_wildcard(v)

            # set nw_src_wildcard, nwdst_wildcard
            nwsrcbits = (fields[0] & OpenflowWildcard.NwSrcMask.value) >> 8
            self.nwsrc_wildcard = nwsrcbits
            nwdstbits = (fields[0] & OpenflowWildcard.NwDstMask.value) >> 14
            self.nwdst_wildcard = nwdstbits

        self.in_port = fields[1]
        self.dl_src = fields[2]
        self.dl_dst = fields[3]
        self.dl_vlan = fields[4]
        self.dl_vlan_pcp = fields[5]
        self.dl_type = fields[6]
        self.nw_tos = fields[7]
        self.nw_proto = fields[8]
        self.nw_src = fields[9]
        self.nw_dst = fields[10]
        self.tp_src = fields[11]
        self.tp_dst = fields[12]
        return raw[OpenflowMatch._MINLEN:]

    def __str__(self):
        wildbits = _make_bitmap(self._wildcards)
        return "{} {:08x} {} {}/{} ({} {}) {} {} {} {}/{}:{}/{} {}:{}".format(
            self.__class__.__name__, wildbits,
            self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, 
            self.dl_vlan_pcp, self.dl_type.name, self.nw_tos,
            self.nw_proto.name, self.nw_src, self.nwsrc_wildcard, 
            self.nw_dst, self.nwdst_wildcard, self.tp_src, self.tp_dst)

    def overlaps_with(self, othermatch, strict=False):
        '''
        Two match objects overlap if the same packet can be matched 
        by both *and* they have the same priority.
        '''
        one = self.matches_entry(othermatch, strict)
        if strict:
            return one
        return one and othermatch.matches_entry(self, strict) 

    def matches_entry(self, othermatch, strict=False):
        '''
        Return True if this match object matches another
        match object (e.g., a flow table entry).

        NB: from OF 1.0 spec:
        A match occurs "when a flow entry exactly matches
        or is more specific than one" [in a flow_mod command]
        (likely to be self in this case).
        '''
        if strict:
            return self == othermatch

        attrs = set(self.__slots__)
        attrs.discard('_wildcards')
        attrs.discard('_nw_src_wildcard')
        attrs.discard('_nw_dst_wildcard')
        matchtest = []
        for a in attrs:
            curr = getattr(self, a)
            other = getattr(othermatch, a)

            if a == '_nw_src' or a == '_nw_dst':
                # FIXME: clean this up
                wattr = "{}_wildcard".format(a)
                otherbits = 32 - getattr(othermatch, wattr)
                othernet = ip_network("{}/{}".format(getattr(othermatch, a), otherbits), strict=False)
                iswildcarded = curr in othernet
            else:
                wc = _wildcard_attr_map[a].name
                iswildcarded = wc in othermatch.wildcards

            matchtest.append(iswildcarded or curr == other)
        return all(matchtest)

    def matches_packet(self, pkt):
        '''
        Return True if the given packet matches this match object.
        '''
        match = []
        wildbits = _make_bitmap(self._wildcards)
        for mf,pkttuple in OpenflowMatch._match_field_to_packet.items():
            mf = "_{}".format(mf)

            # if the attribute is a network address, respect the bits
            if mf == '_nw_src' or mf == '_nw_dst':
                # FIXME: clean me up.  lots of dup w/above and below :(
                wattr = "{}_wildcard".format(mf)
                bits = 32 - getattr(self, wattr)
                if bits < 32:
                    netaddr = ip_network("{}/{}".format(getattr(self, mf), bits), strict=False)
                    for pktcls,field in pkttuple: 
                        if pkt.has_header(pktcls):
                            match.append(getattr(pkt[pktcls], field) in netaddr)
                    continue

            # if attribute is simple wildcard, just ignore the attr
            elif _wildcard_attr_map[mf].value & wildbits:
                continue

            # compare concrete values in packet with match object value
            for pktcls,field in pkttuple:
                if pkt.has_header(pktcls):
                    match.append(getattr(pkt[pktcls], field) == getattr(self, mf))
        return all(match)

    @staticmethod
    def build_from_packet(pkt):
        '''
        Build and return a new OpenflowMatch object based on the
        packet object passed as a parameter.
        '''
        m = OpenflowMatch()
        for mf,pkttuple in OpenflowMatch._match_field_to_packet.items():
            for pktcls,field in pkttuple:
                if pkt.has_header(pktcls):
                    setattr(m, mf, getattr(pkt[pktcls], field))
                    continue
        return m

    @property
    def wildcards(self):
        wcards = []
        wcards.append("NwSrc:{}".format(self.nwsrc_wildcard))
        wcards.append("NwDst:{}".format(self.nwdst_wildcard))
        wcards.extend([w.name for w in self._wildcards])
        return wcards

    def add_wildcard(self, value):
        value = OpenflowWildcard(value)
        self._wildcards.add(value)

    def reset_wildcards(self):
        self._wildcards = set()
        self.nwdst_wildcard = 0
        self.nwsrc_wildcard = 0

    def remove_wildcard(self, value):
        self._wildcards.discard(value)

    def wildcard_all(self):
        self._wildcards = set([OpenflowWildcard.All])
        self.nwsrc_wildcard = 32
        self.nwdst_wildcard = 32

    @property
    def nwsrc_wildcard(self):
        return self._nw_src_wildcard

    @nwsrc_wildcard.setter
    def nwsrc_wildcard(self, value):
        value = max(0, int(value))
        value = min(32, value)
        self._nw_src_wildcard = value

    @property
    def nwdst_wildcard(self):
        return self._nw_src_wildcard

    @nwdst_wildcard.setter
    def nwdst_wildcard(self, value):
        value = max(0, int(value))
        value = min(32, value)
        self._nw_dst_wildcard = value

    @property
    def in_port(self):
        return self._in_port

    @in_port.setter
    def in_port(self, value):
        if int(value) < 0:
            raise ValueError("Can't set a negative port value")
        self._in_port = int(value)

    @property
    def dl_src(self):
        return self._dl_src

    @dl_src.setter
    def dl_src(self, value):
        self._dl_src = EthAddr(value)

    @property
    def dl_dst(self):
        return self._dl_dst

    @dl_dst.setter
    def dl_dst(self, value):
        self._dl_dst = EthAddr(value)

    @property
    def dl_vlan(self):
        return self._dl_vlan

    @dl_vlan.setter
    def dl_vlan(self, value):
        self._dl_vlan = int(value)

    @property
    def dl_vlan_pcp(self):
        return self._dl_vlan_pcp

    @dl_vlan_pcp.setter
    def dl_vlan_pcp(self, value):
        self._dl_vlan_pcp = int(value)

    @property
    def dl_type(self):
        return self._dl_type

    @dl_type.setter
    def dl_type(self, value):
        if isinstance(value, int) and value == 0:
            value = EtherType.NoType
        self._dl_type = EtherType(value)

    @property
    def nw_tos(self):
        return self._nw_tos

    @nw_tos.setter
    def nw_tos(self, value):
        value = int(value)
        if value < 0 or value > 255:
            raise ValueError("Invalid TOS value {}".format(value))
        self._nw_tos = value

    @property
    def nw_proto(self):
        return self._nw_proto

    @nw_proto.setter
    def nw_proto(self, value):
        self._nw_proto = IPProtocol(value)

    @property
    def nw_src(self):
        return self._nw_src

    @nw_src.setter
    def nw_src(self, value):
        self._nw_src = IPv4Address(value)

    @property
    def nw_dst(self):
        return self._nw_dst

    @nw_dst.setter
    def nw_dst(self, value):
        self._nw_dst = ip_address(value)

    @property
    def tp_src(self):
        return self._tp_src

    @tp_src.setter
    def tp_src(self, value):
        value = int(value)
        if value < 0 or value >= 2 ** 16:
            raise ValueError("Invalid transport layer src {}".format(value))
        self._tp_src = value

    @property
    def tp_dst(self):
        return self._tp_dst

    @tp_dst.setter
    def tp_dst(self, value):
        value = int(value)
        if value < 0 or value >= 2 ** 16:
            raise ValueError("Invalid transport layer dst {}".format(value))
        self._tp_dst = value


class OpenflowWildcard(IntEnum):
    InPort = 1 << 0
    DlVlan = 1 << 1
    DlSrc = 1 << 2
    DlDst = 1 << 3
    DlType = 1 << 4
    NwProto = 1 << 5
    TpSrc = 1 << 6
    TpDst = 1 << 7

    # wildcard bit count
    # 0 = exact match, 1 = ignore lsb
    # 2 = ignore 2 least sig bits, etc.
    # >= 32 = wildcard entire field
    NwSrcMask = ((1 << 6) - 1) << 8
    NwDstMask = ((1 << 6) - 1) << 14
    DlVlanPcp = 1 << 20
    NwTos = 1 << 21

    NwSrcAll = 32 << 8
    NwDstAll = 32 << 14
    All = ((1 << 22) - 1)


def _make_wildcard_attr_map():
    '''
    Create a dictionary that maps an attribute name
    in OpenflowMatch with a non-prefix-related wildcard
    bit from the above OpenflowWildcard enumeration.
    '''
    _xmap = {}
    for wc in OpenflowWildcard:
        if not wc.name.endswith('All') and \
            not wc.name.endswith('Mask'):
            translated = ''
            for ch in wc.name:
                if ch.isupper():
                    translated += '_' 
                    translated += ch.lower()
                else:
                    translated += ch
            _xmap[translated] = wc
    return _xmap
_wildcard_attr_map = _make_wildcard_attr_map()


class OpenflowActionType(IntEnum):
    Output = 0
    SetVlanVid = 1
    SetVlanPcp = 2
    StripVlan = 3
    SetDlSrc = 4
    SetDlDst = 5
    SetNwSrc = 6
    SetNwDst = 7
    SetNwTos = 8
    SetTpSrc = 9
    SetTpDst = 10
    Enqueue = 11
    Vendor = 0xffff


class OpenflowAction(OpenflowStruct):
    __slots__ = ['_type','_len']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        super().__init__()
        self._len = OpenflowAction._MINLEN
        self._type = OpenflowActionType.Output

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = OpenflowActionType(value)

    @property
    def len(self):
        return self._len

    @len.setter
    def len(self, value):
        self._len = int(value)    

    def from_bytes(self, raw):
        self.type, self.len = struct.unpack(OpenflowAction._PACKFMT, 
            raw[:OpenflowAction._MINLEN]) 
        return raw[OpenflowAction._MINLEN:]

    def to_bytes(self):
        return struct.pack(OpenflowAction._PACKFMT, self._type.value, 
                           self._len)

    def size(self):
        return self._len


class ActionStripVlan(OpenflowAction):
    def __init__(self):
        super().__init__()
        self._type = OpenflowActionType.StripVlan

    def __call__(self, **kwargs):
        packet = kwargs['packet']
        Exception("Not implemented")


class ActionOutput(OpenflowAction):
    __slots__ = ['_port', '_maxlen']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, port=OpenflowPort.NoPort):
        super().__init__()
        self._type = OpenflowActionType.Output
        self._port = int(port)
        self._maxlen = 1500
        self.len = super()._MINLEN + ActionOutput._MINLEN

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = int(value)    

    @property
    def maxlen(self):
        return self._maxlen

    @maxlen.setter
    def maxlen(self, value):
        self._maxlen = int(value)

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        self.port, self.maxlen = struct.unpack(ActionOutput._PACKFMT, raw[:ActionOutput._MINLEN])

    def to_bytes(self):
        return super().to_bytes() + \
            struct.pack(ActionOutput._PACKFMT, self._port, self._maxlen)

    def __call__(self, **kwargs):
        net = kwargs['net']
        packet = kwargs['packet']
        controllers = kwargs['controllers']
        inport = kwargs['inport']
        if self._port == OpenflowPort.Normal:
            raise Exception("I'm not normal")
        elif self._port == OpenflowPort.Flood:
            for intf in net.interfaces():
                if intf.ifnum != inport:
                    net.send_packet(intf, packet)
        elif self._port == OpenflowPort.All:
            raise Exception("Not implemented")
        elif self._port == OpenflowPort.Controller:
            for c in controllers:
                c.send_packet(port=self._port, packet=packet)
        elif self._port == OpenflowPort.Local:
            raise Exception("Not implemented")
        elif self._port == OpenflowPort.InPort:
            net.send_packet(inport, packet)
        elif self._port == OpenflowPort.Table:
            raise Exception("Not implemented")
        elif self._port == OpenflowPort.NoPort:
            raise Exception("Not implemented")
        else:
            print("packet send on port {} <- {}".format(self._port, packet))
            net.send_packet(self._port, packet)

class ActionEnqueue(OpenflowAction):
    __slots__ = ['_port', '_queue_id']
    _PACKFMT = '!H6xI'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, port=OpenflowPort.NoPort, queue_id=0):
        super().__init__()
        self._type = OpenflowActionType.Enqueue
        self._port = int(port)
        self._queue_id = int(queue_id)
        self.len = super()._MINLEN + ActionEnqueue._MINLEN

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = int(value)

    @property
    def queue_id(self):
        return self._queue_id

    @queue_id.setter
    def queue_id(self, value):
        self._queue_id = int(value)

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        self.port, self.queue_id = struct.unpack(ActionEnqueue._PACKFMT, 
            raw[:ActionEnqueue._MINLEN]) 

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionEnqueue._PACKFMT, 
            self._port, self._queue_id)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")

class ActionVlanVid(OpenflowAction):
    __slots__ = ['_vlan_vid']
    _PACKFMT = '!H2x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, vlan_vid=0):
        super().__init__()
        self._type = OpenflowActionType.SetVlanVid
        self._vlan_vid = vlan_vid
        self.len = super()._MINLEN + ActionVlanVid._MINLEN

    @property
    def vlan_vid(self):
        return self._vlan_vid

    @vlan_vid.setter
    def vlan_vid(self, value):
        self._vlan_vid = int(value)  
    
    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.vlan_vid,) = struct.unpack(ActionVlanVid._PACKFMT, 
            raw[:ActionVlanVid._MINLEN])

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionVlanVid._PACKFMT, 
            self._vlan_vid)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")


class ActionVlanPcp(OpenflowAction):
    __slots__ = ['_vlan_pcp']
    _PACKFMT = '!B3x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, vlan_pcp=0):
        super().__init__()
        self._type = OpenflowActionType.SetVlanPcp
        self._vlan_pcp = vlan_pcp
        self.len = super()._MINLEN + ActionVlanPcp._MINLEN

    @property
    def vlan_pcp(self):
        return self._vlan_pcp

    @vlan_pcp.setter
    def vlan_pcp(self, value):
        self._vlan_pcp = int(value)
    
    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.vlan_pcp,) = struct.unpack(ActionVlanPcp._PACKFMT, 
            raw[:ActionVlanPcp._MINLEN]) 

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionVlanPcp._PACKFMT, 
            self._vlan_pcp)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")

class ActionDlAddr(OpenflowAction):
    __slots__ = ['_dl_addr']
    _PACKFMT = '!6s6x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, srcdst=OpenflowActionType.SetDlSrc, dl_addr="00:00:00:00:00:00"):
        super().__init__()
        self._type = OpenflowActionType(srcdst) 
        if self._type not in (OpenflowActionType.SetDlSrc, OpenflowActionType.SetDlDst):
            raise ValueError("Invalid ActionType for ActionDlAddr")
        self._dl_addr = EthAddr(dl_addr)
        self.len = super()._MINLEN + ActionDlAddr._MINLEN

    @property
    def dl_addr(self):
        return self._dl_addr

    @dl_addr.setter
    def dl_addr(self, value):
        self._dl_addr = EthAddr(value)        

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.dl_addr,) = struct.unpack(ActionDlAddr._PACKFMT, 
            raw[:ActionDlAddr._MINLEN]) 

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionDlAddr._PACKFMT, 
            self._dl_addr.packed)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")

class ActionNwAddr(OpenflowAction):
    __slots__ = ['_nw_addr']
    _PACKFMT = '!4s'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, srcdst=OpenflowActionType.SetNwSrc, nw_addr="0.0.0.0"):
        super().__init__()
        self._type = OpenflowActionType(srcdst) 
        if self._type not in (OpenflowActionType.SetNwSrc, OpenflowActionType.SetNwDst):
            raise ValueError("Invalid ActionType for ActionNwAddr")
        self._nw_addr = ip_address(nw_addr)
        self.len = super()._MINLEN + ActionNwAddr._MINLEN

    @property
    def nw_addr(self):
        return self._nw_addr

    @nw_addr.setter
    def nw_addr(self, value):
        self._nw_addr = ip_address(value) 

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.nw_addr,) = struct.unpack(ActionNwAddr._PACKFMT, 
            raw[:ActionNwAddr._MINLEN]) 

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionNwAddr._PACKFMT, 
            self._nw_addr.packed)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")


class ActionNwTos(OpenflowAction):
    __slots__ = ['_nw_tos']
    _PACKFMT = '!B3x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, tos=0x0):
        super().__init__()
        self._type = OpenflowActionType.SetNwTos
        self._nw_tos = int(tos)
        self.len = super()._MINLEN + ActionNwTos._MINLEN

    @property
    def nw_tos(self):
        return self._nw_tos

    @nw_tos.setter
    def nw_tos(self, value):
        self._nw_tos = int(value)

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.nw_tos,) = struct.unpack(ActionNwTos._PACKFMT, 
            raw[:ActionNwTos._MINLEN]) 

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionNwTos._PACKFMT, self._nw_tos)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")


class ActionTpPort(OpenflowAction):
    __slots__ = ['_tp_port']
    _PACKFMT = '!H2x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, srcdst=OpenflowActionType.SetTpSrc, port=0):
        super().__init__()
        self._type = OpenflowActionType(srcdst) 
        if self._type not in (OpenflowActionType.SetTpSrc, OpenflowActionType.SetTpDst):
            raise ValueError("Invalid ActionType for ActionTpPort")
        self._tp_port = int(port)
        self.len = super()._MINLEN + ActionTpPort._MINLEN

    @property
    def tp_port(self):
        return self._tp_port

    @tp_port.setter
    def tp_port(self, value):
        self._tp_port = int(value)

    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        (self.tp_port,) = struct.unpack(ActionTpPort._PACKFMT, raw[:ActionTpPort._MINLEN])

    def to_bytes(self):
        return super().to_bytes() + struct.pack(ActionTpPort._PACKFMT, self._tp_port)

    def __call__(self, **kwargs):
        raise Exception("Not implemented")


class ActionVendorHeader(OpenflowAction):
    __slots__ = ['_vendor', '_data']
    _PACKFMT = '!I'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, vendor=0xffffffff, data=b''):
        super().__init__()
        self._type = OpenflowActionType.Vendor
        self._vendor = int(vendor)
        self._data = bytes(data)
        self.len = super()._MINLEN + ActionVendorHeader._MINLEN + self._calcdatalen()

    @property
    def vendor(self):
        return self._vendor

    @vendor.setter
    def vendor(self, value):
        self._vendor = int(value)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = bytes(value)
        self.len = super()._MINLEN + ActionVendorHeader._MINLEN + self._calcdatalen()
        
    def from_bytes(self, raw):
        raw = super().from_bytes(raw)
        fields = struct.unpack(ActionVendorHeader._PACKFMT, 
            raw[:ActionVendorHeader._MINLEN]) 
        self.vendor = fields[0]
        datalen = len(raw) - ActionVendorHeader._MINLEN
        self.data = raw[ActionVendorHeader._MINLEN:]

    def to_bytes(self):
        raw = super().to_bytes() + struct.pack(ActionVendorHeader._PACKFMT, self.vendor) + \
            self.data
        padbytes = (self._calcdatalen() - len(self._data)) * b'\x00'
        return raw + padbytes

    def _calcdatalen(self):
        return ceil(len(self._data) / 8) * 8

    def __call__(self, **kwargs):
        raise Exception("Not implemented")


_ActionClassMap = {
    OpenflowActionType.Output: ActionOutput,
    OpenflowActionType.SetVlanVid: ActionVlanVid,
    OpenflowActionType.SetVlanPcp: ActionVlanPcp,
    OpenflowActionType.StripVlan: ActionStripVlan,
    OpenflowActionType.SetDlSrc: ActionDlAddr,
    OpenflowActionType.SetDlDst: ActionDlAddr,
    OpenflowActionType.SetNwSrc: ActionNwAddr,
    OpenflowActionType.SetNwDst: ActionNwAddr,
    OpenflowActionType.SetNwTos: ActionNwTos,
    OpenflowActionType.SetTpSrc: ActionTpPort,
    OpenflowActionType.SetTpDst: ActionTpPort,
    OpenflowActionType.Enqueue: ActionEnqueue,
    OpenflowActionType.Vendor: ActionVendorHeader,
}


def _unpack_actions(raw):
    '''
    deserialize 1 or more actions; return a list of
    Action* objects
    '''
    actions = []

    while len(raw) > 0:
        atype, alen = struct.unpack('!HH', raw[:4])
        atype = OpenflowActionType(atype)
        action = _ActionClassMap.get(atype)()
        action.from_bytes(raw[:alen])
        raw = raw[alen:]
        actions.append(action)
    return actions


class OpenflowEchoRequest(OpenflowStruct):
    __slots__ = ['_data']

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._data = b''

    def size(self):
        return len(self._data)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        if not isinstance(value, bytes):
            raise ValueError("Data value must be bytes object")
        self._data = value

    def to_bytes(self):
        return self._data

    def from_bytes(self, raw):
        self.data = raw


class OpenflowEchoReply(OpenflowEchoRequest):
    def __init__(self):
        OpenflowEchoRequest.__init__(self)


class OpenflowConfigFlags(IntEnum):
    FragNormal = 0
    FragDrop = 1
    FragReasm = 2
    FragMask = 3


class OpenflowSetConfig(OpenflowStruct):
    __slots__ = ['_flags', '_miss_send_len']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._flags = OpenflowConfigFlags.FragNormal
        self._miss_send_len = 1500

    def to_bytes(self):
        return struct.pack(OpenflowSetConfig._PACKFMT, self._flags.value, self._miss_send_len)

    def from_bytes(self, raw):
        if len(raw) < OpenflowSetConfig._MINLEN:
            raise Exception(
                "Not enough bytes to unpack OpenflowSetConfig message")
        fields = struct.unpack(
            OpenflowSetConfig._PACKFMT, raw[:OpenflowSetConfig._MINLEN])
        self.flags = fields[0]
        self.miss_send_len = fields[1]
        return raw[OpenflowSetConfig._MINLEN:]

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        self._flags = OpenflowConfigFlags(value)

    @property
    def miss_send_len(self):
        return self._miss_send_len

    @miss_send_len.setter
    def miss_send_len(self, value):
        self._miss_send_len = int(value)

    def size(self):
        return OpenflowSetConfig._MINLEN


class OpenflowGetConfigReply(OpenflowSetConfig):

    def __init__(self):
        OpenflowSetConfig.__init__(self)


class FlowModCommand(IntEnum):
    Add = 0
    Modify = 1
    ModifyStrict = 2
    Delete = 3
    DeleteStrict = 4


class FlowModFlags(IntEnum):
    NoFlag = 0
    SendFlowRemove = 1
    CheckOverlap = 2
    Emergency = 4


class OpenflowFlowMod(OpenflowStruct):
    '''
    Flowmod message
    '''
    __slots__ = ['_match', '_cookie', '_command', '_idle_timeout',
                 '_hard_timeout', '_priority', '_buffer_id', '_out_port'
                 '_flags', '_actions']
    # NB: packfmt doesn't include match struct or actions
    # those are defined within other structures
    _PACKFMT = '!QHHHHIHH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, match=None):
        OpenflowStruct.__init__(self)
        if match is None:
            match = OpenflowMatch()
        self._match = match
        self._cookie = 0
        self._command = FlowModCommand.Add
        self._idle_timeout = 0
        self._hard_timeout = 0
        self._priority = 0
        self._buffer_id = 0
        self._out_port = 0
        self._flags = set()
        self._actions = []

    def to_bytes(self):
        return self._match.to_bytes() + \
            struct.pack(OpenflowFlowMod._PACKFMT, self._cookie, self._command.value,
                        self._idle_timeout, self._hard_timeout, self._priority, self._buffer_id,
                        self._out_port, self.flags) + \
            b''.join(a.to_bytes() for a in self._actions)

    def from_bytes(self, raw):
        if len(raw) < (OpenflowFlowMod._MINLEN + OpenflowMatch.size()):
            raise Exception("Not enough data to unpack OpenflowFlowMod")
        self._match = OpenflowMatch()
        self.match.from_bytes(raw[:OpenflowMatch.size()])
        raw = raw[OpenflowMatch.size():] 
        fields = struct.unpack(OpenflowFlowMod._PACKFMT, raw[:OpenflowFlowMod._MINLEN])
        self.cookie = fields[0]
        self.command = fields[1]
        self.idle_timeout = fields[2]
        self.hard_timeout = fields[3]
        self.priority = fields[4]
        self.buffer_id = fields[5]
        self.out_port = fields[6]
        self._flags = _unpack_bitmap(fields[7], FlowModFlags) 
        self._actions = _unpack_actions(raw[OpenflowFlowMod._MINLEN:])

    def size(self):
        return len(self.to_bytes())

    @property
    def command(self):
        return self._command

    @command.setter
    def command(self, value):
        self._command = FlowModCommand(value)

    @property
    def flags(self):
        return _make_bitmap(self._flags)

    def get_flags(self):
        return self._flags

    def set_flag(self, value):
        self._flags.add(FlowModFlags(value))

    def clear_flags(self):
        self._flags.clear()

    @property 
    def cookie(self):
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        self._cookie = int(value)

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        self._idle_timeout = int(value)

    @property
    def hard_timeout(self):
        return self._hard_timeout

    @hard_timeout.setter
    def hard_timeout(self, value):
        self._hard_timeout = int(value)

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        self._priority = int(value)

    @property
    def buffer_id(self):
        return self._buffer_id

    @buffer_id.setter
    def buffer_id(self, value):
        self._buffer_id = int(value)

    @property
    def out_port(self):
        return self._out_port

    @out_port.setter
    def out_port(self, value):
        self._out_port = int(value) 
        
    @property
    def match(self):
        return self._match

    @property
    def actions(self):
        return self._actions
   

class OpenflowSwitchFeaturesReply(OpenflowStruct):

    '''
    Switch features response message, not including the header.
    '''
    __slots__ = ['_dpid', '_nbuffers', '_ntables', '_capabilities',
                 '_actions', '_ports']
    _PACKFMT = '!8sIBxxxII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self.dpid = b'\x00' * 8
        self.nbuffers = 0
        self.ntables = 1
        self._capabilities = set()
        self._actions = set()
        self._ports = []

    def to_bytes(self):
        rawpkt = struct.pack(OpenflowSwitchFeaturesReply._PACKFMT,
                             self._dpid, self._nbuffers, self._ntables,
                             self.capabilities, self.actions)
        for p in self._ports:
            rawpkt += p.to_bytes()
        return rawpkt

    def from_bytes(self, raw):
        if len(raw) < OpenflowSwitchFeaturesReply._MINLEN:
            raise Exception(
                "Not enough data to unpack OpenflowSwitchFeaturesReply message")
        fields = struct.unpack(OpenflowSwitchFeaturesReply._PACKFMT,
                               raw[:OpenflowSwitchFeaturesReply._MINLEN])
        self.dpid = fields[0]
        self.nbuffers = fields[1]
        self.ntables = fields[2]
        self._capabilities = _unpack_bitmap(fields[3], OpenflowCapabilities)
        self._actions = _unpack_bitmap(fields[4], OpenflowActionType) 
        remain = raw[OpenflowSwitchFeaturesReply._MINLEN:]
        p = OpenflowPhysicalPort()
        while len(remain) >= p.size():
            remain = p.from_bytes(remain)
            self._ports.append(p)
            p = OpenflowPhysicalPort()
        return remain

    def size(self):
        return len(self.to_bytes())

    @property
    def dpid(self):
        return self._dpid

    @dpid.setter
    def dpid(self, value):
        if not isinstance(value, bytes):
            raise ValueError("Setting dpid directly requires bytes object")
        if len(value) > 8:
            raise ValueError("dpid can only be 8 bytes")
        # pad high-order bytes if we don't get 8 bytes as the value
        self._dpid = b'\x00' * (8 - len(value)) + value

    @property
    def dpid_low48(self):
        return self._dpid[2:8]

    @dpid_low48.setter
    def dpid_low48(self, value):
        if isinstance(value, EthAddr):
            self._dpid = self.dpid_high16 + value.raw
        elif isinstance(value, bytes):
            if len(value) != 6:
                raise ValueError("Exactly 48 bits (6 bytes) must be given")
            self._dpid = self.dpid_high16 + value.raw
        else:
            raise ValueError(
                "Setting low-order 48 bits of dpid must be done with EthAddr or bytes")

    @property
    def dpid_high16(self):
        return self._dpid[0:2]

    @dpid_high16.setter
    def dpid_high16(self, value):
        if isinstance(value, bytes):
            if len(value) != 2:
                raise ValueError("Exactly 16 bits (2 bytes) must be given")
            self._dpid = value + self.dpid_low48
        else:
            raise ValueError(
                "Setting high-order 16 bits of dpid must be done with bytes")

    @property
    def nbuffers(self):
        return self._nbuffers

    @nbuffers.setter
    def nbuffers(self, value):
        value = int(value)
        if 0 <= value < 2 ** 32:
            self._nbuffers = value
        else:
            raise ValueError("Number of buffers must be zero or greater.")

    @property
    def ntables(self):
        return self._ntables

    @ntables.setter
    def ntables(self, value):
        value = int(value)
        if 0 < value < 256:
            self._ntables = value
        else:
            raise ValueError("Number of tables must be 1-255.")

    @property
    def capabilities(self):
        return _make_bitmap(self._capabilities)

    @capabilities.setter
    def capabilities(self, value):
        if isinstance(value, int):
            value = OpenflowCapabilities(value)
        if not isinstance(value, OpenflowCapabilities):
            raise ValueError("Set value must be of type OpenflowCapabilities")
        self._capabilities.add(value)

    def reset_capabilities(self):
        self._capabilities.clear()

    def clear_capabilities(self):
        self._capabilities.clear()

    def add_capabilities(self, value):
        self._capabilities.add(OpenflowCapabilities(value))

    def get_capabilities(self):
        return self._capabilities

    @property
    def actions(self):
        return _make_bitmap(self._actions)

    @actions.setter
    def actions(self, value):
        if isinstance(value, int):
            value = OpenflowActionType(value)
        if not isinstance(value, OpenflowActionType):
            raise ValueError("Set value must be of type OpenflowActionType")
        self._actions.add(value)

    def reset_actions(self):
        self._actions.clear()

    def clear_actions(self):
        self._actions.clear()

    def get_actions(self):
        return self._actions

    def add_actions(self, value):
        self._actions.add(OpenflowActionType(value))

    @property
    def ports(self):
        return self._ports


class OpenflowErrorType(IntEnum):
    HelloFailed = 0
    BadRequest = 1
    BadAction = 2
    FlowModFailed = 3
    PortModFailed = 4
    QueueOpFailed = 5


class OpenflowErrorCode(IntEnum):
    pass


class OpenflowHelloFailedCode(OpenflowErrorCode):
    Incompatible = 0
    PermissionsError = 1


class OpenflowBadRequestCode(OpenflowErrorCode):
    BadVersion = 0
    BadType = 1
    BadStat = 2
    BadVendor = 3
    BadSubtype = 4
    PermissionsError = 5
    BadLength = 6
    BufferEmpty = 7
    BufferUnknown = 8


class OpenflowBadActionCode(OpenflowErrorCode):
    BadType = 0
    BadLength = 1
    BadVendor = 2
    BadVendorType = 3
    BadOutPort = 4
    BadArgument = 5
    PermissionsError = 6
    TooMany = 7
    BadQueue = 8


class OpenflowFlowModFailedCode(OpenflowErrorCode):
    AllTablesFull = 0
    Overlap = 1
    PermissionsError = 2
    BadEmergencyTimeout = 3
    BadCommand = 4
    Unsupported = 5


class OpenflowPortModFailedCode(OpenflowErrorCode):
    BadPort = 0
    BadHardwareAddress = 1


class OpenflowQueueOpFailedCode(OpenflowErrorCode):
    BadPort = 0
    BadQueue = 1
    PermissionsError = 2


OpenflowErrorTypeCodes = {
    OpenflowErrorType.HelloFailed: OpenflowHelloFailedCode,
    OpenflowErrorType.BadRequest: OpenflowBadRequestCode,
    OpenflowErrorType.BadAction: OpenflowBadActionCode,
    OpenflowErrorType.FlowModFailed: OpenflowFlowModFailedCode,
    OpenflowErrorType.PortModFailed: OpenflowPortModFailedCode,
    OpenflowErrorType.QueueOpFailed: OpenflowQueueOpFailedCode
}


class OpenflowError(OpenflowStruct):
    __slots__ = ('_type', '_code', '_data')
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._type = 0
        self._code = 0
        self._data = b''

    def size(self):
        return OpenflowError._MINLEN + len(self.data)

    def to_bytes(self):
        return struct.pack(OpenflowError._PACKFMT, self.errortype.value,
                           self.errorcode.value) + self.data

    def from_bytes(self, raw):
        xtype, xcode = struct.unpack(OpenflowError._PACKFMT,
                                     raw[:OpenflowError._MINLEN])
        self.errortype = xtype
        self.errorcode = xcode
        self.data = raw[OpenflowError._MINLEN:]

    @property
    def errortype(self):
        return self._type

    @errortype.setter
    def errortype(self, value):
        value = OpenflowErrorType(value)
        self._type = value

    @property
    def errorcode(self):
        return self._code

    @errorcode.setter
    def errorcode(self, value):
        codeclass = OpenflowErrorTypeCodes.get(self._type)
        value = codeclass(value)
        self._code = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = bytes(value)


class OpenflowVendor(OpenflowStruct):
    __slots__ = ('_vendor', '_data')
    _PACKFMT = '!I'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._vendor = 0
        self._data = b''

    def size(self):
        return OpenflowVendor._MINLEN + len(self.data)

    def to_bytes(self):
        return struct.pack(OpenflowVendor._PACKFMT, self.vendor) + self.data

    def from_bytes(self, raw):
        fields = struct.unpack(OpenflowVendor._PACKFMT,
                               raw[:OpenflowVendor._MINLEN])
        self.vendor = fields[0]
        self.data = raw[OpenflowVendor._MINLEN:]

    @property
    def vendor(self):
        return self._vendor

    @vendor.setter
    def vendor(self, value):
        self._vendor = int(value)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = bytes(value)


class OpenflowPortMod(OpenflowStruct):
    __slots__ = ('_port_no', '_ethaddr', '_config', '_mask', '_advertise')
    _PACKFMT = '!H6sIII4x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._port_no = 0
        self._ethaddr = EthAddr()
        self._config = set()
        self._mask = set()
        self._advertise = set()

    def size(self):
        return OpenflowPortMod._MINLEN

    def to_bytes(self):
        return struct.pack(OpenflowPortMod._PACKFMT, self.port, self.ethaddr.raw,
            self.config, self.mask, self.advertise)

    def from_bytes(self, raw):
        if len(raw) < OpenflowPortMod._MINLEN:
            raise Exception("Not enough bytes to unpack PortMod")
        fields = struct.unpack(OpenflowPortMod._PACKFMT, raw)
        self.port = fields[0]
        self.ethaddr = fields[1]
        self._config = _unpack_bitmap(fields[2], OpenflowPortConfig)
        self._mask = _unpack_bitmap(fields[3], OpenflowPortConfig)
        self._advertise = _unpack_bitmap(fields[4], OpenflowPortFeatures)

    @property
    def port_no(self):
        return self._port_no

    @property
    def port(self):
        return self._port_no

    @port_no.setter
    def port_no(self, value):
        self._port_no = int(value)

    @port.setter
    def port(self, value):
        self._port_no = int(value)

    @property
    def ethaddr(self):
        return self._ethaddr

    @property
    def hwaddr(self):
        return self._ethaddr

    @ethaddr.setter
    def ethaddr(self, value):
        self._ethaddr = EthAddr(value)

    @hwaddr.setter
    def hwaddr(self, value):
        self._ethaddr = EthAddr(value)

    @property
    def config(self):
        return _make_bitmap(self._config)

    def get_config(self):
        return self._config

    def set_config(self, value):
        self._config.add(OpenflowPortConfig(value))

    def clear_config(self):
        self._config.clear()

    @property
    def mask(self):
        return _make_bitmap(self._mask)

    def get_mask(self):
        return self._mask

    def set_mask(self, value):
        self._mask.add(OpenflowPortConfig(value))

    def clear_mask(self):
        self._mask.clear()

    @property
    def advertise(self):
        return _make_bitmap(self._advertise)

    def get_advertise(self):
        return self._advertise

    def set_advertise(self, value):
        self._advertise.add(OpenflowPortFeatures(value))

    def clear_advertise(self):
        self._advertise.clear()


class PortStatusReason(IntEnum):
    Add = 0
    Delete = 1
    Modify = 2


class OpenflowPortStatus(OpenflowStruct):
    __slots__ = ('_reason', '_port')
    _PACKFMT = '!B7x'
    _MINLEN = 8 + OpenflowPhysicalPort._MINLEN

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._reason = PortStatusReason.Modify
        self._port = OpenflowPhysicalPort()

    def size(self):
        return OpenflowPortStatus._MINLEN

    def to_bytes(self):
        return struct.pack(OpenflowPortStatus._PACKFMT, self._reason.value) + \
            self._port.to_bytes()

    def from_bytes(self, raw):
        if len(raw) < OpenflowPortStatus._MINLEN:
            raise Exception("Not enough bytes to unpack PortStatus")
        fields = struct.unpack(OpenflowPortStatus._PACKFMT, raw[:8])
        self.reason = fields[0]
        self._port = OpenflowPhysicalPort()
        self._port.from_bytes(raw[8:])

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = PortStatusReason(value)

    @property
    def port(self):
        return self._port
    

class OpenflowStatsType(IntEnum):
    SwitchDescription = 0
    IndividualFlow = 1
    AggregateFlow = 2
    Table = 3
    Port = 4
    Queue = 5
    Vendor = 0xffff
    NoStatsType = 0xdead


class _OpenflowStatsRequest(OpenflowStruct):
    __slots__ = ('_type', '_flags')
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, xtype=OpenflowStatsType.NoStatsType, **kwargs):
        OpenflowStruct.__init__(self, **kwargs)
        self._type = OpenflowStatsType(xtype)
        # NB: no flags are defined in OF 1.0 spec 

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = OpenflowStatsType(value)

    def size(self):
        return _OpenflowStatsRequest._MINLEN

    def to_bytes(self):
        return struct.pack(_OpenflowStatsRequest._PACKFMT, self._type.value, 0)

    def from_bytes(self, raw):
        if len(raw) < _OpenflowStatsRequest._MINLEN:
            raise Exception("Not enough data to unpack _OpenflowStatsRequest")
        fields = struct.unpack(_OpenflowStatsRequest._PACKFMT, raw[:_OpenflowStatsRequest._MINLEN])
        self.type = fields[0]


class SwitchDescriptionStatsRequest(_OpenflowStatsRequest):
    # no body beyond header
    def __init__(self):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.SwitchDescription)


class IndividualFlowStatsRequest(_OpenflowStatsRequest):
    __slots__ = ('_match', '_table_id', '_out_port')
    _PACKFMT = '!BxH'
    _MINLEN = OpenflowMatch.size() + _OpenflowStatsRequest._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.IndividualFlow, **kwargs)
        self._match = OpenflowMatch()
        self._table_id = 0
        self._out_port = 0

    @property
    def match(self):
        return self._match

    @property
    def table_id(self):
        return self._table_id

    @table_id.setter
    def table_id(self, value):
        self._table_id = int(value)

    @property
    def out_port(self):
        return self._out_port

    @out_port.setter
    def out_port(self, value):
        self._out_port = _get_port(value)

    def size(self):
        return IndividualFlowStatsRequest._MINLEN

    def to_bytes(self):
        return super().to_bytes() + self._match.to_bytes() + \
            struct.pack(IndividualFlowStatsRequest._PACKFMT, self._table_id, self._out_port)

    def from_bytes(self, raw):
        if len(raw) < IndividualFlowStatsRequest._MINLEN:
            raise Exception("Not enough data to unpack IndividualFlowStatsRequest")
        super().from_bytes(raw[:_OpenflowStatsRequest._MINLEN])
        raw = raw[_OpenflowStatsRequest._MINLEN:]
        self.match.from_bytes(raw[:OpenflowMatch.size()])
        raw = raw[OpenflowMatch.size():]
        fields = struct.unpack(IndividualFlowStatsRequest._PACKFMT, raw)
        self.table_id = fields[0]
        self.out_port = fields[1]


class AggregateFlowStatsRequest(IndividualFlowStatsRequest):
    # body is same as individual flow stats request
    pass


class TableStatsRequest(_OpenflowStatsRequest):
    # no body beyond header
    def __init__(self):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.Table)


class PortStatsRequest(_OpenflowStatsRequest):
    __slots__ = ('_port_no')
    _PACKFMT = '!H6x'
    _MINLEN = _OpenflowStatsRequest._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.Port, **kwargs)
        self._port_no = OpenflowPort.NoPort

    @property
    def port_no(self):
        return self._port_no

    @port_no.setter
    def port_no(self, value):
        self._port_no = _get_port(value)

    @property
    def port(self):
        return self.port_no

    @port.setter
    def port(self, value):
        self.port_no = value
    
    def size(self):
        return PortStatsRequest._MINLEN

    def to_bytes(self):
        return super().to_bytes() + struct.pack(PortStatsRequest._PACKFMT, self.port)

    def from_bytes(self, raw):
        if len(raw) < PortStatsRequest._MINLEN:
            raise Exception("Not enough data to unpack PortStatsRequest")
        super().from_bytes(raw[:_OpenflowStatsRequest._MINLEN])
        raw = raw[_OpenflowStatsRequest._MINLEN:]
        fields = struct.unpack(PortStatsRequest._PACKFMT, raw)
        self.port = fields[0]


class QueueStatsRequest(_OpenflowStatsRequest):
    __slots__ = ('_port_no', '_queue_id')
    _PACKFMT = '!H2xI'
    _MINLEN = _OpenflowStatsRequest._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.Queue, **kwargs)
        self._port_no = OpenflowPort.NoPort
        self._queue_id = 0

    @property
    def port_no(self):
        return self._port_no

    @port_no.setter
    def port_no(self, value):
        self._port_no = _get_port(value)

    @property
    def port(self):
        return self.port_no

    @port.setter
    def port(self, value):
        self.port_no = value
      
    @property
    def queue_id(self):
        return self._queue_id

    @queue_id.setter
    def queue_id(self, value):
        self._queue_id = int(value)

    def size(self):
        return QueueStatsRequest._MINLEN

    def to_bytes(self):
        return super().to_bytes() + \
            struct.pack(QueueStatsRequest._PACKFMT, self.port, self.queue_id)

    def from_bytes(self, raw):
        if len(raw) < QueueStatsRequest._MINLEN:
            raise Exception("Not enough data to unpack QueueStatsRequest")
        super().from_bytes(raw[:_OpenflowStatsRequest._MINLEN])
        raw = raw[_OpenflowStatsRequest._MINLEN:]
        fields = struct.unpack(QueueStatsRequest._PACKFMT, raw)
        self.port = fields[0]
        self.queue_id = fields[1]


class VendorStatsRequest(_OpenflowStatsRequest):
    __slots__ = ('_vendor_id', '_data')
    _PACKFMT = '!I'
    _MINLEN = _OpenflowStatsRequest._MINLEN + 4

    def __init__(self, **kwargs):
        _OpenflowStatsRequest.__init__(self, OpenflowStatsType.Vendor)
        self._vendor_id = 0xffffffff
        self._data = b''

    @property
    def vendor_id(self):
        return self._vendor_id

    @vendor_id.setter
    def vendor_id(self, value):
        self._vendor_id = int(value)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = bytes(value)

    def size(self):
        return 4 + len(self._data)

    def to_bytes(self):
        return super().to_bytes() + struct.pack(VendorStatsRequest._PACKFMT, self._vendor_id) + \
            self._data

    def from_bytes(self, raw):
        if len(raw) < VendorStatsRequest._MINLEN:
            raise Exception("Not enough data to unpack VendorStatsRequest")
        super().from_bytes(raw[:_OpenflowStatsRequest._MINLEN])
        raw = raw[_OpenflowStatsRequest._MINLEN:]
        fields = struct.unpack(VendorStatsRequest._PACKFMT, raw[:4])
        self.vendor_id = fields[0]
        self.data = raw[4:]


class _OpenflowStatsReply(_OpenflowStatsRequest):
    # reply has identical header as stats request
    pass


class SwitchDescriptionStatsReply(_OpenflowStatsReply):
    __slots__ = ('_mfr_desc', '_hw_desc', '_sw_desc', '_serial_num', '_dp_desc')
    _PACKFMT = '!256s256s256s32s256s'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        self._mfr_desc = '' 
        self._hw_desc = '' 
        self._sw_desc = '' 
        self._serial_num = ''
        self._dp_desc = ''
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.SwitchDescription, **kwargs)

    @property
    def mfr_desc(self):
        return self._mfr_desc

    @mfr_desc.setter
    def mfr_desc(self, value):
        self._mfr_desc = value

    @property
    def hw_desc(self):
        return self._hw_desc

    @hw_desc.setter
    def hw_desc(self, value):
        self._hw_desc = value

    @property
    def sw_desc(self):
        return self._sw_desc

    @sw_desc.setter
    def sw_desc(self, value):
        self._sw_desc = value

    @property
    def serial_num(self):
        return self._serial_num

    @serial_num.setter
    def serial_num(self, value):
        self._serial_num = value

    @property
    def dp_desc(self):
        return self._dp_desc

    @dp_desc.setter
    def dp_desc(self, value):
        self._dp_desc = value

    def size(self):
        return SwitchDescriptionStatsReply._MINLEN

    def to_bytes(self):
        return super().to_bytes() + \
            struct.pack(SwitchDescriptionStatsReply._PACKFMT, 
                self.mfr_desc.encode(), self.hw_desc.encode(), 
                self.sw_desc.encode(), self.serial_num.encode(), 
                self._dp_desc.encode())

    def from_bytes(self, raw):
        if len(raw) < SwitchDescriptionStatsReply._MINLEN:
            raise Exception("Not enough data to unpack SwitchDescriptionStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(SwitchDescriptionStatsReply._PACKFMT, raw)
        self.mfr_desc = fields[0].decode()
        self.hw_desc = fields[1].decode()
        self.sw_desc = fields[2].decode()
        self.serial_num = fields[3].decode()
        self.dp_desc = fields[4].decode()
    

class IndividualFlowStatsReply(_OpenflowStatsReply):
    __slots__ = ('_table_id', '_match', '_duration_sec', '_duration_nsec',
        '_priority', '_idle_timeout', '_hard_timeout', '_cookie', '_packet_count',
        '_byte_count', '_actions')
    _PACKFMT1 = '!HBx'
    _PACKFMT2 = '!IIHHH6xQQQ'
    _MINLEN = struct.calcsize(_PACKFMT1) + struct.calcsize(_PACKFMT2) + \
        OpenflowMatch.size() + _OpenflowStatsReply._MINLEN

    def __init__(self, **kwargs):
        self._table_id = 0
        self._match = OpenflowMatch()
        self._duration_sec = self._duration_nsec = 0
        self._priority = 0
        self._idle_timeout = self._hard_timeout = 0
        self._cookie = 0
        self._packet_count = self._byte_count = 0
        self._actions = []
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.IndividualFlow, **kwargs)

    def size(self):
        actions = b''.join([a.to_bytes() for a in self._actions])
        return IndividualFlowStatsReply._MINLEN + len(actions)

    def to_bytes(self):
        part0 = super().to_bytes()
        part2 = self.match.to_bytes()
        part3 = struct.pack(IndividualFlowStatsReply._PACKFMT2, self.duration_sec, self.duration_nsec,
            self.priority, self.idle_timeout, self.hard_timeout, self.cookie, self.packet_count,
            self._byte_count)
        part4 = b''.join([a.to_bytes() for a in self._actions])
        xlen = IndividualFlowStatsReply._MINLEN + len(part4)
        part1 = struct.pack(IndividualFlowStatsReply._PACKFMT1, xlen, self.table_id)
        return part0 + part1 + part2 + part3 + part4

    def from_bytes(self, raw):
        if len(raw) < IndividualFlowStatsReply._MINLEN:
            raise Exception("Not enough data to unpack IndividualFlowStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        part0size = struct.calcsize(IndividualFlowStatsReply._PACKFMT1)
        part2size = struct.calcsize(IndividualFlowStatsReply._PACKFMT2)
        fields0 = struct.unpack(IndividualFlowStatsReply._PACKFMT1, raw[:part0size])
        xlen = fields0[0]
        self.table_id = fields0[1]
        raw = raw[part0size:]
        self.match = OpenflowMatch()
        self.match.from_bytes(raw[:OpenflowMatch.size()])
        raw = raw[OpenflowMatch.size():]
        fields1 = struct.unpack(IndividualFlowStatsReply._PACKFMT2, raw[:part2size])
        self.duration_sec = fields1[0]
        self.duration_nsec = fields1[1]
        self.priority = fields1[2]
        self.idle_timeout = fields1[3]
        self.hard_timeout = fields1[4]
        self.cookie = fields1[5]
        self.packet_count = fields1[6]
        self.byte_count = fields1[7]
        self._actions = _unpack_actions(raw[part2size:])

    @property
    def table_id(self):
        return self._table_id

    @table_id.setter
    def table_id(self, value):
        self._table_id = int(value)     

    @property
    def match(self):
        return self._match

    @match.setter
    def match(self, value):
        if not isinstance(value, OpenflowMatch):
            raise ValueError("match must be set to OpenflowMatch object")
        self._match = value

    @property
    def cookie(self):
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        self._cookie = int(value)

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        self._priority = int(value)

    @property
    def duration_sec(self):
        return self._duration_sec

    @duration_sec.setter
    def duration_sec(self, value):
        self._duration_sec = int(value)

    @property
    def duration_nsec(self):
        return self._duration_nsec

    @duration_nsec.setter
    def duration_nsec(self, value):
        self._duration_nsec = int(value)

    @property
    def duration(self):
        return self._duration_sec + self._duration_nsec / 1e9
    
    @duration.setter
    def duration(self, value):
        self._duration_sec = int(value)
        self._duration_nsec = int((value - self._duration_sec) * 1e9)

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        self._idle_timeout = int(value)

    @property
    def hard_timeout(self):
        return self._hard_timeout

    @hard_timeout.setter
    def hard_timeout(self, value):
        self._hard_timeout = int(value)

    @property
    def packet_count(self):
        return self._packet_count

    @packet_count.setter
    def packet_count(self, value):
        self._packet_count = int(value)

    @property
    def byte_count(self):
        return self._byte_count

    @byte_count.setter
    def byte_count(self, value):
        self._byte_count = int(value)

    @property
    def actions(self):
        return self._actions


class AggregateFlowStatsReply(_OpenflowStatsReply):
    __slots__ = ('_byte_count', '_packet_count', '_flow_count')
    _PACKFMT = '!QQI'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self, **kwargs):
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.AggregateFlow, **kwargs)
        self._byte_count = self._packet_count = self._flow_count = 0

    def size(self):
        return AggregateFlowStatsReply._MINLEN

    def to_bytes(self):
        return super().to_bytes() + struct.pack(AggregateFlowStatsReply._PACKFMT,
            self.byte_count, self.packet_count, self.flow_count)

    def from_bytes(self, raw):
        if len(raw) < AggregateFlowStatsReply._MINLEN:
            raise Exception("Not enough data to unpack AggregateFlowStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(AggregateFlowStatsReply._PACKFMT, raw)
        self.byte_count = fields[0]
        self.packet_count = fields[1]
        self.flow_count = fields[2]

    @property
    def byte_count(self):
        return self._byte_count

    @byte_count.setter
    def byte_count(self, value):
        self._byte_count = int(value)

    @property
    def packet_count(self):
        return self._packet_count

    @packet_count.setter
    def packet_count(self, value):
        self._packet_count = int(value)

    @property
    def flow_count(self):
        return self._flow_count

    @flow_count.setter
    def flow_count(self, value):
        self._flow_count = int(value)
    

class TableStatsReply(_OpenflowStatsReply):
    __slots__ = ('_table_id', '_name', '_wildcards', '_max_entries', 
        '_active_count', '_lookup_count', '_matched_count')
    _PACKFMT = '!B3x32sIIIQQ'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self):
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.Table)
        self._table_id = 0
        self._name = ''
        self._wildcards = set()
        self._max_entries = 0
        self._active_count = self._lookup_count = self._matched_count = 0

    def size(self):
        return TableStatsReply._MINLEN

    def to_bytes(self):
        wildbits = _make_bitmap(self._wildcards)
        return super().to_bytes() + \
            struct.pack(TableStatsReply._PACKFMT, self.table_id, self.name.encode(),
                wildbits, self.max_entries, self.active_count, 
                self.lookup_count, self.matched_count)

    def from_bytes(self, raw):
        if len(raw) < TableStatsReply._MINLEN:
            raise Exception("Not enough data to unpack TableStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(TableStatsReply._PACKFMT, raw)
        self._wildcards = set()
        wildbits = fields[2]
        if fields[1] == OpenflowWildcard.All.value:
            self.wildcard_all()
            self.nwsrc_wildcard = 32
            self.nwdst_wildcard = 32
        else:
            for v in OpenflowWildcard:
                if not v.name.endswith('All') and \
                   not v.name.endswith('Mask') and \
                   v.value & wildbits == v.value:
                    self.add_wildcard(v)

            # set nwsrc_wildcard, nwdst_wildcard
            nwsrcbits = (wildbits & OpenflowWildcard.NwSrcMask.value) >> 8
            self.nwsrc_wildcard = nwsrcbits
            nwdstbits = (wildbits & OpenflowWildcard.NwDstMask.value) >> 14
            self.nwdst_wildcard = nwdstbits

        self.table_id = fields[0]
        self.name = fields[1].decode()
        self.max_entries = fields[3]
        self.active_count = fields[4]
        self.lookup_count = fields[5]
        self.matched_count = fields[6]

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
 
    @property
    def wildcards(self):
        wcards = []
        wcards.append("NwSrc:{}".format(self.nwsrc_wildcard))
        wcards.append("NwDst:{}".format(self.nwdst_wildcard))
        wcards.extend([w.name for w in self._wildcards])
        return wcards

    def add_wildcard(self, value):
        value = OpenflowWildcard(value)
        self._wildcards.add(value)

    def reset_wildcards(self):
        self._wildcards.clear()

    def remove_wildcard(self, value):
        self._wildcards.discard(value)

    def wildcard_all(self):
        self._wildcards = set([OpenflowWildcard.All])

    @property
    def table_id(self):
        return self._table_id

    @table_id.setter
    def table_id(self, value):
        self._table_id = int(value)
    
    @property
    def max_entries(self):
        return self._max_entries

    @max_entries.setter
    def max_entries(self, value):
        self._max_entries = int(value)

    @property
    def active_count(self):
        return self._active_count

    @active_count.setter
    def active_count(self, value):
        self._active_count = int(value)

    @property
    def lookup_count(self):
        return self._lookup_count

    @lookup_count.setter
    def lookup_count(self, value):
        self._lookup_count = int(value)
    
    @property
    def matched_count(self):
        return self._matched_count

    @matched_count.setter
    def matched_count(self, value):
        self._matched_count = int(value)
    

class PortStatsReply(_OpenflowStatsReply):
    __slots__ = ('_port_no', '_rx_packets', '_tx_packets', '_rx_bytes',
        '_tx_bytes', '_rx_dropped', '_tx_dropped', '_rx_errors', '_tx_errors',
        '_rx_frame_errors', '_rx_over_errors', '_rx_crc_errors', '_collisions')
    _PACKFMT = '!H6x12Q'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self):
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.Port)
        self._port_no = 0
        self._rx_packets = self._tx_packets = 0
        self._rx_bytes = self._tx_bytes = 0
        self._rx_dropped = self._tx_dropped = 0
        self._rx_errors = self._tx_errors = 0
        self._rx_frame_errors = self._rx_over_errors = self._rx_crc_errors = 0
        self._collisions = 0

    def size(self):
        return PortStatsReply._MINLEN

    def to_bytes(self):
        return super().to_bytes() + \
            struct.pack(PortStatsReply._PACKFMT, self.port_no, self.rx_packets,
                self.tx_packets, self.rx_bytes, self.tx_bytes, self.rx_dropped,
                self.tx_dropped, self.rx_errors, self.tx_errors, self.rx_frame_errors,
                self.rx_over_errors, self.rx_crc_errors, self.collisions)

    def from_bytes(self, raw):
        if len(raw) < PortStatsReply._MINLEN:
            raise Exception("Not enough data to unpack PortStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(PortStatsReply._PACKFMT, raw)
        self.port_no = fields[0]
        self.rx_packets = fields[1]
        self.tx_packets = fields[2]
        self.rx_bytes = fields[3]
        self.tx_bytes = fields[4]
        self.rx_dropped = fields[5]
        self.tx_dropped = fields[6]
        self.rx_errors = fields[7]
        self.tx_errors = fields[8]
        self.rx_frame_errors = fields[9]
        self.rx_over_errors = fields[10]
        self.rx_crc_errors = fields[11]
        self.collisions = fields[12]

    @property
    def port_no(self):
        return self._port_no

    @port_no.setter
    def port_no(self, value):
        self._port_no = int(value)

    @property
    def rx_packets(self):
        return self._rx_packets

    @rx_packets.setter
    def rx_packets(self, value):
        self._rx_packets = int(value)

    @property
    def tx_packets(self):
        return self._tx_packets

    @tx_packets.setter
    def tx_packets(self, value):
        self._tx_packets = int(value)

    @property
    def rx_bytes(self):
        return self._rx_bytes

    @rx_bytes.setter
    def rx_bytes(self, value):
        self._rx_bytes = int(value)

    @property
    def tx_bytes(self):
        return self._tx_bytes

    @tx_bytes.setter
    def tx_bytes(self, value):
        self._tx_bytes = int(value)

    @property
    def rx_dropped(self):
        return self._rx_dropped

    @rx_dropped.setter
    def rx_dropped(self, value):
        self._rx_dropped = int(value)

    @property
    def tx_dropped(self):
        return self._tx_dropped

    @tx_dropped.setter
    def tx_dropped(self, value):
        self._tx_dropped = int(value)

    @property
    def rx_errors(self):
        return self._rx_errors

    @rx_errors.setter
    def rx_errors(self, value):
        self._rx_errors = int(value)

    @property
    def tx_errors(self):
        return self._tx_errors

    @tx_errors.setter
    def tx_errors(self, value):
        self._tx_errors = int(value)
    
    @property
    def rx_frame_errors(self):
        return self._rx_frame_errors

    @rx_frame_errors.setter
    def rx_frame_errors(self, value):
        self._rx_frame_errors = int(value)

    @property
    def rx_over_errors(self):
        return self._rx_over_errors

    @rx_over_errors.setter
    def rx_over_errors(self, value):
        self._rx_over_errors = int(value)
    
    @property
    def rx_crc_errors(self):
        return self._rx_crc_errors

    @rx_crc_errors.setter
    def rx_crc_errors(self, value):
        self._rx_over_errors = int(value)

    @property
    def collisions(self):
        return self._collisions

    @collisions.setter
    def collisions(self, value):
        self._collisions = int(value)


class QueueStatsReply(_OpenflowStatsReply):
    __slots__ = ('_port_no', '_queue_id', '_tx_bytes', '_tx_packets', '_tx_errors')
    _PACKFMT = '!H2xIQQQ'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self):
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.Queue)
        self._port_no = self._queue_id = 0
        self._tx_bytes = self._tx_packets = self._tx_errors = 0

    def size(self):
        return PortStatsReply._MINLEN

    def to_bytes(self):
        return super().to_bytes() + struct.pack(QueueStatsReply._PACKFMT,
            self.port_no, self.queue_id, self.tx_bytes, self.tx_packets, self.tx_errors)

    def from_bytes(self, raw):
        if len(raw) < QueueStatsReply._MINLEN:
            raise Exception("Not enough data to unpack QueueStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(QueueStatsReply._PACKFMT, raw)
        self.port_no = fields[0]
        self.queue_id = fields[1]
        self.tx_bytes = fields[2]
        self.tx_packets = fields[3]
        self.tx_errors = fields[4]

    @property
    def port_no(self):
        return self._port_no

    @port_no.setter
    def port_no(self, value):
        self._port_no = int(value)

    @property
    def queue_id(self):
        return self._queue_id

    @queue_id.setter
    def queue_id(self, value):
        self._queue_id = int(value)

    @property
    def tx_bytes(self):
        return self._tx_bytes

    @tx_bytes.setter
    def tx_bytes(self, value):
        self._tx_bytes = int(value)
    
    @property
    def tx_packets(self):
        return self._tx_packets

    @tx_packets.setter
    def tx_packets(self, value):
        self._tx_packets = int(value)

    @property
    def tx_errors(self):
        return self._tx_errors
      
    @tx_errors.setter
    def tx_errors(self, value):
        self._tx_errors = int(value)


class VendorStatsReply(_OpenflowStatsReply):
    __slots__ = ('_vendor_id', '_data')
    _PACKFMT = '!I'
    _MINLEN = _OpenflowStatsReply._MINLEN + struct.calcsize(_PACKFMT)

    def __init__(self):
        _OpenflowStatsReply.__init__(self, OpenflowStatsType.Vendor)
        self._vendor_id = 0
        self._data = b''

    def size(self):
        return VendorStatsReply._MINLEN + len(self._data)

    def to_bytes(self):
        return super().to_bytes() + struct.pack(VendorStatsReply._PACKFMT, self.vendor_id) + \
            self.data

    def from_bytes(self, raw):
        if len(raw) < VendorStatsReply._MINLEN:
            raise Exception("Not enough data to unpack VendorStatsReply")
        super().from_bytes(raw[:_OpenflowStatsReply._MINLEN])
        raw = raw[_OpenflowStatsReply._MINLEN:]
        fields = struct.unpack(VendorStatsReply._PACKFMT, raw[:4])
        self.vendor_id = fields[0]
        self.data = raw[4:]

    @property
    def vendor_id(self):
        return self._vendor_id

    @vendor_id.setter
    def vendor_id(self, value):
        self._vendor_id = value
    
    @property
    def data(self):
        return self._data
   
    @data.setter
    def data(self, value):
        self._data = bytes(value) 


_OpenflowStatsRequestClassMap = {
    OpenflowStatsType.SwitchDescription: SwitchDescriptionStatsRequest,
    OpenflowStatsType.IndividualFlow: IndividualFlowStatsRequest,
    OpenflowStatsType.AggregateFlow: AggregateFlowStatsRequest,
    OpenflowStatsType.Table: TableStatsRequest,
    OpenflowStatsType.Port: PortStatsRequest,
    OpenflowStatsType.Queue: QueueStatsRequest,
    OpenflowStatsType.Vendor: VendorStatsRequest,
}

_OpenflowStatsReplyClassMap = {
    OpenflowStatsType.SwitchDescription: SwitchDescriptionStatsReply,
    OpenflowStatsType.IndividualFlow: IndividualFlowStatsReply,
    OpenflowStatsType.AggregateFlow: AggregateFlowStatsReply,
    OpenflowStatsType.Table: TableStatsReply,
    OpenflowStatsType.Port: PortStatsReply,
    OpenflowStatsType.Queue: QueueStatsReply,
    OpenflowStatsType.Vendor: VendorStatsReply,
}


class OpenflowQueueGetConfigRequest(OpenflowStruct):
    __slots__ = ('_port')
    _PACKFMT = '!H2x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, port=0):
        OpenflowStruct.__init__(self)
        self._port = port

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = _get_port(value)
    
    def size(self):
        return OpenflowQueueGetConfigRequest._MINLEN

    def to_bytes(self):
        return struct.pack(OpenflowQueueGetConfigRequest._PACKFMT, 
            int(self._port))

    def from_bytes(self, raw):
        if len(raw) < OpenflowQueueGetConfigRequest._MINLEN:
            raise Exception("Not enough data to unpack OpenflowQueueGetConfigRequest")
        fields = struct.unpack(OpenflowQueueGetConfigRequest._PACKFMT, raw)
        self.port = fields[0]


class OpenflowQueueGetConfigReply(OpenflowStruct):
    __slots__ = ('_port', '_queues')
    _PACKFMT = '!H6x'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, port=0):
        OpenflowStruct.__init__(self)
        self._port = port
        self._queues = []

    @property
    def queues(self):
        return self._queues
    
    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = _get_port(value)

    def size(self):
        rawqueues = b''.join([q.to_bytes() for q in self._queues])
        return OpenflowQueueGetConfigReply._MINLEN + len(rawqueues)

    def to_bytes(self):
        return struct.pack(OpenflowQueueGetConfigReply._PACKFMT, 
            int(self._port)) + \
            b''.join([q.to_bytes() for q in self._queues])

    def from_bytes(self, raw):
        if len(raw) < OpenflowQueueGetConfigReply._MINLEN:
            raise Exception("Not enough data to unpack OpenflowQueueGetConfigReply")
        fields = struct.unpack(OpenflowQueueGetConfigReply._PACKFMT, 
            raw[:OpenflowQueueGetConfigReply._MINLEN])
        self.port = fields[0]
        raw = raw[OpenflowQueueGetConfigReply._MINLEN:]
        while len(raw) > 0:
            qid,qlen = struct.unpack('!IH', raw[:6])
            rawqueue = raw[:qlen]
            queue = OpenflowPacketQueue()
            queue.from_bytes(rawqueue)
            self._queues.append(queue)
            raw = raw[qlen:]


class OpenflowPacketInReason(IntEnum):
    NoMatch = 0
    Action = 1
    NoReason = 0xff


class OpenflowPacketIn(OpenflowStruct):
    __slots__ = ('_buffer_id', '_in_port', '_reason', '_packet_data')
    _PACKFMT = '!IHHBx'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._buffer_id = 0xffffffff
        self._in_port = OpenflowPort.NoPort
        self._reason = OpenflowPacketInReason.NoReason
        self._packet_data = b''

    def size(self):
        return OpenflowPacketIn._MINLEN + len(self.packet)

    def to_bytes(self):
        totallen = len(self.packet) + OpenflowPacketIn._MINLEN 
        return struct.pack(OpenflowPacketIn._PACKFMT, self.buffer_id,
                           totallen, self.in_port,
                           self.reason.value) + self.packet

    def from_bytes(self, raw):
        if len(raw) < OpenflowPacketIn._MINLEN:
            raise Exception("Not enough data to unpack OpenflowPacketIn")
        fields = struct.unpack(
            OpenflowPacketIn._PACKFMT, raw[:OpenflowPacketIn._MINLEN])
        self.buffer_id = fields[0]
        xlen = fields[1]
        self.in_port = fields[2]
        self.reason = fields[3]
        self.packet = raw[OpenflowPacketIn._MINLEN:]

    @property
    def buffer_id(self):
        return self._buffer_id

    @buffer_id.setter
    def buffer_id(self, value):
        self._buffer_id = int(value)

    @property
    def in_port(self):
        return self._in_port

    @in_port.setter
    def in_port(self, value):
        self._in_port = _get_port(value)

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = OpenflowPacketInReason(value)

    @property
    def packet(self):
        return self._packet_data

    @packet.setter
    def packet(self, value):
        if isinstance(value, Packet):
            value = value.to_bytes()
        self._packet_data = bytes(value)


class OpenflowPacketOut(OpenflowStruct):
    __slots__ = ('_buffer_id', '_in_port', '_actions', '_packet_data')
    _PACKFMT = '!IHH'
    _MINLEN = 8

    def __init__(self):
        OpenflowStruct.__init__(self)
        self._buffer_id = 0xffffffff
        self._in_port = OpenflowPort.NoPort
        self._actions = []
        self._packet = b''

    @property
    def buffer_id(self):
        return self._buffer_id

    @buffer_id.setter
    def buffer_id(self, value):
        self._buffer_id = int(value)

    @property
    def in_port(self):
        return self._in_port

    @in_port.setter
    def in_port(self, value):
        self._in_port = _get_port(value)

    @property
    def actions(self):
        return self._actions

    @property
    def packet(self):
        return self._packet_data

    @packet.setter
    def packet(self, value):
        if isinstance(value, Packet):
            value = value.to_bytes()
        self._packet_data = bytes(value)

    def size(self):
        actionlen = len(b''.join(a.to_bytes() for a in self._actions))
        return OpenflowPacketOut._MINLEN + len(self.packet) + actionlen

    def to_bytes(self):
        actions = b''.join(a.to_bytes() for a in self._actions)
        return struct.pack(OpenflowPacketOut._PACKFMT, self.buffer_id,
                           self.in_port, len(actions)) + actions + self.packet

    def from_bytes(self, raw):
        if len(raw) < OpenflowPacketOut._MINLEN:
            raise Exception("Not enough data to unpack OpenflowPacketOut")
        fields = struct.unpack(
            OpenflowPacketOut._PACKFMT, raw[:OpenflowPacketOut._MINLEN])
        self.buffer_id = fields[0]
        self.in_port = fields[1]
        actionlen = fields[2]
        raw = raw[OpenflowPacketOut._MINLEN:]
        self._actions = _unpack_actions(raw[:actionlen])
        self.packet = raw[actionlen:]


class FlowRemovedReason(IntEnum):
    IdleTimeout = 0
    HardTimeout = 1
    Delete = 2
    Unknown = 0xff


class OpenflowFlowRemoved(OpenflowStruct):
    __slots__ = ('_match', '_cookie', '_priority', '_reason',
                 '_duration_sec', '_duration_nsec', '_idle_timeout',
                 '_packet_count', '_byte_count')
    _PACKFMT = '!QHBxIIH2xQQ'
    _MINLEN = struct.calcsize(_PACKFMT) + OpenflowMatch.size()

    def __init__(self, reason=FlowRemovedReason.Unknown, match=None):
        OpenflowStruct.__init__(self)
        if match is None:
            match = OpenflowMatch()
        self._match = match
        self._cookie = 0
        self._priority = 0
        self._reason = reason
        self._duration_sec = self._duration_nsec = 0
        self._idle_timeout = 0
        self._packet_count = 0
        self._byte_count = 0

    def size(self):
        return OpenflowFlowRemoved._MINLEN

    def to_bytes(self):
        return self._match.to_bytes() + \
            struct.pack(OpenflowFlowRemoved._PACKFMT, self._cookie, self._priority,
                self._reason.value, self._duration_sec, self._duration_nsec,
                self._idle_timeout, self._packet_count, self._byte_count)

    def from_bytes(self, raw):
        if len(raw) < OpenflowFlowRemoved._MINLEN:
            raise Exception("Not enough bytes to unpack OpenflowFlowRemoved")

        self._match = OpenflowMatch()
        self._match.from_bytes(raw[:OpenflowMatch.size()])
        fields = struct.unpack(OpenflowFlowRemoved._PACKFMT, raw[OpenflowMatch.size():self.size()])
        self.cookie = fields[0]
        self.priority = fields[1]
        self.reason = fields[2]
        self.duration_sec = fields[3]
        self.duration_nsec = fields[4]
        self.idle_timeout = fields[5]
        self.packet_count = fields[6]
        self.byte_count = fields[7]

    @property
    def match(self):
        return self._match

    @match.setter
    def match(self, value):
        if not isinstance(value, OpenflowMatch):
            raise ValueError("match must be set to OpenflowMatch object")
        self._match = value

    @property
    def cookie(self):
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        self._cookie = int(value)

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        self._priority = int(value)

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = FlowRemovedReason(value)

    @property
    def duration_sec(self):
        return self._duration_sec

    @duration_sec.setter
    def duration_sec(self, value):
        self._duration_sec = int(value)

    @property
    def duration_nsec(self):
        return self._duration_nsec

    @duration_nsec.setter
    def duration_nsec(self, value):
        self._duration_nsec = int(value)

    @property
    def duration(self):
        return self._duration_sec + self._duration_nsec / 1e9
    
    @duration.setter
    def duration(self, value):
        self._duration_sec = int(value)
        self._duration_nsec = int((value - self._duration_sec) * 1e9)

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, value):
        self._idle_timeout = int(value)

    @property
    def packet_count(self):
        return self._packet_count

    @packet_count.setter
    def packet_count(self, value):
        self._packet_count = int(value)

    @property
    def byte_count(self):
        return self._byte_count

    @byte_count.setter
    def byte_count(self, value):
        self._byte_count = int(value)


class OpenflowHeader(PacketHeaderBase):

    '''
    Standard 8 byte header for all Openflow packets.
    This is a mostly-internal class used by the various
    OpenflowMessage type classes.
    '''
    __slots__ = ['_version', '_type', '_length', '_xid', '_subtype']
    _PACKFMT = '!BBHI'
    _MINLEN = struct.calcsize(_PACKFMT)
    _OpenflowTypeClasses = {
        OpenflowType.Hello: None,
        OpenflowType.Error: OpenflowError,
        OpenflowType.EchoRequest: OpenflowEchoRequest,
        OpenflowType.EchoReply: OpenflowEchoReply,
        OpenflowType.Vendor: OpenflowVendor,
        OpenflowType.FeaturesRequest: None,
        OpenflowType.FeaturesReply: OpenflowSwitchFeaturesReply,
        OpenflowType.GetConfigRequest: None,
        OpenflowType.GetConfigReply: OpenflowGetConfigReply,
        OpenflowType.SetConfig: OpenflowSetConfig,
        OpenflowType.PacketIn: OpenflowPacketIn,
        OpenflowType.FlowRemoved: OpenflowFlowRemoved,
        OpenflowType.PortStatus: OpenflowPortStatus,
        OpenflowType.PacketOut: OpenflowPacketOut,
        OpenflowType.FlowMod: OpenflowFlowMod,
        OpenflowType.PortMod: OpenflowPortMod,
        OpenflowType.StatsRequest: _OpenflowStatsRequest,
        OpenflowType.StatsReply: _OpenflowStatsReply,
        OpenflowType.BarrierRequest: None,
        OpenflowType.BarrierReply: None,
        OpenflowType.QueueGetConfigRequest: OpenflowQueueGetConfigRequest,
        OpenflowType.QueueGetConfigReply: OpenflowQueueGetConfigReply,
    }

    def __init__(self, xtype=OpenflowType.Hello, xid=0, version=0x01):
        '''
        ofp_header struct from Openflow v1.0.0 spec.
        '''
        self._version = version
        self._type = xtype
        self._length = OpenflowHeader._MINLEN
        self._xid = xid
        self._subtype = None

    @staticmethod
    def build(xtype, *args, xid=0, version=0x01):
        pkt = Packet()
        header = OpenflowHeader(xtype=xtype, xid=xid, version=version)
        pkt += header
        clsname = OpenflowHeader._OpenflowTypeClasses.get(xtype)
        if clsname is not None:
            pkt += clsname(*args)
        return pkt

    @property
    def xid(self):
        return self._xid

    @xid.setter
    def xid(self, value):
        self._xid = int(value)

    @property
    def version(self):
        return self._version

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = OpenflowType(value)

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        self._length = int(value)

    def from_bytes(self, raw):
        if len(raw) < OpenflowHeader._MINLEN:
            raise Exception("Not enough bytes to unpack Openflow header;"
                            " need {}, only have {}".format(OpenflowHeader._MINLEN,
                                                            len(raw)))
        fields = struct.unpack(
            OpenflowHeader._PACKFMT, raw[:OpenflowHeader._MINLEN])
        self._version = fields[0]
        self.type = fields[1]
        self.length = fields[2]
        self.xid = fields[3]
        raw = raw[OpenflowHeader._MINLEN:]
        if self.type == OpenflowType.StatsRequest or self.type == OpenflowType.StatsReply:
            if len(raw) >= 2: # JS??     
                (statstype,) = struct.unpack('!H', raw[:2])
                self._subtype = OpenflowStatsType(statstype)
        return raw

    def to_bytes(self):
        return struct.pack(OpenflowHeader._PACKFMT, self._version,
                           self._type.value, self._length, self._xid)

    def size(self):
        return OpenflowHeader._MINLEN

    def next_header_class(self):
        hdrcls = OpenflowHeader._OpenflowTypeClasses.get(self.type, None)
        if self.type == OpenflowType.StatsRequest or \
           self.type == OpenflowType.StatsReply and \
           self._subtype is not None:

            clsname = "{}{}".format(self._subtype.name, self.type.name)
            cls = globals()[clsname]
            return cls

        return hdrcls

    def pre_serialize(self, raw, pkt, i):
        '''
        Set length of the header based on
        '''
        self.length = len(raw) + OpenflowHeader._MINLEN

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        return '{} xid={} len={}'.format(self.type.name,
                                         self.xid, self.length)
