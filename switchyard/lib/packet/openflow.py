from switchyard.lib.packet.packet import PacketHeaderBase
from enum import Enum
import struct

class OpenflowType(Enum):
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

class OpenflowPort(Enum):
    Max = 0xff00
    InPort = 0xfff8
    Table = 0xfff9
    Normal = 0xfffa
    Flood = 0xfffb
    All = 0xfffc
    Controller = 0xfffd
    Local = 0xfffe
    NoPort = 0xffff # Can't use None!

class OpenflowPortState(Enum):
    LinkDown = 1 << 0
    StpListen = 0 << 8
    StpLearn = 1 << 8
    StpForward = 2 << 8
    StpBlock = 3 << 8
    StpMask = 3 << 8

class OpenflowPortConfig(Enum):
    Down = 1 << 0
    NoStp = 1 << 1
    NoRecv = 1 << 2
    NoRecvStp = 1 << 3
    NoFlood = 1 << 4
    NoFwd = 1 << 5
    NoPacketIn = 1 << 6

class OpenflowPortFeatures(Enum):
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

class OpenflowStruct(PacketHeaderBase):
    pass

class OpenflowPhysicalPort(OpenflowStruct):
    __slots__ = ['_portnum','_hwaddr','_name','_config',
                 '_state','_curr','_advertised','_supported','_peer']
    _PACKFMT = '!H6s16sIIIIII'
    _MINLEN = struct.calcsize(_PACKFMT)
    

class OpenflowPacketQueue(OpenflowStruct):
    __slots__ = ['_queue_id', '_properties']
    _PACKFMT = '!IHxx'
    _MINLEN = struct.calcsize(_PACKFMT)

class OpenflowQueuePropertyTypes(Enum):
    NoProperty = 0
    MinRate = 1

class OpenFlowQueueMinRateProperty(OpenflowStruct):
    __slots__ = ['_rate']
    _PACKFMT = '!HH4xH6x'
    _MINLEN = struct.calcsize(_PACKFMT)

OpenflowTypeClasses = {}

class OpenflowMatch(OpenflowStruct):
    __slots__ = ['wildcards','_in_port','_dl_src','_dl_dst',
                 '_dl_vlan','_dl_vlan_pcp','_dl_type',
                 '_nw_tos','_nw_proto','_nw_src','_nw_dst',
                 '_tp_src','_tp_dst']
    _PACKFMT = '!IH6s6sHBxHBB2xIIHH'        
    _MINLEN = struct.calcsize(_PACKFMT)

class OpenflowWildcards(Enum):
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
    NwSrcAll = 32 << 8

    NwDstMask = ((1 << 6) - 1) << 14
    NwDstAll = 32 << 14

    DlVlanPcp = 1 << 20
    NwTos = 1 << 21
    All = ((1 << 22) - 1)

class OpenflowActionType(Enum):
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

class OpenflowSwitchFeatures(PacketHeaderBase):
    '''
    Switch features response message, not including the header.
    '''
    __slots__ = ['_dpid','_nbuffers','_ntables','_capabilities',
                 '_actions', '_ports' ]
    _PACKFMT = '!QIBxxxII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        PacketHeaderBase.__init__(self)
        self._dpid = 0
        self._nbuffers = 0
        self._ntables = 0
        self._capabilities = 0
        self._actions = 0
        self._ports = []


class OpenflowHeader(PacketHeaderBase):
    '''
    Standard 8 byte header for all Openflow packets.
    This is the entire packet for:
      Hello
      FeaturesRequest

    '''
    __slots__ = ['_version','_type','_length','_xid']
    _PACKFMT = '!BBHI'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        '''
        ofp_header struct from Openflow v1.0.0 spec.
        '''
        PacketHeaderBase.__init__(self)
        self._version = 0x01
        self._type = OpenflowType.Hello
        self._length = OpenflowHeader._MINLEN
        self._xid = 0

    @property  
    def xid(self):
        return self._xid

    @xid.setter
    def xid(self, value):
        self._xid = int(value)

    @property 
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = OpenflowType(value)

    def from_bytes(self, raw):
        if len(raw) < OpenflowHeader._MINLEN:
            raise Exception("Not enough bytes to unpack Openflow header; need {}, only have {}".format(Openfl._MINLEN, len(raw)))
        fields = struct.unpack(OpenflowHeader._PACKFMT, raw[:OpenflowHeader._MINLEN])
        self.version = fields[0]
        self.type = fields[1]
        self.length = fields[2]
        self.xid = fields[3]
        return raw[OpenflowHeader._MINLEN:]

    def to_bytes(self):
        return struct.pack(OpenflowHeader._PACKFMT, self._version, self._type.value, self._length, self._xid)

    def __eq__(self, other):
        return self.version == other.version and \
            self.type == other.type and \
            self.length == other.length and \
            self.xid == other.xid

    def size(self):
        return OpenflowHeader._MINLEN

    def pre_serialize(self, raw, pkt, i):
        pass

    def next_header_class(self):
        return OpenflowTypeClasses[self._type]

    def __str__(self):
        return '{} {} {} {}'.format(self.__class__.__name__, self.type.name, self.xid, self.length)