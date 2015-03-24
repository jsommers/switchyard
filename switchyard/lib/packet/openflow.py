from switchyard.lib.packet.packet import PacketHeaderBase, Packet
from switchyard.lib.address import EthAddr
from enum import Enum
import struct

OpenflowTypeClasses = {}

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
    NoState = 0
    LinkDown = 1 << 0
    StpListen = 0 << 8
    StpLearn = 1 << 8
    StpForward = 2 << 8
    StpBlock = 3 << 8
    StpMask = 3 << 8

class OpenflowPortConfig(Enum):
    NoConfig = 0
    Down = 1 << 0
    NoStp = 1 << 1
    NoRecv = 1 << 2
    NoRecvStp = 1 << 3
    NoFlood = 1 << 4
    NoFwd = 1 << 5
    NoPacketIn = 1 << 6

class OpenflowPortFeatures(Enum):
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

class OpenflowCapabilities(Enum):
    NoCapabilities = 0
    FlowStats = 1 << 0
    TableStats = 1 << 1
    PortStats = 1 << 2
    Stp = 1 << 3
    Reserved = 1 << 4
    IpReasm = 1 << 5
    QueueStats = 1 << 6
    ArpMatchIp = 1 << 7


class _OpenflowStruct(PacketHeaderBase):
    def __init__(self):
        PacketHeaderBase.__init__(self)

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def next_header_class(self):
        pass

    def pre_serialize(self):
        pass

class OpenflowPhysicalPort(_OpenflowStruct):
    __slots__ = ['_portnum','_hwaddr','_name','_config',
                 '_state','_curr','_advertised','_supported','_peer']
    _PACKFMT = '!H6s16sIIIIII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, portnum=0, hwaddr='', name=''):
        _OpenflowStruct.__init__(self)
        self._portnum = portnum
        self._hwaddr = EthAddr(hwaddr)
        self._name = name
        self._config = OpenflowPortConfig.NoConfig
        self._state = OpenflowPortState.NoState
        self._curr = 0
        self._advertised = 0
        self._supported = 0
        self._peer = 0

    def to_bytes(self):
        return struct.pack(OpenflowPhysicalPort._PACKFMT,
                           self._portnum, self._hwaddr.raw, self._name.encode('utf8'),
                           self._config.value, self._state.value, self._curr,
                           self._advertised, self._supported, self._peer)

    def from_bytes(self, raw):
        if len(raw) < OpenflowPhysicalPort._MINLEN:
            raise Exception("Not enough raw data to unpack OpenflowPhysicalPort object")
        fields = struct.unpack(OpenflowPhysicalPort._PACKFMT, raw[:OpenflowPhysicalPort._MINLEN])        
        self.portnum = fields[0]
        self.hwaddr = fields[1]
        self.name = fields[2]
        self.config = fields[3]
        self.state = fields[4]
        self.curr = fields[5]
        self.advertised = fields[6]
        self.supported = fields[7]
        self.peer = fields[8]
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
        return self._config

    @config.setter
    def config(self, value):
        pass


class OpenflowPacketQueue(_OpenflowStruct):
    __slots__ = ['_queue_id', '_properties']
    _PACKFMT = '!IHxx'
    _MINLEN = struct.calcsize(_PACKFMT)

class OpenflowQueuePropertyTypes(Enum):
    NoProperty = 0
    MinRate = 1

class OpenFlowQueueMinRateProperty(_OpenflowStruct):
    __slots__ = ['_rate']
    _PACKFMT = '!HH4xH6x'
    _MINLEN = struct.calcsize(_PACKFMT)

class OpenflowMatch(_OpenflowStruct):
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

class OpenflowActionTypes(Enum):
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


class OpenflowEchoRequest(_OpenflowStruct):
    __slots__ = ['_data']
    def __init__(self):
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

class OpenflowSwitchFeaturesReply(_OpenflowStruct):
    '''
    Switch features response message, not including the header.
    '''
    __slots__ = ['_dpid','_nbuffers','_ntables','_capabilities',
                 '_actions', '_ports' ]
    _PACKFMT = '!8sIBxxxII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        self.dpid = b'\x00' * 8
        self.nbuffers = 0
        self.ntables = 1
        self._capabilities = set()
        self._actions = set()
        self._ports = []

    @staticmethod
    def _make_bitmap(xset):
        val = 0x00000000
        for enumval in xset:
            val |= enumval.value
        return val

    def to_bytes(self):
        rawpkt = struct.pack(OpenflowSwitchFeaturesReply._PACKFMT,
            self._dpid, self._nbuffers, self._ntables, 
            self.capabilities, self.actions)
        for p in self._ports:
            rawpkt += p.to_bytes()
        return rawpkt

    def from_bytes(self, raw):
        if len(raw) < OpenflowSwitchFeaturesReply._MINLEN:
            raise Exception("Not enough data to unpack OpenflowSwitchFeaturesReply message")
        fields = struct.unpack(OpenflowSwitchFeaturesReply._PACKFMT, 
                               raw[:OpenflowSwitchFeaturesReply._MINLEN])
        self.dpid = fields[0]
        self.nbuffers = fields[1]
        self.ntables = fields[2]

        # FIXME
        # OpenflowCapabilities
        for v in OpenflowCapabilities:
            if v.value & fields[3] == 1:
                self.capabilities = v
        # self.capabilities = fields[3]
        for a in OpenflowActionTypes:
            if a.value & fields[4] == 1:
                self.actions = a
        # self.actions = fields[4]

        remain = raw[OpenflowSwitchFeaturesReply._MINLEN:]
        p = OpenflowPhysicalPort()
        while remain >= p.size():
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
        self._dpid = b'\x00' * (8-len(value)) + value

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
            raise ValueError("Setting low-order 48 bits of dpid must be done with EthAddr or bytes")

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
            raise ValueError("Setting high-order 16 bits of dpid must be done with bytes")

    @property 
    def nbuffers(self):
        return self._nbuffers

    @nbuffers.setter
    def nbuffers(self, value):
        value = int(value)
        if 0 <= value < 2**32:
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
        return self._make_bitmap(self._capabilities)

    @capabilities.setter
    def capabilities(self, value):
        if isinstance(value, int): 
            value = OpenflowCapabilities(value)
        if not isinstance(value, OpenflowCapabilities):
            raise ValueError("Set value must be of type OpenflowCapabilities")
        self._capabilities.add(value)

    @property 
    def actions(self):
        return self._make_bitmap(self._actions)

    @actions.setter
    def actions(self, value):
        if isinstance(value, int): 
            value = OpenflowActionTypes(value)
        if not isinstance(value, OpenflowActionTypes):
            raise ValueError("Set value must be of type OpenflowActionTypes")
        self._actions.add(value)

    @property 
    def ports(self):
        return self._ports


class OpenflowHeader(PacketHeaderBase):
    '''
    Standard 8 byte header for all Openflow packets.
    This is a mostly-internal class used by the various
    OpenflowMessage type classes.
    '''
    __slots__ = ['_version','_type','_length','_xid']
    _PACKFMT = '!BBHI'
    _MINLEN = struct.calcsize(_PACKFMT)
    _OpenflowTypeClasses = {
        OpenflowType.Hello: None,
        # OpenflowType.Error: OpenflowError,
        OpenflowType.EchoRequest: OpenflowEchoRequest,
        OpenflowType.EchoReply: OpenflowEchoReply,
        # OpenflowType.Vendor: OpenflowVendor,
        OpenflowType.FeaturesRequest: None,
        OpenflowType.FeaturesReply: OpenflowSwitchFeaturesReply,
        # OpenflowType.GetConfigRequest: OpenflowGetConfigRequest,
        # OpenflowType.GetConfigReply: OpenflowGetConfigReply,
        # OpenflowType.SetConfig: OpenflowSetConfig,
        # OpenflowType.PacketIn: OpenflowPacketIn,
        # OpenflowType.FlowRemoved: OpenflowFlowRemoved,
        # OpenflowType.PortStatus: OpenflowPortStatus,
        # OpenflowType.PacketOut: OpenflowPacketOut,
        # OpenflowType.FlowMod: OpenflowFlowMod,
        # OpenflowType.PortMod: OpenflowPortMod,
        # OpenflowType.StatsRequest: OpenflowStatsRequest,
        # OpenflowType.StatsReply: OpenflowStatsReply,
        # OpenflowType.BarrierRequest: OpenflowBarrierRequest,
        # OpenflowType.BarrierReply: OpenflowBarrierReply,
        # OpenflowType.QueueGetConfigRequest: OpenflowQueueGetConfigRequest,
        # OpenflowType.QueueGetConfigReply: OpenflowQueueGetConfigReply,
    }

    def __init__(self, xtype = OpenflowType.Hello, xid = 0):
        '''
        ofp_header struct from Openflow v1.0.0 spec.
        '''
        self._version = 0x01
        self._type = xtype
        self._length = OpenflowHeader._MINLEN
        self._xid = xid

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
        fields = struct.unpack(OpenflowHeader._PACKFMT, raw[:OpenflowHeader._MINLEN])
        self._version = fields[0]
        self.type = fields[1]
        self.length = fields[2]
        self.xid = fields[3]
        return raw[OpenflowHeader._MINLEN:]

    def to_bytes(self):
        return struct.pack(OpenflowHeader._PACKFMT, self._version, 
            self._type.value, self._length, self._xid)

    def size(self):
        return OpenflowHeader._MINLEN

    def next_header_class(self):
        hdrcls = OpenflowHeader._OpenflowTypeClasses.get(self.type, None)
        return hdrcls

    def pre_serialize(self, raw, pkt, i):
        '''
        Set length of the header based on
        '''
        self._header.length = len(raw) + OpenflowHeader._MINLEN

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        return '{} xid={} len={}'.format(self.header.type.name, 
            self.header.xid, self.header.length)

def send_openflow_message(sock, pkt):
    sock.sendall(pkt.to_bytes())

def receive_openflow_message(sock):
    ofheader = OpenflowHeader()
    data = sock.recv(ofheader.size())
    ofheader.from_bytes(data)
    remain = ofheader.length - ofheader.size()
    while remain > 0:
        more = sock.recv(remain)
        data += more
        remain -= len(more)
    p = Packet.from_bytes(data, OpenflowHeader)
    return p
