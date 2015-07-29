from switchyard.lib.packet import PacketHeaderBase, Packet, IPProtocol, EtherType
from switchyard.lib.address import EthAddr, IPv4Address
from switchyard.lib.common import log_debug
from enum import Enum, IntEnum
import struct

def _make_bitmap(xset):
    val = 0x00000000
    for enumval in xset:
        val |= enumval.value
    return val

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

class OpenflowPort(IntEnum):
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

    def pre_serialize(self, *args):
        pass

class OpenflowPhysicalPort(_OpenflowStruct):
    __slots__ = ['_portnum','_hwaddr','_name','_config',
                 '_state','_curr','_advertised','_supported','_peer']
    _PACKFMT = '!H6s16sIIIIII'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, portnum=0, hwaddr='', name=''):
        _OpenflowStruct.__init__(self)
        self._portnum = portnum
        if hwaddr:
            self._hwaddr = EthAddr(hwaddr)
        else:
            self._hwaddr = EthAddr()
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
        self.name = fields[2].decode('utf8')
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
    __slots__ = ['_wildcards', '_nwsrc_wildcard','_nwdst_wildcard',
                 '_in_port','_dl_src','_dl_dst',
                 '_dl_vlan','_dl_vlan_pcp','_dl_type',
                 '_nw_tos','_nw_proto','_nw_src','_nw_dst',
                 '_tp_src','_tp_dst']
    _PACKFMT = '!IH6s6sHBxHBB2x4s4sHH'        
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self):
        _OpenflowStruct.__init__(self)
        self._wildcards = set()
        self._in_port = 0
        self._dl_src = EthAddr()
        self._dl_dst = EthAddr()
        self._dl_vlan = 0
        self._dl_vlan_pcp = 0
        self._dl_type = EtherType.IP
        self._nw_tos = 0
        self._nw_proto = IPProtocol.ICMP
        self._nwsrc_wildcard = 0
        self._nwdst_wildcard = 0
        self._nw_src = IPv4Address(0)
        self._nw_dst = IPv4Address(0)
        self._tp_src = 0
        self._tp_dst = 0

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
        fields = struct.unpack(OpenflowMatch._PACKFMT, raw[:OpenflowMatch._MINLEN])
        self._wildcards = set()
        if fields[0] == OpenflowWildcards.All.value:
            self.wildcard_all()
            self.nwsrc_wildcard = 32
            self.nwdst_wildcard = 32
        else:            
            for v in OpenflowWildcards:
                if not v.name.endswith('All') and \
                   not v.name.endswith('Mask') and \
                   v.value & fields[0] != 0:
                    self.add_wildcard(v)

            # set nwsrc_wildcard, nwdst_wildcard
            nwsrcbits = (fields[0] & OpenflowWildcards.NwSrcMask.value) >> 8
            self.nwsrc_wildcard = nwsrcbits
            nwdstbits = (fields[0] & OpenflowWildcards.NwDstMask.value) >> 14
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

    def overlaps(self, othermatch):
        '''
        Return True if this match overlaps with othermatch.  False
        otherwise.
        '''
        overlap = True
        attrs = set(self.__slots__)
        attrs.discard('_wildcards')
        attrs.discard('_nwsrc_wildcard')
        attrs.discard('_nwdst_wildcard')
        for x in attrs:
            print (x)

        return overlap

    # def match_packet(self, packet):
    #     '''
    #     Does the packet match the elements in this structure?
    #     Return True if so, False otherwise.
    #     '''
    #     # FIXME
    #     null = NullPacketHeader()
    #     header = packet.get_header(IPv4, null)

    @property 
    def wildcards(self):
        wcards = []
        wcards.append("NwSrc:{}".format(self.nwsrc_wildcard))
        wcards.append("NwDst:{}".format(self.nwdst_wildcard))
        wcards.extend([w.name for w in self._wildcards])
        return wcards

    def add_wildcard(self, value):
        value = OpenflowWildcards(value)
        self._wildcards.add(value)

    def reset_wildcards(self):
        self._wildcards = set()

    def remove_wildcard(self, value):
        self._wildcards.discard(value)

    def wildcard_all(self):
        self._wildcards = set([OpenflowWildcards.All])

    @property
    def nwsrc_wildcard(self):
        return self._nwsrc_wildcard

    @nwsrc_wildcard.setter
    def nwsrc_wildcard(self, value):
        value = max(0, int(value))
        value = min(32, value)
        self._nwsrc_wildcard = value

    @property
    def nwdst_wildcard(self):
        return self._nwsrc_wildcard

    @nwdst_wildcard.setter
    def nwdst_wildcard(self, value):
        value = max(0, int(value))
        value = min(32, value)
        self._nwdst_wildcard = value

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
        self._nw_dst = IPv4Address(value)

    @property 
    def tp_src(self):
        return self._tp_src

    @tp_src.setter
    def tp_src(self, value):
        value = int(value)
        if value < 0 or value >= 2**16:
            raise ValueError("Invalid transport layer src {}".format(value))
        self._tp_src = value

    @property 
    def tp_dst(self):
        return self._tp_dst

    @tp_dst.setter
    def tp_dst(self, value):
        value = int(value)
        if value < 0 or value >= 2**16:
            raise ValueError("Invalid transport layer dst {}".format(value))
        self._tp_dst = value

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
    NwDstMask = ((1 << 6) - 1) << 14
    DlVlanPcp = 1 << 20
    NwTos = 1 << 21

    NwSrcAll = 32 << 8
    NwDstAll = 32 << 14
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

class OpenflowConfigFlags(Enum):
    FragNormal = 0
    FragDrop = 1
    FragReasm = 2
    FragMask = 3

class OpenflowSetConfig(_OpenflowStruct):
    __slots__ = ['_flags','_miss_send_len']
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self):
        _OpenflowStruct.__init__(self)
        self._flags = OpenflowConfigFlags.FragNormal
        self._miss_send_len = 1500

    def to_bytes(self):
        return struct.pack(OpenflowSetConfig._PACKFMT, self._flags.value, self._miss_send_len)

    def from_bytes(self, raw):
        if len(raw) < OpenflowSetConfig._MINLEN:
            raise Exception("Not enough bytes to unpack OpenflowSetConfig message")
        fields = struct.unpack(OpenflowSetConfig._PACKFMT, raw[:OpenflowSetConfig._MINLEN])
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
        
class OpenflowFlowMod(_OpenflowStruct):
    '''
    Flowmod message
    '''
    __slots__ = ['_match','_cookie','_command','_idle_timeout',
                 '_hard_timeout','_priority','_buffer_id','_out_port'
                 '_flags','_actions']
    # packfmt doesn't include match struct or actions
    # those are defined within other structures
    _PACKFMT = '!QHHHHIHH'
    _MINLEN = OpenflowMatch.size() + struct.calcsize(_PACKFMT) 

    def __init__(self, match=None):
        _OpenflowStruct.__init__(self)
        if match is None:
            match = OpenflowMatch
        self._match = match
        self._cookie = 0
        self._command = 0
        self._idle_timeout = 0
        self._hard_timeout = 0
        self._priority = 0
        self._buffer_id = 0
        self._out_port = 0
        self._flags = 0
        self._actions = []

    def to_bytes(self):
        return self._match.to_bytes() + \
               struct.pack(OpenflowFlowMod._PACKFMT, self._cookie, self._command.value,
               	self._idle_timeout, self._hard_timeout, self._priority, self._buffer_id,
               	self._out_port, self._flags) + \
               b''.join(a.to_bytes() for a in self._actions)

    def from_bytes(self, raw):
        pass

    def size(self):
    	return len(self.to_bytes())
        

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
        return _make_bitmap(self._capabilities)

    @capabilities.setter
    def capabilities(self, value):
        if isinstance(value, int): 
            value = OpenflowCapabilities(value)
        if not isinstance(value, OpenflowCapabilities):
            raise ValueError("Set value must be of type OpenflowCapabilities")
        self._capabilities.add(value)

    def reset_capabilities(self):
        self._capabilities = set()

    @property 
    def actions(self):
        return _make_bitmap(self._actions)

    @actions.setter
    def actions(self, value):
        if isinstance(value, int): 
            value = OpenflowActionTypes(value)
        if not isinstance(value, OpenflowActionTypes):
            raise ValueError("Set value must be of type OpenflowActionTypes")
        self._actions.add(value)

    def reset_actions(self):
        self._actions = set()

    @property 
    def ports(self):
        return self._ports

class OpenflowErrorType(Enum):
    HelloFailed = 0
    BadRequest = 1
    BadAction = 2
    FlowModFailed = 3
    PortModFailed = 4
    QueueOpFailed = 5

class OpenflowErrorCode(Enum):
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


class OpenflowError(_OpenflowStruct):
    __slots__ = ('_type','_code','_data')
    _PACKFMT = '!HH'
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self):
        _OpenflowStruct.__init__(self)
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

class OpenflowVendor(_OpenflowStruct):
    __slots__ = ('_vendor','_data')
    _PACKFMT = '!I'
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self):
        _OpenflowStruct.__init__(self)
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

class OpenflowPacketInReason(Enum):
    NoMatch = 0
    Action = 1
    NoReason = 0xff

class OpenflowPacketIn(_OpenflowStruct):
    __slots__ = ('_buffer_id','_in_port','_reason', '_data')
    _PACKFMT = '!IHHBx'
    _MINLEN = struct.calcsize(_PACKFMT)
    def __init__(self):
        _OpenflowStruct.__init__(self)
        self._buffer_id = -1
        self._in_port = OpenflowPort.NoPort
        self._reason = OpenflowPacketInReason.NoReason
        self._data = b''

    def size(self):
        return OpenflowPacketIn._MINLEN + len(self.data)

    def to_bytes(self):
        totallen = len(self.data) + OpenflowPacketIn._MINLEN + OpenflowHeader._MINLEN
        return struct.pack(OpenflowPacketIn._PACKFMT, self.buffer_id,
                           self._total_len, self.in_port, 
                           self.reason.value) + self.data

    def from_bytes(self, raw):
        if len(raw) < OpenflowPacketIn._MINLEN:
            raise Exception("Not enough data to unpack OpenflowPacketIn")
        fields = struct.unpack(OpenflowPacketIn._PACKFMT, raw[:OpenflowPacketIn._MINLEN])
        self.buffer_id = fields[0]
        self.in_port = fields[2]
        self.reason = fields[3]
        self.data = raw[OpenflowPacketIn._MINLEN:]

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
        value = int(value) 
        try:
            self._in_port = OpenflowPort(value)
        except ValueError:
            if 0 <= value < OpenflowPort.Max:
                self._in_port = value
            else:
                raise ValueError("Invalid port number")

    @property 
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = OpenflowPacketInReason(value)

    @property 
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = bytes(value)

class OpenflowFlowRemoved(_OpenflowStruct):
    __slots__ = ('_match','_cookie','_priority','_reason',
                 '_duration_sec','_duration_nsec','_idle_timeout',
                 '_packet_count','_byte_count')
    _PACKFMT = '!QHBxIIH2xQQ'
    _MINLEN = struct.calcsize(_PACKFMT)


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
        # OpenflowType.PortStatus: OpenflowPortStatus,
        # OpenflowType.PacketOut: OpenflowPacketOut,
        OpenflowType.FlowMod: OpenflowFlowMod,
        # OpenflowType.PortMod: OpenflowPortMod,
        # OpenflowType.StatsRequest: OpenflowStatsRequest,
        # OpenflowType.StatsReply: OpenflowStatsReply,
        OpenflowType.BarrierRequest: None,
        OpenflowType.BarrierReply: None,
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
        self.length = len(raw) + OpenflowHeader._MINLEN

    def __eq__(self, other):
        return self.to_bytes() == other.to_bytes()

    def __str__(self):
        return '{} xid={} len={}'.format(self.type.name, 
            self.xid, self.length)

def send_openflow_message(sock, pkt):
    log_debug("Sending Openflow message {} ({} bytes)".format(pkt, len(pkt)))
    sock.sendall(pkt.to_bytes())

def receive_openflow_message(sock):
    ofheader = OpenflowHeader()
    data = sock.recv(ofheader.size())
    ofheader.from_bytes(data)
    log_debug("Attempting to receive Openflow message (header: {}) ({} bytes)".format(ofheader, ofheader.length))

    remain = ofheader.length - ofheader.size()
    while remain > 0:
        more = sock.recv(remain)
        data += more
        remain -= len(more)
    p = Packet.from_bytes(data, OpenflowHeader)
    return p
