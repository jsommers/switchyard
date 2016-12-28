import struct
from enum import IntEnum
from abc import ABCMeta, abstractmethod

from .packet import PacketHeaderBase,Packet
from .common import checksum
from ..exceptions import *

'''
References:
    IETF RFCs 675, 793, 1122, 2581, 3540, 5681
'''

class TCPOption(metaclass=ABCMeta):
    @abstractmethod
    def to_bytes(self):
        pass

    @abstractmethod
    def from_bytes(self, raw):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

# EndOfOptions, Padding, MaxSegmentSize, WindowScaling, SACK, Timestamp, AltChecksum

class TCPOptions(PacketHeaderBase):
    __slots__ = ['_optlist']
    def __init__(self, **kwargs):
        self._optlist = []
        super().__init__(**kwargs)

    def size(self):
        return len(self.to_bytes())

    def next_header_class(self):
        return

    def pre_serialize(self, raw, pkt, i):
        return

    def __eq__(self, other):
        if self.size() != other.size():
            return False
        return True  # FIXME

    def to_bytes(self):
        return b''.join([opt.to_bytes() for opt in self._optlist])

    def from_bytes(self, raw):
        # FIXME
        return 0

class TCPFlags(IntEnum):
    FIN = 0
    SYN = 1
    RST = 2
    PSH = 3
    ACK = 4
    URG = 5
    ECE = 6 # ECN-echo RFC 3168
    CWR = 7 # Congestion-window reduced RFC 3168
    NS =  8 # ECN-nonce concealment protection RFC 3540

class TCP(PacketHeaderBase):
    __slots__ = ['_src','_dst','_seq','_ack',
        '_flags','_window','_urg','_options','_len', '_checksum']
    _PACKFMT = '!HHIIHHHH'
    _MINLEN = struct.calcsize(_PACKFMT)
    _next_header_map = {}
    _next_header_class_key = ''

    def __init__(self, **kwargs):
        self.src = self.dst = 0
        self.seq = self.ack = 0
        self._flags = 0x000
        self.window = 0
        self.urgent_pointer = 0
        self._options = TCPOptions()
        self._checksum = 0
        self._len = 0
        super().__init__(**kwargs)

    def size(self):
        return struct.calcsize(TCP._PACKFMT)

    def _compute_checksum_ipv4(self, ip4, xdata):
        if ip4 is None:
            return 0
        phdr = struct.pack('!IIxBH', int(ip4.src), int(ip4.dst), 
            ip4.protocol.value, self._len)
        tcphdr = self._make_header(0)
        return checksum(phdr + tcphdr + xdata)

    def pre_serialize(self, raw, pkt, i):
        self._len = self.size() + len(raw)
        # checksum calc currently assumes we're only dealing with ipv4.
        # will need to be modified for ipv6 support...
        self._checksum = self._compute_checksum_ipv4(pkt.get_header_by_name('IPv4'), raw)

    def _make_header(self, csum):
        offset_flags = self.offset << 12 | self._flags
        header = struct.pack(TCP._PACKFMT, self.src, self.dst,
            self.seq, self.ack, offset_flags, self.window,
            csum, self.urgent_pointer)
        return header

    def to_bytes(self):
        '''
        Return packed byte representation of the TCP header.
        '''
        header = self._make_header(self._checksum)
        return header + self._options.to_bytes()

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < TCP._MINLEN:
            raise NotEnoughDataError("Not enough bytes ({}) to reconstruct an TCP object".format(len(raw)))
        fields = struct.unpack(TCP._PACKFMT, raw[:TCP._MINLEN])
        self._src = fields[0]
        self._dst = fields[1]
        self._seq = fields[2]        
        self._ack = fields[3]
        offset = fields[4] >> 12
        self._flags = fields[4] & 0x01ff
        self._window = fields[5]
        csum = fields[6]
        self._urg = fields[7]
        headerlen = offset * 4
        optlen = headerlen - TCP._MINLEN
        self._options.from_bytes(raw[TCP._MINLEN:headerlen])
        return raw[headerlen:]

    def __eq__(self, other):
        return self.src == other.src and \
            self.dst == other.dst and \
            self.seq == other.seq and \
            self.ack == other.ack and \
            self.offset == other.offset and \
            self.flags == other.flags and \
            self.window == other.window and \
            self.urgent_pointer == other.urgent_pointer and \
            self.options == other.options

    @property
    def offset(self):
        return TCP._MINLEN // 4 + len(self._options.to_bytes()) // 4

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @src.setter
    def src(self,value):
        self._src = value

    @dst.setter
    def dst(self,value):
        self._dst = value

    def __str__(self):
        return '{} {}->{} ({} {}:{})'.format(self.__class__.__name__, 
            self.src, self.dst, self.flagstr, self.seq, self.ack)

    @property
    def seq(self):
        return self._seq

    @seq.setter
    def seq(self, value):
        self._seq = value

    @property
    def ack(self):
        return self._ack

    @ack.setter
    def ack(self, value):
        self._ack = value

    @property
    def window(self):
        return self._window

    @window.setter
    def window(self, value):
        self._window = value

    @property 
    def checksum(self):
        return self._checksum

    @property
    def flags(self):
        return self._flags

    @property
    def flagstr(self):
        flist = []
        for f in range(9):
            if self._isset(f):
                flist.append(TCPFlags(f).name[0])
        return "".join(flist)

    @property
    def urgent_pointer(self):
        return self._urg

    @urgent_pointer.setter
    def urgent_pointer(self, value):
        self._urg = value

    @property
    def options(self):
        return self._options

    def _isset(self, flag):
        if isinstance(flag, int):
            flag = TCPFlags(flag)
        mask = 0x01 << flag.value 
        return (self._flags & mask) == mask

    def _setflag(self, flag, value):
        mask = 0x01 << flag.value 
        if value:
            self._flags = self._flags | mask
        else:
            self._flags = self._flags & ~mask

    @property
    def NS(self):
        return self._isset(TCPFlags.NS)

    @NS.setter
    def NS(self, value):
        self._setflag(TCPFlags.NS, value)

    @property
    def CWR(self):
        return self._isset(TCPFlags.CWR)

    @CWR.setter
    def CWR(self, value):
        self._setflag(TCPFlags.CWR, value)

    @property
    def ECE(self):
        return self._isset(TCPFlags.ECE)

    @ECE.setter
    def ECE(self, value):
        self._setflag(TCPFlags.ECE, value)

    @property
    def URG(self):
        return self._isset(TCPFlags.URG)

    @URG.setter
    def URG(self, value):
        self._setflag(TCPFlags.URG, value)

    @property
    def ACK(self):
        return self._isset(TCPFlags.ACK)

    @ACK.setter
    def ACK(self, value):
        self._setflag(TCPFlags.ACK, value)

    @property
    def PSH(self):
        return self._isset(TCPFlags.PSH)

    @PSH.setter
    def PSH(self, value):
        self._setflag(TCPFlags.PSH, value)

    @property
    def RST(self):
        return self._isset(TCPFlags.RST)

    @RST.setter
    def RST(self, value):
        self._setflag(TCPFlags.RST, value)

    @property
    def SYN(self):
        return self._isset(TCPFlags.SYN)

    @SYN.setter
    def SYN(self, value):
        self._setflag(TCPFlags.SYN, value)

    @property
    def FIN(self):
        return self._isset(TCPFlags.FIN)

    @FIN.setter
    def FIN(self, value):
        self._setflag(TCPFlags.FIN, value)
