from switchyard.lib.packet.packet import PacketHeaderBase,Packet
import struct
from enum import Enum
from abc import ABCMeta, abstractmethod

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
    __slots__ = ['__optlist']
    def __init__(self):
        super().__init__()
        self.__optlist = []

    def size(self):
        return len(self.to_bytes())

    def next_header_class(self):
        return

    def tail_serialized(self):
        return

    def __eq__(self, other):
        if self.size() != other.size():
            return False
        return True  # FIXME

    def to_bytes(self):
        return b''.join([opt.to_bytes() for opt in self.__optlist])

    def from_bytes(self, raw):
        # FIXME
        return 0

class TCPFlags(Enum):
    FIN = 1
    SYN = 2
    RST = 3
    PSH = 4
    ACK = 5
    URG = 6
    ECE = 7 # ECN-echo RFC 3168
    CWR = 8 # Congestion-window reduced RFC 3168
    NS =  9 # ECN-nonce concealment protection RFC 3540

class TCP(PacketHeaderBase):
    __slots__ = ['__srcport','__dstport','__seq','__ack',
        '__flags','__window','__urg','__options']
    __PACKFMT__ = '!HHIIHHHH'
    __MINSIZE__ = struct.calcsize(__PACKFMT__)

    def __init__(self):
        self.srcport = self.dstport = 0
        self.seq = self.ack = 0
        self.__flags = 0x000
        self.window = 0
        self.urgent_pointer = 0
        self.__options = TCPOptions()

    def size(self):
        return struct.calcsize(TCP.__PACKFMT__)

    def tail_serialized(self, raw):
        pass

    def to_bytes(self):
        '''
        Return packed byte representation of the TCP header.
        '''
        offset_flags = self.offset << 12 | self.__flags
        header = struct.pack(TCP.__PACKFMT__, self.srcport, self.dstport,
            self.seq, self.ack, offset_flags, self.window,
            self.checksum(), self.urgent_pointer)
        return b''.join( (header, self.__options.to_bytes()) )

    def from_bytes(self, raw):
        '''Return an Ethernet object reconstructed from raw bytes, or an
           Exception if we can't resurrect the packet.'''
        if len(raw) < TCP.__MINSIZE__:
            raise Exception("Not enough bytes ({}) to reconstruct an TCP object".format(len(raw)))
        fields = struct.unpack(TCP.__PACKFMT__, raw[:TCP.__MINSIZE__])
        self.__srcport = fields[0]
        self.__dstport = fields[1]
        self.__seq = fields[2]        
        self.__ack = fields[3]
        offset = fields[4] >> 12
        self.__flags = fields[4] & 0x01ff
        self.__window = fields[5]
        csum = fields[6]
        self.__urg = fields[7]
        headerlen = offset * 4
        optlen = headerlen - TCP.__MINSIZE__
        self.__options.from_bytes(raw[TCP.__MINSIZE__:headerlen])
        return raw[headerlen:]

    def __eq__(self, other):
        return self.srcport == other.srcport and \
            self.dstport == other.dstport and \
            self.seq == other.seq and \
            self.ack == other.ack and \
            self.offset == other.offset and \
            self.flags == other.flags and \
            self.window == other.window and \
            self.urgent_pointer == other.urgent_pointer and \
            self.options == other.options

    @property
    def offset(self):
        return TCP.__MINSIZE__ // 4 + len(self.__options.to_bytes()) // 4

    @property
    def srcport(self):
        return self.__srcport

    @property
    def dstport(self):
        return self.__dstport

    @srcport.setter
    def srcport(self,value):
        self.__srcport = value

    @dstport.setter
    def dstport(self,value):
        self.__dstport = value

    def __str__(self):
        return '{} {}->{}'.format(self.__class__.__name__, self.srcport, self.dstport)

    def next_header_class(self):
        return None

    @property
    def seq(self):
        return self.__seq

    @seq.setter
    def seq(self, value):
        self.__seq = value

    @property
    def ack(self):
        return self.__ack

    @ack.setter
    def ack(self, value):
        self.__ack = value

    @property
    def window(self):
        return self.__window

    @window.setter
    def window(self, value):
        self.__window = value

    def checksum(self):
        # FIXME 
        return 0

    @property
    def flags(self):
        return self.__flags

    @property
    def urgent_pointer(self):
        return self.__urg

    @urgent_pointer.setter
    def urgent_pointer(self, value):
        self.__urg = value

    @property
    def options(self):
        return self.__options

    def __isset(self, flag):
        mask = 0x01 << flag.value 
        return (self.__flags & mask) == mask

    def __setflag(self, flag, value):
        mask = 0x01 << flag.value 
        if value:
            self.__flags = self.__flags | mask
        else:
            self.__flags = self.__flags & ~mask

    @property
    def NS(self):
        return self.__isset(TCPFlags.NS)

    @NS.setter
    def NS(self, value):
        self.__setflag(TCPFlags.NS, value)

    @property
    def CWR(self):
        return self.__isset(TCPFlags.CWR)

    @CWR.setter
    def CWR(self, value):
        self.__setflag(TCPFlags.CWR, value)

    @property
    def ECE(self):
        return self.__isset(TCPFlags.ECE)

    @ECE.setter
    def ECE(self, value):
        self.__setflag(TCPFlags.ECE, value)

    @property
    def URG(self):
        return self.__isset(TCPFlags.URG)

    @URG.setter
    def URG(self, value):
        self.__setflag(TCPFlags.URG, value)

    @property
    def ACK(self):
        return self.__isset(TCPFlags.ACK)

    @ACK.setter
    def ACK(self, value):
        self.__setflag(TCPFlags.ACK, value)

    @property
    def PSH(self):
        return self.__isset(TCPFlags.PSH)

    @PSH.setter
    def PSH(self, value):
        self.__setflag(TCPFlags.PSH, value)

    @property
    def RST(self):
        return self.__isset(TCPFlags.RST)

    @RST.setter
    def RST(self, value):
        self.__setflag(TCPFlags.RST, value)

    @property
    def SYN(self):
        return self.__isset(TCPFlags.SYN)

    @SYN.setter
    def SYN(self, value):
        self.__setflag(TCPFlags.SYN, value)

    @property
    def FIN(self):
        return self.__isset(TCPFlags.FIN)

    @FIN.setter
    def FIN(self, value):
        self.__setflag(TCPFlags.FIN, value)

if __name__ == '__main__':
    t = TCP()
    b = t.to_bytes()
    t2 = TCP()
    t2.from_bytes(b)
    assert(t == t2)
