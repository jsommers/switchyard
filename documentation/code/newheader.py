from switchyard.lib.userlib import *
import struct

class SpanningTreeMessage(PacketHeaderBase):
    _PACKFMT = "6sxB" 

    def __init__(self, root="00:00:00:00:00:00", **kwargs):
        self._root = EthAddr(root)
        self._hops_to_root = 0
        PacketHeaderBase.__init__(self, **kwargs)

    def to_bytes(self):
        raw = struct.pack(self._PACKFMT, self._root.raw, self._hops_to_root)
        return raw

    def from_bytes(self, raw):
        packsize = struct.calcsize(self._PACKFMT)
        if len(raw) < packsize:
            raise ValueError("Not enough bytes to unpack SpanningTreeMessage")
        xroot,xhops = struct.unpack(self._PACKFMT, raw[:packsize])
        self._root = EthAddr(xroot)
        self.hops_to_root = xhops
        return raw[packsize:]

    @property
    def hops_to_root(self):
        return self._hops_to_root

    @hops_to_root.setter
    def hops_to_root(self, value):
        self._hops_to_root = int(value)

    @property
    def root(self):
        return self._root

    def __str__(self):
        return "{} (root: {}, hops-to-root: {})".format(
            self.__class__.__name__, self.root, self.hops_to_root)


if __name__ == '__main__':
    spm = SpanningTreeMessage("00:11:22:33:44:55", hops_to_root=1)
    print(spm)

    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    pkt = Ethernet(src="11:22:11:22:11:22", 
                   dst="22:33:22:33:22:33",
                   ethertype=EtherType.SLOW) + spm
    print(pkt)
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    print(p)
