from switchyard.lib.userlib import *
import struct

class UDPPing(PacketHeaderBase):
    _PACKFMT = "!H"

    def __init__(self, seq=0, **kwargs):
        self._sequence = int(seq)
        PacketHeaderBase.__init__(self, **kwargs)

    def to_bytes(self):
        raw = struct.pack(self._PACKFMT, self._sequence)
        return raw

    def from_bytes(self, raw):
        packsize = struct.calcsize(self._PACKFMT)
        if len(raw) < packsize:
            raise ValueError("Not enough bytes to unpack UDPPing")
        attrs = struct.unpack(self._PACKFMT, raw[:packsize])
        self.sequence = attrs[0]
        return raw[packsize:]

    @property
    def sequence(self):
        return self._sequence

    @sequence.setter
    def sequence(self, value):
        self._sequence = int(value)

    def __str__(self):
        return "{} seq: {}".format(self.__class__.__name__, self.sequence)


if __name__ == '__main__':
    up1 = UDPPing()
    print(up1)

    up2 = UDPPing()
    up2.sequence = 13
    print(up2)

    up3 = UDPPing(sequence=42)
    print(up3)

    UDP_PING_PORT = 12345
    pkt = Ethernet(src="11:22:11:22:11:22", 
                   dst="22:33:22:33:22:33") + \
          IPv4(src="1.2.3.4", dst="5.6.7.8", 
               protocol=IPProtocol.UDP, ttl=64) + \
          UDP(src=55555, dst=UDP_PING_PORT) + \
          UDPPing(42)
    print("Before serialize/deserialize:", pkt)
    xbytes = pkt.to_bytes()
    reanimated_pkt = Packet(raw=xbytes)
    print("After deserialization:", reanimated_pkt)

    print("*" * 40)

    UDP.add_next_header_class(UDP_PING_PORT, UDPPing)
    UDP.set_next_header_class_key('dst')
    pkt = Ethernet(src="11:22:11:22:11:22", 
                   dst="22:33:22:33:22:33") + \
          IPv4(src="1.2.3.4", dst="5.6.7.8", 
               protocol=IPProtocol.UDP, ttl=64) + \
          UDP(src=55555, dst=UDP_PING_PORT) + \
          UDPPing(sequence=13)
    print("Before serialize/deserialize:", pkt)
    xbytes = pkt.to_bytes()
    reanimated_pkt = Packet(raw=xbytes)
    print("After deserialization:", reanimated_pkt)
