from switchyard.lib.packet import *
from switchyard.lib.address import SpecialIPv6Addr
import unittest 

class IPv6PacketTests(unittest.TestCase):
    def setUp(self):
        self.e = Ethernet()
        self.e.ethertype = EtherType.IPv6
        self.ip = IPv6()
        self.ip.protocol = IPProtocol.ICMPv6
        self.pkt = self.e + self.ip + ICMPv6()

    def testReconstruct(self):
        xbytes = self.pkt.to_bytes()
        pkt2 = Packet(raw=xbytes)
        self.assertEqual(self.pkt, pkt2)

    def testBlankAddrs(self):
        self.assertEqual(self.ip.srcip, SpecialIPv6Addr.UNDEFINED.value)
        self.assertEqual(self.ip.dstip, SpecialIPv6Addr.UNDEFINED.value)

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.ip.ipdest = IPAddr('fe00::')

    def testBadProtocolType(self):
        # try to set an invalid protocol number
        with self.assertRaises(ValueError):
            self.ip.protocol = 0xff

if __name__ == '__main__':
    unittest.main()
