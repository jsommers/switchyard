from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr, SpecialIPv4Addr
import unittest 

class IPv4PacketTests(unittest.TestCase):
    def setUp(self):
        self.e = Ethernet()
        self.ip = IPv4()
        self.icmp = ICMP()
        self.pkt = self.e + self.ip + self.icmp
        self.ip.protocol = IPProtocol.ICMP

    def testReconstruct(self):
        xbytes = self.pkt.to_bytes()
        pkt2 = Packet(raw=xbytes)
        self.assertEqual(self.pkt, pkt2)

    def testBlankAddrs(self):
        self.assertEqual(self.ip.srcip, SpecialIPv4Addr.IP_ANY.value)
        self.assertEqual(self.ip.dstip, SpecialIPv4Addr.IP_ANY.value)

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.ip.ipdest = IPAddr('0.0.0.0')

    def testBadProtocolType(self):
        # try to set an invalid protocol number
        with self.assertRaises(ValueError):
            self.ip.protocol = 0xff

if __name__ == '__main__':
    unittest.main()
