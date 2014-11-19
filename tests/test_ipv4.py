from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr, SpecialIPv4Addr
import unittest 

from switchyard.lib.pcapffi import *

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

    def testFrag(self):
        iphdr = IPv4()
        self.assertEqual(iphdr.flags, IPFragmentFlag.NoFragments)
        iphdr.flags = IPFragmentFlag.MoreFragments
        iphdr.fragment_offset = 1000
        self.assertEqual(iphdr.flags, IPFragmentFlag.MoreFragments)
        self.assertEqual(iphdr.fragment_offset, 1000)

    def testTosbits(self):
        iphdr = IPv4()
        iphdr.dscp = 46
        self.assertEqual(iphdr.dscp, 46)
        self.assertEqual(iphdr.tos, 0x2E<<2)
        self.assertEqual(iphdr.ecn, 0)
        iphdr.ecn = 0x1
        self.assertEqual(iphdr.ecn, 1)
        self.assertEqual(iphdr.tos, (0x2E<<2) | 0x1)

    def testOptionContainer(self):
        opts = IPOptionList()
        self.assertEqual(opts.to_bytes(), b'')

    def testRecordRouteOpt(self):
        rr = IPOptionRecordRoute()
        iphdr = self.pkt[1]
        iphdr.options.add_option(rr)
        iphdr.srcip = "1.2.3.4"
        iphdr.dstip = "4.5.6.7"
        iphdr.tos = 0x11
        # print (iphdr)
        # print (iphdr.to_bytes())
        # print (len(iphdr))
        self.assertEqual(iphdr.hl, 15)

        # writer = PcapDumper("testdump.pcap")
        # p = Ethernet() + iphdr + ICMP()
        # p[2].icmpdata.identifier = 7
        # p[2].icmpdata.sequence = 42
        # writer.write_packet(p.to_bytes())
        # writer.close()


if __name__ == '__main__':
    unittest.main()
