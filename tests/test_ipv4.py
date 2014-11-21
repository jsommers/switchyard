import unittest 
from copy import deepcopy

from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr

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
            self.ip.ipdest = IPv4Address('0.0.0.0')

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

    def testNoOpt(self):
        iphdr = self.pkt[1] 
        iphdr.options.append(IPOptionNoOperation())
        self.assertEqual(iphdr.hl, 6)
        self.assertEqual(iphdr.size(), 24)
        raw = iphdr.to_bytes()
        self.assertEqual(raw[-4:], b'\x01\x00\x00\x00')

    def testOptionIndexing(self):
        optlist = IPOptionList()
        self.assertEqual(len(optlist), 0)
        with self.assertRaises(IndexError):
            x = optlist[0]
        with self.assertRaises(ValueError):
            optlist[0] = 5
        with self.assertRaises(IndexError):
            optlist[0] = IPOptionNoOperation()
        xopt = IPOptionNoOperation()
        optlist.append(xopt)
        optlist.append(xopt)
        self.assertEqual(len(optlist), 2)
        self.assertEqual(optlist[0], xopt)
        self.assertEqual(optlist[1], xopt)
        self.assertEqual(optlist[-1], xopt)
        self.assertEqual(optlist[-2], xopt)
        with self.assertRaises(IndexError):
            x = optlist[-3]
        with self.assertRaises(IndexError):
            del optlist[4]
        del optlist[1]
        self.assertEqual(len(optlist), 1)
        rr = IPOptionRecordRoute()
        optlist[0] = rr
        self.assertEqual(optlist[0], rr)

        raw = optlist.to_bytes()
        optlist2 = IPOptionList.from_bytes(raw)
        self.assertEqual(optlist[0], optlist2[0])

    def routeOptTestHelper(self, ropt):
        ropt = IPOptionRecordRoute()
        self.pkt[1] = IPv4()
        iphdr = self.pkt[1]
        iphdr.options.append(ropt)
        iphdr.srcip = "1.2.3.4"
        iphdr.dstip = "4.5.6.7"
        iphdr.tos = 0x11
        self.assertEqual(iphdr.hl, 15)
        raw = iphdr.options.to_bytes()
        compare = struct.pack('B', ropt.optnum.value) + b'\x27\x04' + (9 * 4 * b'\x00') + b'\x00'
        self.assertEqual(compare, raw)
        self.assertEqual(ropt.num_addrs(), 9)
        self.assertEqual(len(ropt), 9)
        for i in range(len(ropt)):
            self.assertEqual(ropt[i], IPv4Address("0.0.0.0"))
            self.assertEqual(ropt[-len(ropt)], IPv4Address("0.0.0.0"))
        for i in range(len(ropt)):
            ropt[i] = IPv4Address("1.1.1.1")
            self.assertEqual(ropt[i], IPv4Address("1.1.1.1"))
        with self.assertRaises(IndexError):
            x = ropt[10]

    def testRouteOptions(self):
        self.routeOptTestHelper(IPOptionRecordRoute())
        self.routeOptTestHelper(IPOptionLooseSourceRouting())
        self.routeOptTestHelper(IPOptionStrictSourceRouting())

    def fourByteOptionTestHelper(self, opt, copyfl, value):
        compare = struct.pack('!BBH', copyfl | opt.optnum.value, 4, value)
        self.assertEqual(opt.to_bytes(), compare)
        copyopt = deepcopy(opt)
        opt.from_bytes(compare)
        self.assertEqual(copyopt, opt)

    def testFourByteOpts(self):
        self.fourByteOptionTestHelper(IPOptionRouterAlert(), 0x80, 0)
        self.fourByteOptionTestHelper(IPOptionMTUProbe(), 0, 1500)
        self.fourByteOptionTestHelper(IPOptionMTUReply(), 0, 1500)

    def testIPOptionTimestamp(self):
        topt = IPOptionTimestamp()
        raw = topt.to_bytes()
        compare = b'\x44\x24\x05\x01' + b'\x00\x00\x00\x00' * 8
        self.assertEqual(compare, raw)
        for i in range(topt.num_timestamps()):
            ts = topt.timestamp_entry(i)
            self.assertEqual(ts.timestamp, 0)
            self.assertEqual(ts.ipv4addr, IPv4Address("0.0.0.0"))

        compare = b'\x44\x28\x05\x00' + b'\x00\x00\x00\x00' * 9
        xtopt = IPOptionTimestamp()
        xtopt.from_bytes(compare)
        self.assertEqual(xtopt.to_bytes(), compare)

if __name__ == '__main__':
    unittest.main()
