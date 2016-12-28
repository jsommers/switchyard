import unittest 
from copy import deepcopy, copy

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

    def testNextHdr(self):
        ip = IPv4(src="1.2.3.4", dst="4.5.6.7", ttl=64, ipid=99, protocol=IPProtocol.IGMP)
        with self.assertLogs() as cm:
            cls = ip.next_header_class()
            self.assertIsNone(cls)
        self.assertIn("No class exists", cm.output[0])
        ip2 = IPv4()
        with self.assertRaises(Exception):
            ip2.from_bytes(ip.to_bytes()[:-1])
        otherb = b'\x35' + ip.to_bytes()[1:]
        with self.assertRaises(Exception):
            ip2.from_bytes(otherb)
        otherb = b'\x46' + ip.to_bytes()[1:]
        with self.assertRaises(Exception):
            ip2.from_bytes(otherb)
        self.assertEqual(ip2.total_length, 20)

    def testBlankAddrs(self):
        self.assertEqual(self.ip.src, SpecialIPv4Addr.IP_ANY.value)
        self.assertEqual(self.ip.dst, SpecialIPv4Addr.IP_ANY.value)

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.ip.ipdest = IPv4Address('0.0.0.0')
        with self.assertRaises(ValueError): 
            self.ip.ttl = 500        
        with self.assertRaises(ValueError): 
            self.ip.tos = 256        
        with self.assertRaises(ValueError): 
            self.ip.dscp = 65        
        with self.assertRaises(ValueError): 
            self.ip.ecn = -1
        with self.assertRaises(ValueError): 
            self.ip.ecn = 8
        with self.assertRaises(ValueError): 
            self.ip.ipid = 131072 
        with self.assertRaises(ValueError): 
            self.ip.fragment_offset = -1
        with self.assertRaises(ValueError): 
            self.ip.fragment_offset = 2**14

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
        with self.assertRaises(Exception):
            opts.append(1)

        self.assertEqual("IPOptionList ()", str(opts))
        opts.append(IPOptionNoOperation())
        self.assertEqual("IPOptionList (IPOptionNoOperation)", str(opts))
        self.assertNotEqual(opts, [1,2,3])
        opts2 = IPOptionList()
        self.assertNotEqual(opts, opts2)
        opts2.append(IPOptionNoOperation())
        self.assertEqual(opts, opts2)

    def testNoOpt(self):
        iphdr = self.pkt[1] 
        iphdr.options.append(IPOptionNoOperation())
        self.assertEqual(iphdr.hl, 6)
        self.assertEqual(iphdr.size(), 24)
        raw = iphdr.to_bytes()
        self.assertEqual(raw[-4:], b'\x01\x00\x00\x00')
        iphdr.options[-1] = IPOptionNoOperation()
        self.assertEqual(iphdr.hl, 6)
        self.assertEqual(iphdr.size(), 24)
        self.assertEqual(raw[-4:], b'\x01\x00\x00\x00')
        del iphdr.options[-1]
        self.assertEqual(iphdr.options.size(), 0)
        self.assertEqual(str(IPOptionNoOperation()), "IPOptionNoOperation")

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
        iphdr.src = "1.2.3.4"
        iphdr.dst = "4.5.6.7"
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

        with self.assertRaises(Exception):
            IPOptionRecordRoute(10)
        with self.assertRaises(Exception):
            IPOptionRecordRoute(-1)

        opt = IPOptionRecordRoute(2)
        self.assertEqual(opt.pointer, 4)
        self.assertIn("0.0.0.0, 0.0.0.0", str(opt))
        opt.pointer = 8
        self.assertEqual(opt.pointer, 8)
        for i in range(4):
            with self.assertRaises(ValueError):
                opt.pointer = i
        with self.assertRaises(ValueError):
            opt.pointer = 12
        self.assertEqual(opt.num_addrs(), 2)
        del opt[-1]
        self.assertEqual(opt.num_addrs(), 1)
        with self.assertRaises(IndexError):
            del opt[1]
        with self.assertRaises(IndexError):
            del opt[-2]
        opt[0] = "149.43.80.25"
        self.assertEqual(opt[0], IPv4Address("149.43.80.25"))
        with self.assertRaises(IndexError):
            opt[1] = "1.1.1.1"
        opt[-1] = "1.2.3.4"
        self.assertEqual(opt[0], IPv4Address("1.2.3.4"))
        with self.assertRaises(ValueError):
            opt[1] = 88

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

        testbad = IPOptionTimestamp()    
        with self.assertRaises(Exception):
            testbad.from_bytes(compare[:-1])

        self.assertNotEqual(topt, xtopt)
        self.assertEqual(topt.flag, 1)
        self.assertEqual(xtopt.flag, 0)
        topt.flag = xtopt.flag = 0x0
        topt._entries = copy(xtopt._entries)

        raw = b'\x44\x08\x05\x00' + b'\x00\x00\x00\x00' * 1
        xtopt.from_bytes(raw) 
        self.assertIn("IPOptionTimestamp (TimestampEntry(ipv4addr=None, timestamp=0))", str(xtopt))

        raw = b'\x44\x0c\x05\x01' + b'\x7f\x00\x00\x01' + b'\x00\x00\x00\x00'
        xtopt.from_bytes(raw) 
        self.assertIn("TimestampEntry(ipv4addr=IPv4Address('127.0.0.1'), timestamp=0)", str(xtopt))


if __name__ == '__main__':
    unittest.main()
