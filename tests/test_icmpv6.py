import unittest 
from copy import deepcopy
from ipaddress import IPv6Address, IPv6Network
from switchyard.lib.packet import *
from switchyard.lib.address import SpecialIPv6Addr
from switchyard.pcapffi import PcapDumper

class ICMPPv6PacketTests(unittest.TestCase):
    def setUp(self):
        self.e = Ethernet()
        self.e.ethertype = EtherType.IPv6
        self.ip = IPv6()
        self.ip.nextheader = IPProtocol.ICMPv6
        self.pkt = self.e + self.ip + ICMPv6()

    def testBasic(self):
        i = IPv6()
        self.assertEqual(i.size(), 40)
        with self.assertRaises(Exception):
            i.from_bytes(b'\x00\x01\x02')
        b = i.to_bytes()
        with self.assertRaises(Exception):
            i.from_bytes(b[:-1])
        b = b'\x70' + b[1:]
        with self.assertRaises(Exception):
            i.from_bytes(b)
        i = IPv6(nextheader=IPProtocol.GRE)
        with self.assertLogs() as cm:
            self.assertIsNone(i.next_header_class())
        self.assertIn('No class exists', cm.output[0])
        self.assertEqual(i.hoplimit, 128)
        i.hoplimit = 64
        self.assertEqual(i.hoplimit, 64)
        i = IPv6(src=SpecialIPv6Addr.UNDEFINED.value, dst=SpecialIPv6Addr.ALL_NODES_LINK_LOCAL.value)
        self.assertEqual(i.src, SpecialIPv6Addr.UNDEFINED.value)
        self.assertEqual(i.dst, SpecialIPv6Addr.ALL_NODES_LINK_LOCAL.value)
        self.assertIn("::->ff02::1", str(i))

    def testOptionLinkLayerAddress(self):
        lladdr = ICMPv6OptionTargetLinkLayerAddress('33:33:00:00:00:01')
        raw = lladdr.to_bytes()
        self.assertEqual(len(raw), 8)
        self.assertEqual(raw[1], 1)
        lladdr2 = ICMPv6OptionTargetLinkLayerAddress()
        lladdr2.from_bytes(raw)
        self.assertEqual(lladdr, lladdr2)

    def testOptionPrefixInformation(self):
        pfx = ICMPv6OptionPrefixInformation(prefix='fd00::/64')
        raw = pfx.to_bytes()
        pfx2 = ICMPv6OptionPrefixInformation()
        pfx2.from_bytes(raw)
        self.assertEqual(pfx, pfx2)
        pfx2.prefix_length = 48
        self.assertEqual(pfx2.prefix_length, 48)
        self.assertIn('/48', str(pfx2.prefix))
    
    def testOptionRedirectedHeader(self):
        opt = ICMPv6OptionRedirectedHeader(b'\x00\x11\x22\x33')
        raw = opt.to_bytes()
        opt2 = ICMPv6OptionRedirectedHeader()
        opt2.from_bytes(raw)
        self.assertEqual(opt, opt2)

    def testOptionMTU(self):
        opt = ICMPv6OptionMTU(576)
        raw = opt.to_bytes()
        opt2 = ICMPv6OptionMTU()
        opt2.from_bytes(raw)
        self.assertEqual(opt, opt2)

    def testOptionList(self):
        opt = ICMPv6OptionPrefixInformation(prefix='fd00::/64')
        optlist = ICMPv6OptionList(opt,
                                   ICMPv6OptionRedirectedHeader(b'\x00\x11\x22\x33'),
                                   ICMPv6OptionMTU(576))
        self.assertEqual(optlist.size(), 3)
        raw = optlist.to_bytes()
        optlist2 = ICMPv6OptionList.from_bytes(raw)
        self.assertEqual(optlist, optlist2)
        with self.assertRaises(TypeError):
            optlist.append("hello")
        self.assertEqual(optlist.size(), len(optlist))
        self.assertEqual(len(raw), optlist.raw_length())
        del optlist[-1]
        self.assertEqual(len(optlist), 2)
        self.assertEqual(opt, optlist[0])
        with self.assertRaises(IndexError):
            optlist[2]
        with self.assertRaises(IndexError):
            optlist[-3]
        with self.assertRaises(IndexError):
            del optlist[-3]
        optlist[0] = opt
        self.assertEqual(len(optlist), 2)
        self.assertEqual(optlist[0], opt)

    def testReconstruct1(self):
        raw = b'33\x00\x00\x00\x16\x18\x81\x0e\x03\xaeQ\x86\xdd`\x00\x00\x00\x00$\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\xe7\xbe)OU\x89s\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16:\x00\x01\x00\x05\x02\x00\x00\x8f\x00\xbb6\x00\x00\x00\x01\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb'         
        p = Packet(raw)
        ip6 = p[IPv6]
        self.assertEqual(ip6.src, ip_address('fe80::1ce7:be29:4f55:8973'))
        self.assertEqual(ip6.dst, ip_address('ff02::16'))
        self.assertEqual(ip6.nextheader, IPProtocol.IPv6HopOption)
        opts = p[IPv6HopOption]
        self.assertEqual(opts[1].__class__, RouterAlert)
        icmpv6 = p[ICMPv6]
        self.assertEqual(icmpv6.icmptype, ICMPv6Type.Version2MulticastListenerReport)
        self.assertEqual(icmpv6.icmp6type, ICMPv6Type.Version2MulticastListenerReport)
        self.assertEqual(icmpv6.icmpcode, 0)
        self.assertEqual(icmpv6.icmp6code, 0)
        with self.assertRaises(ValueError):
            icmpv6.icmp6code = 13

    def testReconstruct2(self):
        raw = b'33\x00\x00\x00\x16\x18\x81\x0e\x03\xaeQ\x86\xdd`\x00\x00\x00\x00$\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\xe7\xbe)OU\x89s\xff\x02\x00\x00'
        with self.assertRaises(NotEnoughDataError):
            p = Packet(raw)

    def testSetType(self):
        p = Ethernet(ethertype=EtherType.IPv6) + IPv6(nextheader=IPProtocol.ICMPv6) + ICMPv6(icmp6type=ICMPv6Type.RouterSolicitation)
        self.assertEqual(p[-1].icmptype, ICMPv6Type.RouterSolicitation)
        self.assertEqual(p[-1].icmp6type, ICMPv6Type.RouterSolicitation)
        #print(p.to_bytes())
        #print(p)
        #print(p[-1])

    def testMakeRouterAdvertisement(self):
        p = Ethernet(ethertype=EtherType.IPv6, src='58:ac:78:93:da:00', dst='33:33:00:00:00:01') + IPv6(nextheader=IPProtocol.ICMPv6, hoplimit=255, src='fe80::1', dst='ff02::1') + ICMPv6(icmptype=ICMPv6Type.RouterAdvertisement, icmpdata=ICMPv6RouterAdvertisement(options=(ICMPv6OptionSourceLinkLayerAddress('00:50:56:af:97:68'),)))
        raw = p.to_bytes()
        p2 = Packet(raw=raw)
        self.assertEqual(p, p2)
        icmp6 = p[ICMPv6]
        self.assertEqual(icmp6.icmpdata.curhoplimit, 64)
        icmp6.icmpdata.curhoplimit = 128
        self.assertEqual(icmp6.icmpdata.curhoplimit, 128)
        self.assertFalse(icmp6.icmpdata.m)
        self.assertFalse(icmp6.icmpdata.o)
        self.assertFalse(icmp6.icmpdata.h)
        self.assertFalse(icmp6.icmpdata.p)
        icmp6.icmpdata.m = 1
        icmp6.icmpdata.o = 1
        icmp6.icmpdata.h = 1
        icmp6.icmpdata.p = 1
        self.assertTrue(icmp6.icmpdata.m)
        self.assertTrue(icmp6.icmpdata.o)
        self.assertTrue(icmp6.icmpdata.h)
        self.assertTrue(icmp6.icmpdata.p)
        icmp6.icmpdata.router_lifetime = 600
        self.assertEqual(icmp6.icmpdata.router_lifetime, 600)
        self.assertEqual(icmp6.icmpdata.reachable_time, 0)
        self.assertEqual(icmp6.icmpdata.retrans_timer, 0)
        icmp6.icmpdata.reachable_time = 13
        icmp6.icmpdata.retrans_timer = 13
        self.assertEqual(icmp6.icmpdata.reachable_time, 13)
        self.assertEqual(icmp6.icmpdata.retrans_timer, 13)

    def testMakeRouterSolicitation(self):
        p = Ethernet(ethertype=EtherType.IPv6, src='58:ac:78:93:da:00', dst='33:33:00:00:00:01') + IPv6(nextheader=IPProtocol.ICMPv6, hoplimit=255, src='fe80::1', dst='ff02::1') + ICMPv6(icmptype=ICMPv6Type.RouterSolicitation, icmpdata=ICMPv6RouterSolicitation(options=(ICMPv6OptionSourceLinkLayerAddress('00:50:56:af:97:68'),ICMPv6OptionMTU(1250), ICMPv6OptionPrefixInformation(prefix='fd00::/64'))))
        raw = p.to_bytes()
        p2 = Packet(raw=raw)
        self.assertEqual(p, p2)

    def testMakeNeighborAdvertisement(self):
        p = Ethernet(ethertype=EtherType.IPv6, dst='58:ac:78:93:da:00', src='00:50:56:af:97:68') + \
            IPv6(nextheader=IPProtocol.ICMPv6, hoplimit=255, 
                 src='2001:db8:cafe:1:d0f8:9ff6:4201:7086',
                 dst='2001:db8:cafe:1::1') + \
            ICMPv6(icmptype=ICMPv6Type.NeighborAdvertisement, 
                   icmpdata=ICMPv6NeighborAdvertisement(options=(ICMPv6OptionTargetLinkLayerAddress('00:1b:24:04:a2:1e'),)))
        raw = p.to_bytes()
        p2 = Packet(raw=raw)
        self.assertEqual(p, p2)
        icmp6 = p[ICMPv6]
        self.assertEqual(icmp6.icmpdata.get_rso_str(), '')
        icmp6.icmpdata.r = True
        self.assertTrue(icmp6.icmpdata.r)
        icmp6.icmpdata.s = True
        self.assertTrue(icmp6.icmpdata.s)
        icmp6.icmpdata.o = True
        self.assertTrue(icmp6.icmpdata.o)
        self.assertEqual(icmp6.icmpdata.get_rso_str(), 'RSO')
        icmp6.icmpdata.targetaddr = 'fe80::1'
        self.assertEqual(icmp6.icmpdata.targetaddr, IPv6Address('fe80::1'))

    def testMakeNeighborSolicitation(self):
        p = Ethernet(ethertype=EtherType.IPv6, dst='33:33:ff:01:70:86', src='58:ac:78:93:da:00') + \
            IPv6(nextheader=IPProtocol.ICMPv6, hoplimit=255, src='2001:db8:cafe:1::1', dst='ff02::1:ff01:7086') +  \
            ICMPv6(icmptype=ICMPv6Type.NeighborSolicitation, 
                   icmpdata=ICMPv6NeighborSolicitation(options=(ICMPv6OptionSourceLinkLayerAddress('58:ac:78:93:da:00'),)))
        raw = p.to_bytes()
        p2 = Packet(raw=raw)
        self.assertEqual(p, p2)

    def testMakeRedirect(self):
        p = Ethernet(ethertype=EtherType.IPv6, dst='33:33:ff:01:70:86', src='58:ac:78:93:da:00') + \
            IPv6(nextheader=IPProtocol.ICMPv6, hoplimit=255, src='2001:db8:cafe:1::1', dst='ff02::1:ff01:7086') +  \
            ICMPv6(icmptype=ICMPv6Type.RedirectMessage,
                   icmpdata=ICMPv6RedirectMessage(targetaddr='fe80:3::1', destaddr='fe80:3::2', options=(ICMPv6OptionTargetLinkLayerAddress('58:ac:78:93:da:00'), ICMPv6OptionRedirectedHeader(self.pkt.to_bytes()))))
        raw = p.to_bytes()
        p2 = Packet(raw=raw)
        self.assertEqual(p, p2)

    def testNeighborAdvertisementReconstruct(self):
        raw=b'\x60\x00\x00\x00\x00\x18\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\xea\x8d\x28\xff\xfe\x59\x2e\x5b\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\x44\x49\xff\x8e\x68\x2b\x21\x88\x00\x1b\xd8\xc0\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\xea\x8d\x28\xff\xfe\x59\x2e\x5b' 
        p = Packet(raw=raw, first_header=IPv6)
        #print(p)

        raw=b'\x60\x00\x00\x00\x00\x20\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\x44\x49\xff\x8e\x68\x2b\x21\xfe\x80\x00\x00\x00\x00\x00\x00\xea\x8d\x28\xff\xfe\x59\x2e\x5b\x87\x00\x45\xf7\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\xea\x8d\x28\xff\xfe\x59\x2e\x5b\x01\x01\xac\xbc\x32\xc2\xb6\x59'
        p = Packet(raw=raw, first_header=IPv6)
        #print(p)

if __name__ == '__main__':
    unittest.main()