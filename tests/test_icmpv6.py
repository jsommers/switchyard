import unittest 
from copy import deepcopy

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
        self.assertEqual(i.hopcount, 128)
        i.hopcount = 64
        self.assertEqual(i.hopcount, 64)
        i = IPv6(src=SpecialIPv6Addr.UNDEFINED.value, dst=SpecialIPv6Addr.ALL_NODES_LINK_LOCAL.value)
        self.assertEqual(i.src, SpecialIPv6Addr.UNDEFINED.value)
        self.assertEqual(i.dst, SpecialIPv6Addr.ALL_NODES_LINK_LOCAL.value)
        self.assertIn("::->ff02::1", str(i))

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

    def testReconstruct2(self):
        raw = b'33\x00\x00\x00\x16\x18\x81\x0e\x03\xaeQ\x86\xdd`\x00\x00\x00\x00$\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\xe7\xbe)OU\x89s\xff\x02\x00\x00'
        with self.assertRaises(NotEnoughDataError):
            p = Packet(raw)


if __name__ == '__main__':
    unittest.main()