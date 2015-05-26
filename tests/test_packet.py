from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.testing import PacketFormatter
from io import StringIO
import sys
import unittest 

class PacketTests(unittest.TestCase):
    def testEmptyPacket(self):
        p = Packet()
        self.assertEqual(len(p),0)
        self.assertEqual(list(p), [])

    def testEthPacket(self):
        p = Packet()
        p += Ethernet()
        self.assertEqual(len(p), 14)
        self.assertTrue(isinstance(list(p)[0], Ethernet))

    def testAdd(self):
        e1 = Ethernet()
        e2 = Ethernet()
        p = e1 + e2
        self.assertTrue(isinstance(p, Packet))
        self.assertEqual(len(list(p)), 2)
        self.assertEqual(len(p), 28)

    def testIndexing(self):
        e1 = Ethernet()
        e2 = Ethernet()
        p = e1 + e2
        self.assertEqual(p[0], e1)
        self.assertEqual(p[1], e2)
        p[1] = e1
        self.assertEqual(p[1], e1)
        with self.assertRaises(IndexError):
            e = p[2]

    def testFormatter(self):
        e = Ethernet()
        ip = IPv4()
        icmp = ICMP()
        fullpkt = e + ip + icmp
        self.assertEqual(PacketFormatter.format_pkt(fullpkt), str(fullpkt))
        partial = ip + icmp
        self.assertEqual(PacketFormatter.format_pkt(fullpkt, cls=IPv4), str(partial))
        with self.assertLogs(level='WARN') as cm:
            self.assertEqual(PacketFormatter.format_pkt(fullpkt, cls=IPv6), str(fullpkt))
        self.assertIn('non-existent header', cm.output[0])
        PacketFormatter.full_display()
        self.assertEqual(PacketFormatter.format_pkt(fullpkt), str(fullpkt))

    def testHeaderAccess(self):
        eth = Ethernet()
        ip = IPv4()
        icmp = ICMP()
        p = eth + ip + icmp
        self.assertTrue(p.has_header(Ethernet))
        self.assertTrue(p.has_header(IPv4))
        self.assertTrue(p.has_header(ICMP))
        self.assertIsInstance(p[0], Ethernet)
        self.assertIsInstance(p[1], IPv4)
        self.assertIsInstance(p[2], ICMP)
        self.assertEqual(p.num_headers(), 3)
        self.assertEqual(eth, p.get_header(Ethernet))
        self.assertEqual(ip, p.get_header(IPv4))
        self.assertEqual(icmp, p.get_header(ICMP))
        self.assertEqual(p.get_header_index(Ethernet), 0)
        self.assertEqual(p.get_header_index(IPv4), 1)
        self.assertEqual(p.get_header_index(ICMP), 2)
        self.assertEqual(p[Ethernet], eth)
        self.assertEqual(p[IPv4], ip)
        self.assertEqual(p[ICMP], icmp)
        with self.assertRaises(KeyError):
            p[IPv6]
        del p[Ethernet]
        self.assertFalse(p.has_header(Ethernet))
        self.assertEqual(p.num_headers(), 2)
        with self.assertRaises(KeyError):
            del p[Ethernet]

if __name__ == '__main__':
    unittest.main()
