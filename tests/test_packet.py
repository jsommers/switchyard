from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.common import PacketFormatter
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
        print("Expect a warning from the next test...")
        self.assertEqual(PacketFormatter.format_pkt(fullpkt, cls=IPv6), str(fullpkt))



if __name__ == '__main__':
    unittest.main()
