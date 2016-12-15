from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr, SpecialIPv4Addr
import unittest 

class TCPPacketTests(unittest.TestCase):
    def setUp(self):
        self.t = TCP()

    def testReconstruct(self):
        self.t.ack = 1234
        self.t.ack = 5678
        self.t.PSH = True
        b = self.t.to_bytes()
        t2 = TCP()
        t2.from_bytes(b)
        self.assertEqual(self.t, t2)
        self.assertEqual(t2.size(), 20)
        self.assertIsNone(self.t.next_header_class())

    def testFlags(self):
        self.assertEqual(self.t.flags, 0)
        self.t.SYN = 1
        self.t.FIN = True
        self.assertTrue(self.t.SYN)
        self.assertTrue(self.t.FIN)

        t2 = TCP(src=40, dst=80, seq=19, ack=47, SYN=1, ACK=1)
        self.assertIn("SA", str(t2))
        t2.ACK = 0
        self.assertNotIn("SA", str(t2))
        self.assertEqual(t2.ACK, 0)

        for f in TCPFlags:
            setattr(t2, f.name, 1)
            self.assertEqual(getattr(t2, f.name), 1)
            setattr(t2, f.name, 0)
            self.assertEqual(getattr(t2, f.name), 0)

        for f in TCPFlags:
            setattr(t2, f.name, 1)
            self.assertEqual(getattr(t2, f.name), 1)
        self.assertEqual(len(t2.flagstr), 9)

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.t.srcport = 55

    def testChecksum(self):
        ip = IPv4(protocol=IPProtocol.TCP)
        t = TCP(src=40, dst=80, seq=19, ack=47, SYN=1)
        self.assertEqual(t.checksum, 0)
        p = Ethernet() + ip + t
        b = p.to_bytes()
        self.assertEqual("TCP 40->80 (S 19:47)", str(t))
        self.assertEqual(t.checksum, 44841)

        with self.assertRaises(Exception):
            x = Packet(raw=b[:-2])


if __name__ == '__main__':
    unittest.main()
