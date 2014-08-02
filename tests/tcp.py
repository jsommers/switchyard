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

    def testFlags(self):
        self.assertEqual(self.t.flags, 0)
        self.t.SYN = 1
        self.t.FIN = True
        self.assertTrue(self.t.SYN)
        self.assertTrue(self.t.FIN)

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.t.sourceport = 55

if __name__ == '__main__':
    unittest.main()
