import unittest 
from socket import AF_INET, AF_INET6, AF_DECnet

from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr

class NullPacketTests(unittest.TestCase):
    def testNullInstance(self):
        n = Null()
        b = n.to_bytes()
        self.assertEqual(len(b), 4)
        self.assertEqual(len(b), n.size())
        self.assertEqual(b, b'\x02\x00\x00\x00')

        n2 = Null()
        self.assertEqual(n, n2)

        self.assertEqual(str(n), "Null: AF_INET")
        self.assertIsNone(n2.pre_serialize(None, None, None))

    def testAf(self):
        n = Null()
        self.assertEqual(n.af,  AF_INET)
        n.af = AF_INET6
        self.assertEqual(n.af,  AF_INET6)
        self.assertEqual(n.next_header_class(), IPv6)
        n.af = AF_INET
        self.assertEqual(n.next_header_class(), IPv4)

        n.af = AF_DECnet
        with self.assertRaises(Exception):
            n.next_header_class()

    def testFromBytes(self):
        n = Null(AF_INET6)
        b = n.to_bytes()

        with self.assertRaises(Exception):
            n.from_bytes(b'\x00')

        x = n.from_bytes(b'\x02\x00\x00\x00')
        n2 = Null(AF_INET)
        self.assertEqual(n, n2)

        self.assertEqual(x, b'')


if __name__ == '__main__':
    unittest.main()
