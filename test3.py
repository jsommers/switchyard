from cn_toolbelt.lib.packet import Ethernet
from cn_toolbelt.lib.address import EthAddr, IPAddr
import unittest 

class EthernetPacketTests(unittest.TestCase):
    def setUp(self):
        self.e = Ethernet()

    def testBlankAddrs(self):
        self.assertEqual(self.e.src, EthAddr())
        self.assertEqual(self.e.dst, EthAddr())

    def testSetSrc(self):
        astr = '00:00:00:00:00:01'
        self.e.src = astr
        self.assertEqual(self.e.src, EthAddr(astr))

    def testSetDst(self):
        astr = '00:00:00:00:00:01'
        self.e.dst = astr
        self.assertEqual(self.e.dst, EthAddr(astr))

    def testBadSet(self):
        with self.assertRaises(Exception):
            self.e.xdst = EthAddr()

    def testGetFields(self):
        fieldnames = self.e.fields
        self.assertIn('src', fieldnames)
        self.assertIn('dst', fieldnames)

if __name__ == '__main__':
    unittest.main()
