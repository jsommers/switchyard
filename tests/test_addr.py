from switchyard.lib.packet import *
from switchyard.lib.address import *
from ipaddress import AddressValueError
import unittest 

class AddressTests(unittest.TestCase):
    def testEthAddr(self):
        e = EthAddr()
        self.assertEqual(e, SpecialEthAddr.ETHER_ANY.value)
        e1 = EthAddr("01-80-C2-00-00-0e")
        self.assertTrue(e1.is_bridge_filtered)
        e2 = EthAddr("e2-00-00-00-00-00")
        self.assertTrue(e2.is_local)
        self.assertFalse(e2.is_global)
        self.assertEqual(e2.raw, b'\xe2\x00\x00\x00\x00\x00')
        self.assertEqual(e2.toRaw(), b'\xe2\x00\x00\x00\x00\x00')
        self.assertEqual(e2.packed, b'\xe2\x00\x00\x00\x00\x00')
        self.assertEqual(e2.toStr('-'), "e2-00-00-00-00-00")
        self.assertEqual(str(e2), "e2:00:00:00:00:00")
        self.assertEqual(repr(e2), "EthAddr('e2:00:00:00:00:00')")
        self.assertEqual(e2.toTuple(), (0xe2, 0x0, 0x0, 0x0, 0x0, 0x0))
        self.assertTrue(e1 < e2)

    def testSpecialEth(self):
        self.assertEqual(SpecialEthAddr.ETHER_ANY.value.raw, b'\x00'*6)
        self.assertTrue(SpecialEthAddr.LLDP_MULTICAST.value.is_multicast)
        self.assertEqual(str(SpecialEthAddr.PAE_MULTICAST.value), "01:80:c2:00:00:03")


if __name__ == '__main__':
    unittest.main()
