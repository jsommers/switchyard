from switchyard.lib.packet import *
from switchyard.lib.address import *
import unittest 

class AddressTests(unittest.TestCase):
    def testEthAddr(self):
        e = EthAddr()
        self.assertEqual(e, SpecialEthAddr.ETHER_ANY.value)
        e = EthAddr("01-80-C2-00-00-0e")
        self.assertTrue(e.is_bridge_filtered)
        e = EthAddr("e2-00-00-00-00-00")
        self.assertTrue(e.is_local)
        self.assertFalse(e.is_global)

    def testSpecialEth(self):
        self.assertEqual(SpecialEthAddr.ETHER_ANY.value.raw, b'\x00'*6)
        self.assertTrue(SpecialEthAddr.LLDP_MULTICAST.value.is_multicast)
        self.assertEqual(str(SpecialEthAddr.PAE_MULTICAST.value), "01:80:c2:00:00:03")


    def testUtils(self):
        mask = IPv4Address("255.255.252.0")
        l = netmask_to_cidr(mask)
        self.assertEqual(l, 22)
        self.assertEqual(mask, cidr_to_netmask(l))
        self.assertEqual(infer_netmask(IPAddr("10.0.0.1")), 8)
        self.assertEqual(infer_netmask(IPAddr("192.168.1.24")), 24)
        self.assertEqual(str(cidr_to_netmask(24)), "255.255.255.0")
        addr,netbits = parse_cidr("149.43.80.25/22", allow_host=True)
        self.assertEqual(addr, IPv4Address("149.43.80.25"))
        self.assertEqual(netbits, 22)
        self.assertEqual(netmask_to_cidr("255.255.0.0"), 16)

if __name__ == '__main__':
    unittest.main()
