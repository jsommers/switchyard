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


    def testUtils(self):
        mask = IPv4Address("255.255.252.0")
        l = netmask_to_cidr(mask)
        self.assertEqual(l, 22)
        self.assertEqual(mask, cidr_to_netmask(l))
        self.assertEqual(infer_netmask(IPAddr("10.0.0.1")), 8)
        self.assertEqual(infer_netmask(IPAddr("192.168.1.24")), 24)
        self.assertEqual(infer_netmask(IPAddr("149.43.80.25")), 16)
        self.assertEqual(infer_netmask(IPAddr("0.0.0.0")), 0)
        self.assertEqual(str(cidr_to_netmask(24)), "255.255.255.0")
        addr,netbits = parse_cidr("149.43.80.25/22", allow_host=True)
        self.assertEqual(addr, IPv4Address("149.43.80.25"))
        self.assertEqual(netbits, 22)
        self.assertEqual(netmask_to_cidr("255.255.0.0"), 16)
        with self.assertRaises(AddressValueError) as _:
            netmask_to_cidr("320.255.255.0")
        with self.assertRaises(RuntimeError) as _:
            netmask_to_cidr(2**32+1000)
        with self.assertRaises(RuntimeError) as _:
            parse_cidr("1.2.3.4/40")
        with self.assertRaises(RuntimeError) as _:
            parse_cidr("1.2.3.4/40")
        with self.assertRaises(RuntimeError) as _:
            parse_cidr("1.2.3.1/24")
        self.assertEqual(parse_cidr('149.43.80.1', infer=False), (IPv4Address("149.43.80.1"), 32))
        self.assertEqual(parse_cidr('149.43.80.0', infer=False), (IPv4Address("149.43.80.0"), 32))
        self.assertEqual(parse_cidr('149.43.80.0', infer=True), (IPv4Address("149.43.80.0"), 32))
        self.assertEqual(parse_cidr('149.43.0.0', infer=True), (IPv4Address("149.43.0.0"), 16))
        self.assertEqual(parse_cidr('149.43.80.0/255.255.252.0'), (IPv4Address("149.43.80.0"), 22))
        self.assertEqual(parse_cidr('149.43.80.1/255.255.252.0', allow_host=True), 
            (IPv4Address("149.43.80.1"), 22))
        with self.assertRaises(RuntimeError) as _:
            parse_cidr('149.43.0.0/255.240.255.254')
        self.assertEqual(infer_netmask(IPv4Address("242.0.0.0")), 32)
        self.assertEqual(infer_netmask(IPv4Address("224.0.0.0")), 32)


if __name__ == '__main__':
    unittest.main()
