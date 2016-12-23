from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
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

    def testBadEType(self):
        # try to set an invalid ethertype
        with self.assertRaises(ValueError):
            self.e.ethertype = 0x01

    def testBadAddr(self):
        with self.assertRaises(RuntimeError):
            x = EthAddr("a")

    def testParse(self):
        raw = b'\x01\x02\x03\x04\x05\x06\x06\x05\x04\x03\x02\x01\x08\x00'
        astr = '01:02:03:04:05:06'
        e = Ethernet()
        e.from_bytes(raw)
        self.assertEqual(e.dst, EthAddr(astr))
        self.assertEqual(e.src, EthAddr(':'.join(astr.split(':')[::-1])))
        self.assertEqual(e.ethertype, EtherType.IP)

    def testBadParse(self):
        raw = b'x\01'
        e = Ethernet()
        with self.assertRaises(Exception):
            e.from_bytes(raw)

    def testVlan(self):
        e = Ethernet()
        e.src = "00:11:22:33:44:55"
        e.dst = "aa:bb:cc:dd:ee:ff"
        e.ethertype = EtherType.x8021Q

        v = Vlan()
        v.vlanid = 42
        v.pcp = 2
        v.ethertype = EtherType.IP

        ip = IPv4()
        ip.src = "1.2.3.4"
        ip.dst = "5.6.7.8"
        icmp = ICMP()

        packet = e + v + ip + icmp
        self.assertEqual(packet.num_headers(), 4)
        self.assertEqual(packet[1].vlanid, 42)
        self.assertEqual(packet[1].pcp, 2)
        self.assertEqual(len(packet), 46)
        serialized = packet.to_bytes()

        other = Packet(raw=serialized)
        self.assertEqual(packet, other)

if __name__ == '__main__':
    unittest.main()
