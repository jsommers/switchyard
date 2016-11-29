from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
import unittest 

class ArpTests(unittest.TestCase):
    def testArpRequest(self):
        p = create_ip_arp_request("00:00:00:11:22:33", "1.2.3.4", "10.11.12.13")
        self.assertEqual(p.num_headers(), 2)
        ether = p[0]
        arp = p[1]
        self.assertEqual(ether.src, "00:00:00:11:22:33")
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.ethertype, EtherType.ARP)
        self.assertEqual(len(ether), 14)
        self.assertEqual(arp.operation, ArpOperation.Request)
        self.assertEqual(arp.hardwaretype, ArpHwType.Ethernet)
        self.assertEqual(arp.protocoltype, EtherType.IP)
        self.assertEqual(arp.senderhwaddr, EthAddr("00:00:00:11:22:33"))
        self.assertEqual(arp.targethwaddr, EthAddr("ff:ff:ff:ff:ff:ff"))
        self.assertEqual(arp.senderprotoaddr, IPv4Address("1.2.3.4"))
        self.assertEqual(arp.targetprotoaddr, IPv4Address("10.11.12.13"))
        serialized = arp.to_bytes()
        other = Arp()
        other.from_bytes(serialized)
        self.assertEqual(arp, other)
        self.assertEqual(len(arp), 28)
        with self.assertRaises(Exception):
            other.from_bytes(serialized[:-3])
        xbytes = arp.to_bytes()
        # inject an invalid arp operation
        xbytes = xbytes[:6] + b'\xff\xff' + xbytes[8:]
        a = Arp()
        with self.assertRaises(Exception):
            a.from_bytes(xbytes)

    def testArpReply(self):
        p = create_ip_arp_reply("aa:bb:cc:dd:ee:ff", "00:00:00:11:22:33", "10.11.12.13", "1.2.3.4")
        self.assertEqual(p.num_headers(), 2)
        ether = p[0]
        arp = p[1]
        self.assertEqual(ether.dst, "00:00:00:11:22:33")
        self.assertEqual(ether.src, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(ether.ethertype, EtherType.ARP)
        self.assertEqual(len(ether), 14)
        self.assertEqual(arp.operation, ArpOperation.Reply)
        self.assertEqual(arp.hardwaretype, ArpHwType.Ethernet)
        self.assertEqual(arp.protocoltype, EtherType.IP)
        self.assertEqual(arp.targethwaddr, EthAddr("00:00:00:11:22:33"))
        self.assertEqual(arp.senderhwaddr, EthAddr("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(arp.targetprotoaddr, IPv4Address("1.2.3.4"))
        self.assertEqual(arp.senderprotoaddr, IPv4Address("10.11.12.13"))
        serialized = arp.to_bytes()
        other = Arp()
        other.from_bytes(serialized)
        self.assertEqual(arp, other)
        self.assertEqual(len(arp), 28)

if __name__ == '__main__':
    unittest.main()
