import unittest

from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.pcapffi import PcapDumper

class RIPv2PacketTests(unittest.TestCase):
    def testRequest(self):
        p = Ethernet() + IPv4() + UDP() + RIPv2()
        p[0].src = '00:11:22:33:44:55'
        p[0].dst = '55:44:33:22:11:00'
        p[1].protocol = IPProtocol.UDP
        p[1].srcip = '192.168.100.42'
        p[1].dstip = '192.168.100.255'
        p[2].srcport = 5000
        p[2].dstport = 520
        xraw = p.to_bytes()
        pkt = Packet(raw=xraw)
        pkt[-1] = RIPv2(pkt[-1])
        self.assertEqual(pkt, p)

    def testReply(self):
        p = Ethernet() + IPv4() + UDP() + RIPv2()
        p[0].src = '00:11:22:33:44:55'
        p[0].dst = '55:44:33:22:11:00'
        p[1].protocol = IPProtocol.UDP
        p[1].srcip = '192.168.100.42'
        p[1].dstip = '192.168.100.255'
        p[2].srcport = 5000
        p[2].dstport = 520
        p[3].command = RIPCommand.Reply
        p[3].append(RIPRouteEntry('192.168.200.0','255.255.255.0','192.168.200.254',4))
        p[3].append(RIPRouteEntry('192.168.100.0','255.255.252.0','192.168.100.254',3))
        xraw = p.to_bytes()
        pkt = Packet(raw=xraw)
        pkt[-1] = RIPv2(pkt[-1])
        self.assertEqual(pkt, p)
        s = str(pkt)
        self.assertIn('192.168.200.0/24', s)
        self.assertIn('192.168.100.0/22', s)
        self.assertEqual(pkt[-1][0].address, IPv4Address('192.168.200.0'))
        self.assertEqual(pkt[-1][0].netmask, IPv4Address('255.255.255.0'))
        self.assertEqual(pkt.size(), 44)

        pkt[-1][-1] = RIPRouteEntry('192.168.0.0','255.255.0.0','192.168.42.5',15)
        s = str(pkt)
        self.assertIn('192.168.0.0/16', s)
        self.assertNotIn('192.168.100.0/22', s)
        with self.assertRaises(ValueError):
            pkt[-1].append(1)
        with self.assertRaises(ValueError):
            pkt[-1][0] = 0
        with self.assertRaises(IndexError):
            pkt[-1][2] = RIPRouteEntry()
        with self.assertRaises(IndexError):
            x = pkt[-1][2]


if __name__ == '__main__':
    unittest.main()

