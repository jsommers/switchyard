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


if __name__ == '__main__':
    unittest.main()
