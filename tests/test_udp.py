from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
import unittest 

class UDPPacketTests(unittest.TestCase):
    def testSerialize(self):
        ether = Ethernet()
        ether.src = '00:00:00:11:22:33'
        ether.dst = '11:22:33:00:00:00'
        ether.ethertype = EtherType.IP
        ippkt = IPv4()
        ippkt.srcip = '1.2.3.4'
        ippkt.dstip = '4.5.6.7'
        ippkt.protocol = IPProtocol.UDP
        ippkt.ttl = 37
        ippkt.ipid = 0
        udppkt = UDP()
        udppkt.srcport = 10000
        udppkt.dstport = 9999
        pkt =  ether + ippkt + udppkt + RawPacketContents('hello, world') 
        b = pkt.to_bytes()

        newpkt = Packet(raw=b)
        self.assertEqual(b, newpkt.to_bytes())


if __name__ == '__main__':
    unittest.main()
