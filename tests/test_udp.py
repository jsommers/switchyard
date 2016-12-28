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
        ippkt.src = '1.2.3.4'
        ippkt.dst = '4.5.6.7'
        ippkt.protocol = IPProtocol.UDP
        ippkt.ttl = 37
        ippkt.ipid = 0
        udppkt = UDP()
        udppkt.src = 10000
        udppkt.dst = 9999
        pkt =  ether + ippkt + udppkt + RawPacketContents('hello, world') 
        b = pkt.to_bytes()

        newpkt = Packet(raw=b)
        self.assertEqual(b, newpkt.to_bytes())

        b = b[:-15] # slice into the udp header
        with self.assertRaises(Exception):
            newpkt = Packet(raw=b)

    def testChecksum(self):
        u = UDP()
        self.assertEqual(u.checksum, 0)

        p = IPv4() + u
        p[0].protocol = IPProtocol.UDP
        b = p.to_bytes()
        self.assertEqual(u.checksum, 65502)
        u = UDP(src=1234,dst=4567)
        u.pre_serialize(b'', Packet(), 0)
        self.assertEqual(u.checksum, 0)

        x = b'\x00\x00\xfe\xff\x00\x00'
        c = checksum(x, start=0, skip_word=1)
        self.assertEqual(c, 65535)


if __name__ == '__main__':
    unittest.main()
