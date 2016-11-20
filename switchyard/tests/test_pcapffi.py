import unittest 
import os

from switchyard.lib.pcapffi import *
from switchyard.lib.packet import *

class PcapFfiTests(unittest.TestCase):
    def testWriteRead(self):
        dump = PcapDumper("testXX.pcap")
        pkt = Ethernet() + IPv6() + ICMPv6()
        pkt[0].ethertype = EtherType.IPv6
        pkt[1].nextheader = IPProtocol.ICMPv6
        with self.assertRaises(PcapException):
            dump.write_packet(pkt)
        dump.write_packet(pkt.to_bytes())
        dump.close()

        reader = PcapReader("testXX.pcap")
        count = 0
        while True:
            p = reader.recv_packet()
            if not p:
                break
            count += 1
            if count == 1:
                rpkt = Packet(raw=p.raw)
                self.assertEqual(pkt, rpkt)
        reader.close()
        self.assertEqual(count, 1)
        os.unlink("testXX.pcap")


if __name__ == '__main__':
    unittest.main()
