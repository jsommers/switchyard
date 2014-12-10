from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
import unittest

class RIPv2PacketTests(unittest.TestCase):
    def testCreateSerialize(self):
        p = Ethernet() + IPv4() + UDP() + RIPv2()
        p[1].protocol = IPProtocol.UDP
        print (p) 

if __name__ == '__main__':
    unittest.main()
