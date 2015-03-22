import unittest 
from copy import deepcopy
from switchyard.lib.packet.openflow import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr

class OpenflowPacketTests(unittest.TestCase):
    def testHello(self):
        ofp = OpenflowHeader()
        ofp.type = OpenflowType.Hello
        self.assertEqual(ofp.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        ofp.xid = 42
        self.assertEqual(ofp.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
       
    def testSwitchFeatures(self):
        pass

if __name__ == '__main__':
    unittest.main()
