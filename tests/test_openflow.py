import unittest 
from copy import deepcopy
from switchyard.lib.packet.openflow import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr

class OpenflowPacketTests(unittest.TestCase):
    def testHello(self):
        hello = OpenflowHello()
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        hello.header.xid = 42
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowSwitchFeaturesRequest()
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')

    def testSwitchFeatureReply(self):
        featuresreply = OpenflowSwitchFeaturesReply()
        self.assertEqual(featuresreply.to_bytes(), b'\x01\x06\x00\x08\x00\x00\x00\x00')


if __name__ == '__main__':
    unittest.main()
