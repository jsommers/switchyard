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
        bval = hello.to_bytes()

        hello2 = OpenflowHello()
        hello2.from_bytes(bval)
        self.assertEqual(hello, hello2)
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowSwitchFeaturesRequest()
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')

    def testSwitchFeatureReply(self):
        featuresreply = OpenflowSwitchFeaturesReply()
        featuresreply.dpid_low48 = EthAddr("00:01:02:03:04:05")
        featuresreply.dpid_high16 = b'\xab\xcd'
        self.assertEqual(featuresreply.to_bytes(), b'\x01\x06\x00\x08\x00\x00\x00\x00')

    def testEchoRequest(self):
        echoreq = OpenflowEchoRequest()        

    def testEchoReply(self):
        echorepl = OpenflowEchoReply()


if __name__ == '__main__':
    unittest.main()
