import unittest 
from copy import deepcopy
from switchyard.lib.packet.openflow import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr

class OpenflowPacketTests(unittest.TestCase):
    def testHello(self):
        hello = OpenflowHeader(OpenflowType.Hello, 0)
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        hello.xid = 42
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
        bval = hello.to_bytes()

        hello2 = OpenflowHeader(OpenflowType.Hello)
        hello2.from_bytes(bval)
        self.assertEqual(hello, hello2)
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowHeader(OpenflowType.FeaturesRequest, 0)
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')

    def testSwitchFeatureReply(self):
        featuresreply = OpenflowSwitchFeaturesReply()
        featuresreply.dpid_low48 = EthAddr("00:01:02:03:04:05")
        featuresreply.dpid_high16 = b'\xab\xcd'
        p = OpenflowPhysicalPort(0, EthAddr("ab:cd:ef:ab:cd:ef"), "eth0")
        featuresreply.ports.append(p)
        xb = featuresreply.to_bytes()
        fr = OpenflowSwitchFeaturesReply()
        fr.from_bytes(xb)
        self.assertEqual(fr, featuresreply)

    def testEchoRequest(self):
        echoreq = OpenflowEchoRequest()        
        echoreq.data = b'\x01\x23\x45'
        b = echoreq.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = OpenflowEchoRequest()
        another.from_bytes(b)
        self.assertEqual(echoreq, another)

    def testEchoReply(self):
        echorepl = OpenflowEchoReply()
        echorepl.data = b'\x01\x23\x45'
        b = echorepl.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = OpenflowEchoRequest()
        another.from_bytes(b)
        self.assertEqual(echorepl, another)

if __name__ == '__main__':
    unittest.main()
