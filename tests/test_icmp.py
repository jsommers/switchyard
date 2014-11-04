from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.packet.common import ICMPType
import unittest 

class ICMPPacketTests(unittest.TestCase):
    def testBadCode(self):
        i = ICMP()
        with self.assertRaises(ValueError):
            i.icmptype = 0

        with self.assertRaises(ValueError):
            i.icmpcode = ICMPType.EchoRequest

        with self.assertRaises(ValueError):
            i.icmpcode = 1

    def testValidCode(self):
        i = ICMP()
        i.icmpcode = 0
        self.assertEqual(i.icmpcode, ICMPTypeCodeMap[i.icmptype].EchoRequest)
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].EchoRequest
        self.assertEqual(i.icmpcode, ICMPTypeCodeMap[i.icmptype].EchoRequest)

    def testSerializeEchoReq(self):
        i = ICMP() # default to EchoRequest with zero seq and ident
        self.assertEqual(i.to_bytes(), b'\x08\x00\xf7\xff\x00\x00\x00\x00')

    def testSetSubtype(self):
        i = ICMP()
        self.assertIsInstance(i.icmpdata, ICMPEchoRequest)
        i.icmptype = ICMPType.SourceQuench
        self.assertIsInstance(i.icmpdata, ICMPSourceQuench)
        self.assertEqual(i.to_bytes(), b'\x04\x00\xfb\xff\x00\x00\x00\x00')

    def testDeserialize(self):
        i = ICMP()
        i.from_bytes(b'\x04\x00\xfb\xff\x00\x00\x00\x00')
        self.assertEqual(i.icmptype, ICMPType.SourceQuench)
        self.assertIsInstance(i.icmpdata, ICMPSourceQuench)


if __name__ == '__main__':
    unittest.main()
