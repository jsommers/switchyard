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

    def testChangeICMPIdentity(self):
        i = ICMP() # echorequest, by default
        i.icmptype = ICMPType.EchoReply
        self.assertEqual(i.icmptype, ICMPType.EchoReply)
        self.assertEqual(i.icmpcode, ICMPTypeCodeMap[i.icmptype].EchoReply)

        other = ICMP()

        i.icmptype = ICMPType.DestinationUnreachable
        self.assertEqual(i.icmptype, ICMPType.DestinationUnreachable)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.SourceQuench
        self.assertEqual(i.icmptype, ICMPType.SourceQuench)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.Redirect
        self.assertEqual(i.icmptype, ICMPType.Redirect)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.EchoRequest
        self.assertEqual(i.icmptype, ICMPType.EchoRequest)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.RouterAdvertisement
        self.assertEqual(i.icmptype, ICMPType.RouterAdvertisement)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.RouterSolicitation
        self.assertEqual(i.icmptype, ICMPType.RouterSolicitation)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.TimeExceeded
        self.assertEqual(i.icmptype, ICMPType.TimeExceeded)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.ParameterProblem
        self.assertEqual(i.icmptype, ICMPType.ParameterProblem)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.Timestamp
        self.assertEqual(i.icmptype, ICMPType.Timestamp)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.TimestampReply
        self.assertEqual(i.icmptype, ICMPType.TimestampReply)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.InformationRequest
        self.assertEqual(i.icmptype, ICMPType.InformationRequest)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.InformationReply
        self.assertEqual(i.icmptype, ICMPType.InformationReply)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.AddressMaskRequest
        self.assertEqual(i.icmptype, ICMPType.AddressMaskRequest)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

        i.icmptype = ICMPType.AddressMaskReply
        self.assertEqual(i.icmptype, ICMPType.AddressMaskReply)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

    def testValidCode(self):
        i = ICMP()
        i.icmpcode = 0
        self.assertEqual(i.icmpcode, ICMPTypeCodeMap[i.icmptype].EchoRequest)
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].EchoRequest
        self.assertEqual(i.icmpcode, ICMPTypeCodeMap[i.icmptype].EchoRequest)

    def testSerializeEchoReq(self):
        i = ICMP() # default to EchoRequest with zero seq and ident
        self.assertEqual(i.to_bytes(), b'\x08\x00\xf7\xff\x00\x00\x00\x00')

        i.icmpdata.data = ( b'hello, world ' * 3 )
        other = ICMP()
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)

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
