from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.packet.common import ICMPType
import unittest 

class ICMPPacketTests(unittest.TestCase):
    def testBadTypeCode(self):
        i = ICMP()
        with self.assertRaises(ValueError):
            i.icmptype = 2

        with self.assertRaises(ValueError):
            i.icmptype = 19

        with self.assertRaises(ValueError):
            i.icmptype = 49

        with self.assertRaises(ValueError):
            i.icmpcode = ICMPType.EchoRequest

        with self.assertRaises(ValueError):
            i.icmpcode = 1

        i.icmptype = 0 # echo reply; any code other than 0 is invalid
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

        # not enough bytes
        with self.assertRaises(Exception):
            i.from_bytes(b'\x04\x00\xfb\xff\x00\x00\x00')

    def testUnreachableMtu(self):
        i = ICMP()
        i.icmptype = ICMPType.DestinationUnreachable
        i.icmpdata.nexthopmtu = 5
        i.icmpdata.origdgramlen = 42
        self.assertEqual(i.to_bytes()[-1], 5) 
        self.assertEqual(i.icmpdata.origdgramlen, 42)

    def testICMPKwArgsValid(self):
        icmptype = ICMPType.DestinationUnreachable
        # valid combination
        i = ICMP(icmptype=icmptype, icmpcode=ICMPTypeCodeMap[icmptype].NetworkUnreachable)
        self.assertIsInstance(i.icmpdata, ICMPDestinationUnreachable)
        i2 = ICMP()
        i2.from_bytes(i.to_bytes())
        self.assertIsInstance(i2.icmpdata, ICMPDestinationUnreachable)
        self.assertEqual(i2.icmptype, icmptype)
        self.assertEqual(i2.icmpcode, ICMPTypeCodeMap[icmptype].NetworkUnreachable)

    def testICMPKwArgsInvalid1(self):
        with self.assertRaises(ValueError):
            i = ICMP(icmptype=0, icmpcode=45)

    def testICMPKwArgsInvalid2(self):
        with self.assertRaises(ValueError):
            i = ICMP(icmptype=ICMPType.EchoRequest, icmpcode=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].CommunicationAdministrativelyProhibited)

    def testStringify(self):
        i = ICMP(icmptype=3, icmpcode=8)
        s = str(i)
        self.assertTrue(s.startswith('ICMP DestinationUnreachable:SourceHostIsolated'))


if __name__ == '__main__':
    unittest.main()
