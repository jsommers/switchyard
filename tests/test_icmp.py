from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.packet.common import ICMPType
from switchyard.lib.packet.icmpv6 import construct_icmpv6_type_map
import unittest 
from copy import deepcopy, copy

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

        with self.assertRaises(Exception):
            other.from_bytes(i.to_bytes()[:-1])
        i.icmpdata.origdgramlen = 28
        self.assertEqual(i.icmpdata.origdgramlen, 28)
        i.icmpdata.nexthopmtu = 288
        self.assertEqual(i.icmpdata.nexthopmtu, 288)

        i.icmptype = ICMPType.SourceQuench
        self.assertEqual(i.icmptype, ICMPType.SourceQuench)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)
        self.assertEqual(i.icmpdata.size(), 4)

        i.icmptype = ICMPType.Redirect
        self.assertEqual(i.icmptype, ICMPType.Redirect)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)
        i.icmpdata.redirectto = '149.43.80.25'
        self.assertEqual(i.icmpdata.redirectto, IPv4Address('149.43.80.25'))
        self.assertIn("RedirectAddress: 149.43.80.25", str(i))
        with self.assertRaises(Exception):
            other.from_bytes(i.to_bytes()[:-1])

        i.icmptype = ICMPType.EchoRequest
        self.assertEqual(i.icmptype, ICMPType.EchoRequest)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)
        i.icmpdata.identifier = 13
        i.icmpdata.sequence = 42
        self.assertEqual(i.icmpdata.identifier, 13)
        self.assertEqual(i.icmpdata.sequence, 42)

        with self.assertRaises(Exception):
            other.from_bytes(i.to_bytes()[:-1])

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
        i.icmpdata.origdgramlen = 28
        self.assertEqual(i.icmpdata.origdgramlen, 28)

        with self.assertRaises(Exception):
            other.from_bytes(i.to_bytes()[:-1])
        self.assertIn("OrigDgramLen: 28", str(i))

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

        mr = ICMPAddressMaskRequest()
        addrmaskdata = i.icmpdata.to_bytes()
        mr.from_bytes(addrmaskdata)
        with self.assertRaises(Exception):
            mr.from_bytes(addrmaskdata[:-3])
        with self.assertRaises(Exception):
            mr.from_bytes(addrmaskdata[:3])
        self.assertIsNone(i.icmpdata.next_header_class())
        self.assertIsNone(i.icmpdata.pre_serialize(None, None, None))
        self.assertEqual(i.icmpdata.size(), 4)
        i.icmpdata.addrmask = IPv4Address("255.255.255.0")
        i.icmpdata.identifier = 13
        i.icmpdata.sequence = 42
        self.assertEqual(str(i.icmpdata.addrmask), "255.255.255.0")
        self.assertEqual(i.icmpdata.identifier, 13)
        self.assertEqual(i.icmpdata.sequence, 42)
        ix = ICMP(icmptype=ICMPType.AddressMaskRequest, 
                addrmask="255.255.255.0", identifier=13, sequence=42)
        self.assertEqual(ix, i)

        i.icmptype = ICMPType.AddressMaskReply
        self.assertEqual(i.icmptype, ICMPType.AddressMaskReply)
        other.from_bytes(i.to_bytes())
        self.assertEqual(i, other)
        self.assertIn("0 0 0.0.0.0", str(other))

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

        with self.assertRaises(Exception):
            other.from_bytes(i.to_bytes()[:3])

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

    def testStr(self):
        i = ICMP(icmptype=ICMPType.DestinationUnreachable, 
            icmpcode=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable)
        p = IPv4() + UDP()
        i.icmpdata.origdgramlen = len(p)
        i.icmpdata.nexthopmtu = 1300
        i.icmpdata.data = p.to_bytes()
        self.assertIn('DestinationUnreachable:HostUnreachable', str(i))

    def testDataprops(self):
        i = ICMP()
        with self.assertRaises(Exception):
            i.icmpdata.data = IPv4()
        self.assertIsInstance(i.icmpdata, ICMPData)
        d = i.icmpdata
        self.assertIsNone(d.next_header_class())
        self.assertIsNone(d.pre_serialize(None, None, None))
        self.assertEqual(d.size(), 4)

        with self.assertRaises(Exception):
            i.icmpdata = IPv4()

        x = ICMPData()
        self.assertIsNone(x.next_header_class())
        self.assertIsNone(x.pre_serialize(None, None, None))

    def testIcmp6(self):
        x = construct_icmpv6_type_map()(ICMPv6EchoRequest)
        self.assertEqual(x, ICMPv6Type.EchoRequest)
        x = construct_icmpv6_type_map()(ICMPv6EchoReply)
        self.assertEqual(x, ICMPv6Type.EchoReply)

        
if __name__ == '__main__':
    unittest.main()
