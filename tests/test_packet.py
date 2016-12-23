from io import StringIO
import sys
import unittest 

from switchyard.lib.packet import *
from switchyard.lib.address import EthAddr, IPAddr
from switchyard.lib.testing import SwitchyardTestEvent

class FakeTestEvent(SwitchyardTestEvent):
    def __init__(self, display=None):
        self._display = display

    def match(self, evtype, **kwargs):
        pass

    def fail_reason(self):
        pass


class PacketTests(unittest.TestCase):
    def testEmptyPacket(self):
        p = Packet()
        self.assertEqual(len(p),0)
        self.assertEqual(list(p), [])

    def testEthPacket(self):
        p = Packet()
        p += Ethernet()
        self.assertEqual(len(p), 14)
        self.assertTrue(isinstance(list(p)[0], Ethernet))

    def testAddInsert(self):
        e1 = Ethernet()
        e2 = Ethernet()
        p = e1 + e2
        self.assertTrue(isinstance(p, Packet))
        self.assertEqual(len(list(p)), 2)
        self.assertEqual(len(p), 28)

        with self.assertRaises(Exception):
            p += p

        p1 = Packet()
        p1 += Ethernet()
        p2 = Packet()
        p2 += IPv4()
        p3 = p1 + p2
        self.assertEqual(p3[0], p1[0])
        self.assertEqual(p3[1], p2[0])

        with self.assertRaises(Exception):
            p3 = p3 + "hello, bob!"

        p = IPv4() + ICMP()
        p.prepend_header(Ethernet())
        self.assertEqual(p.num_headers(), 3)
        self.assertEqual(p[0], Ethernet())

        p.add_payload(b'Some raw gunk')
        self.assertEqual(p[3].to_bytes(), b'Some raw gunk')

        with self.assertRaises(Exception):
            p.add_header(42)

        self.assertTrue(p.has_header("IPv4"))
        self.assertFalse(p.has_header(IPv6))
        self.assertFalse(p.has_header("IPv6"))
        self.assertFalse(p.has_header("IPv13"))

        with self.assertRaises(Exception):
            IPv6() + "ugh"


    def testIndexing(self):
        e1 = Ethernet()
        e2 = Ethernet()
        p = e1 + e2
        self.assertEqual(p[0], e1)
        self.assertEqual(p[1], e2)
        p[1] = e1
        self.assertEqual(p[1], e1)
        with self.assertRaises(IndexError):
            e = p[2]

        with self.assertRaises(IndexError):
            e = p["a"]

        with self.assertRaises(IndexError):
            del p["a"]

    def testFormatter(self):
        e = Ethernet()
        ip = IPv4()
        icmp = ICMP()
        fullpkt = e + ip + icmp

        xfull = FakeTestEvent(None)
        self.assertEqual(xfull.format_pkt(fullpkt), str(fullpkt))

        partial = "Ethernet... | " + str(ip) + " | ICMP..."
        xpartial = FakeTestEvent(IPv4)
        self.assertEqual(xpartial.format_pkt(fullpkt), str(partial))

        xbad = FakeTestEvent(IPv6)
        with self.assertLogs(level='WARN') as cm:
            self.assertEqual(xbad.format_pkt(fullpkt), str(fullpkt))
        self.assertIn('non-existent header', cm.output[0])

    def testHeaderAccess(self):
        eth = Ethernet()
        ip = IPv4()
        icmp = ICMP()
        p = eth + ip + icmp
        self.assertTrue(p.has_header(Ethernet))
        self.assertTrue(p.has_header(IPv4))
        self.assertTrue(p.has_header(ICMP))
        self.assertIsInstance(p[0], Ethernet)
        self.assertIsInstance(p[1], IPv4)
        self.assertIsInstance(p[2], ICMP)
        self.assertEqual(p.num_headers(), 3)
        self.assertEqual(eth, p.get_header(Ethernet))
        self.assertEqual(ip, p.get_header(IPv4))
        self.assertEqual(icmp, p.get_header(ICMP))
        self.assertEqual(p.get_header_index(Ethernet), 0)
        self.assertEqual(p.get_header_index(IPv4), 1)
        self.assertEqual(p.get_header_index(ICMP), 2)
        self.assertEqual(p[Ethernet], eth)
        self.assertEqual(p[IPv4], ip)
        self.assertEqual(p[ICMP], icmp)
        with self.assertRaises(KeyError):
            p[IPv6]
        del p[Ethernet]
        self.assertFalse(p.has_header(Ethernet))
        self.assertEqual(p.num_headers(), 2)
        with self.assertRaises(KeyError):
            del p[Ethernet]

        with self.assertRaises(TypeError):
            p["a"] = ICMP()

        with self.assertRaises(TypeError):
            p[0] = "abc"

        self.assertIn(icmp, p)
        icmp2 = ICMP(icmptype=ICMPType.Redirect)
        self.assertNotIn(icmp2, p)
        icmp3 = ICMP()
        self.assertIn(icmp3, p)

    def testEquality(self):
        p1 = Packet()
        p2 = Packet()
        self.assertEqual(p1, p2)
        with self.assertRaises(TypeError):
            p1 == "hello, crash"
        p1 += ICMP()
        self.assertNotEqual(p1, p2)
        p2 += ICMP()
        self.assertEqual(p1, p2)
        p2[0].icmptype = ICMPType.Redirect
        self.assertNotEqual(p1, p2)
        p1.insert_header(0, IPv4())
        self.assertNotEqual(p1, p2)

    def testNullPacketHeader(self):
        nph = NullPacketHeader()
        self.assertEqual(nph.to_bytes(), b'')
        self.assertEqual(nph.size(), 0)
        self.assertEqual(nph.from_bytes(b'abc'), b'abc')
        self.assertIsNone(nph.next_header_class())
        self.assertIsNone(nph.pre_serialize(None, None, None))
        self.assertIs(nph(), nph)
        self.assertEqual(str(nph), "NullPacketHeader")
        self.assertEqual(repr(nph), "NullPacketHeader()")
        self.assertEqual(nph, nph)
        self.assertNotEqual(nph, IPv4())
        self.assertIs(getattr(nph, 'blahblah'), nph)

    def testRawPacket(self):
        raw = RawPacketContents(b'abc')
        with self.assertRaises(TypeError):
            RawPacketContents(42)
        with self.assertRaises(TypeError):
            RawPacketContents(IPv4())
        self.assertEqual(raw.to_bytes(), b'abc')
        raw.from_bytes('hwyl')
        self.assertEqual(raw.to_bytes(), b'hwyl')
        self.assertIsNone(raw.next_header_class())
        self.assertEqual(raw.size(), 4)

        i = ICMP()
        raw.from_bytes(i.to_bytes())
        raw2 = RawPacketContents(i.to_bytes())
        self.assertNotEqual(raw, i)
        self.assertNotEqual(raw, raw.to_bytes())
        self.assertEqual(raw, raw2)

        raw.from_bytes(b'diolch yn fawr')
        self.assertEqual(str(raw), "RawPacketContents (14 bytes) b'diolch yn '...")

        raw.from_bytes(b'diolch')
        self.assertEqual(str(raw), "RawPacketContents (6 bytes) b'diolch'")

        with self.assertRaises(TypeError):
            raw.from_bytes(1234567890)


if __name__ == '__main__':
    unittest.main()
