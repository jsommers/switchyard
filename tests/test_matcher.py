import sys
import os
import os.path
import unittest
import copy
import time

from switchyard.lib.testing import *
from switchyard.lib.testing import _PacketMatcher as PacketMatcher
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.logging import setup_logging
from switchyard.lib.exceptions import *


class SrpyMatcherTest(unittest.TestCase):
    def testExactMatch0(self):
        pkt = Ethernet() + Arp()
        matcher = ExactMatch(pkt)
        self.assertTrue(matcher.match(pkt))
        pkt[0].src = '00:00:00:00:01:01'
        self.assertFalse(matcher.match(pkt))

    def testExactMatch1(self):
        pkt = Ethernet() + Arp()
        matcher = PacketMatcher(pkt, exact=True)
        self.assertTrue(matcher.match(pkt))

    def testExactMatch2(self):
        pkt = Ethernet() + IPv4() + ICMP()
        matcher = PacketMatcher(pkt, exact=True)
        pkt[0].ethertype = EtherType.ARP
        rv = matcher.match(pkt)
        self.assertFalse(rv)

    def testWildcardMatch0(self):
        pkt = Ethernet() + IPv4()
        matcher = WildcardMatch(pkt, [])
        self.assertTrue(matcher.match(pkt))
        pkt[1].ipid = 100 # ipid isn't checked in wildcard match
        self.assertTrue(matcher.match(pkt))
        pkt[0].src = '01:02:03:04:05:06'
        self.assertFalse(matcher.match(pkt))
        matcher = WildcardMatch(pkt, ['dl_src'])
        self.assertTrue(matcher.match(pkt))
        self.assertTrue('dl_src' in str(matcher))

        with self.assertRaises(ValueError):
            m = WildcardMatch(pkt, (1,2,3))
        
    def testWildcardMatch1(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch1(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, predicates=['''lambda pkt: pkt[0].src == '00:00:00:00:00:00' '''], exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch2(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, predicates=['''lambda pkt: pkt[0].src == '00:00:00:00:00:01' '''], exact=False)
        rv = matcher.match(pkt)
        self.assertFalse(rv)

    def testPredicateMatch3(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, 
            predicates=['''lambda pkt: pkt[0].src == '00:00:00:00:00:00' ''', 
            '''lambda pkt: isinstance(pkt[1], IPv4) and pkt[1].ttl == 0'''],
            wildcards=[],
            exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch4(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, 
            predicates=[
            '''lambda pkt: pkt[0].src == '00:00:00:00:00:00' ''',
            '''lambda pkt: isinstance(pkt[1], IPv4) and pkt[1].ttl == 0'''],
            exact=False)        
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch6(self):
        pkt = Ethernet() + IPv4()
        with self.assertRaises(Exception):
            matcher = PacketMatcher(pkt, 'not a function', exact=False)

    def testWildcarding(self):
        pkt = Ethernet() + IPv4()
        pkt[1].src = IPAddr("192.168.1.1")
        pkt[1].dst = IPAddr("192.168.1.2")
        pkt[1].ttl = 64
        
        matcher = PacketMatcher(pkt, wildcards=['dl_dst', 'nw_dst'], exact=False)
        pkt[0].dst = "11:11:11:11:11:11"
        pkt[1].dst = "192.168.1.3"
        self.assertTrue(matcher.match(copy.deepcopy(pkt)))

    def testWildcarding2(self):
        pkt = create_ip_arp_request('11:22:33:44:55:66', '192.168.1.1', '192.168.10.10')
        xcopy = copy.deepcopy(pkt)
        pkt[1].targethwaddr = '00:ff:00:ff:00:ff'
        matcher = PacketMatcher(pkt, wildcards=['arp_tha'], exact=False)
        self.assertTrue(matcher.match(xcopy))

        pkt[1].senderhwaddr = '00:ff:00:ff:00:ff'
        matcher = PacketMatcher(pkt, wildcards=['arp_tha'], exact=False)
        rv = matcher.match(xcopy)
        self.assertFalse(rv)

    def testWildcardMatchOutput(self):
        pkt = create_ip_arp_request('11:22:33:44:55:66', '192.168.1.1', '192.168.10.10')
        outev = PacketOutputEvent("eth1", pkt, wildcards=('arp_tha',), exact=False)
        self.assertNotIn("IPv4", str(outev))
        rv = outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device='eth1', packet=pkt)
        self.assertEqual(rv, SwitchyardTestEvent.MATCH_SUCCESS)

        outev = PacketOutputEvent("eth1", pkt, wildcards=('arp_tha',), exact=False)
        pktcopy = copy.deepcopy(pkt)
        pktcopy[1].targethwaddr = '00:ff:00:ff:00:ff'
        rv = outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device='eth1', packet=pktcopy)
        self.assertEqual(rv, SwitchyardTestEvent.MATCH_SUCCESS)

        outev = PacketOutputEvent("eth1", pkt, wildcards=('arp_tha','dl_src'), exact=False)
        with self.assertRaises(TestScenarioFailure) as exc:
            pktcopy[1].senderhwaddr = '00:ff:00:ff:00:ff'
            rv = outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device='eth1', packet=pktcopy)
        self.assertNotIn("IPv4", str(exc.exception))

    def testWildCard2(self):
        p = Ethernet() + \
            IPv4(protocol=IPProtocol.UDP,src="1.2.3.4",dst="5.6.7.8") + \
            UDP(src=9999, dst=4444)
        xcopy = copy.copy(p)
        outev = PacketOutputEvent("eth1", p, wildcards=((UDP,'src'),), exact=False)
        rv = outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device='eth1', packet=xcopy)
        self.assertTrue(rv)

        outev = PacketOutputEvent("eth1", p, wildcards=((UDP,'src'),), exact=False)
        with self.assertRaises(TestScenarioFailure) as exc:
            xcopy[2].dst = 5555
            rv = outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device='eth1', packet=xcopy)
        estr = str(exc.exception)        
        self.assertIn("In the UDP header, dst is wrong", estr)

    def testMatcherOutputDiagnosis(self):
        p = Packet()
        outev = PacketOutputEvent("en0", p, exact=True)
        newp = Ethernet() + IPv4() + ICMP()
        with self.assertRaises(TestScenarioFailure) as exc:
            outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device="en0", packet=newp)
        self.assertIn("Unnecessary headers", str(exc.exception))

        p = Ethernet() + IPv4() + ICMP()
        newp = Packet() 
        outev = PacketOutputEvent("en0", p, exact=True)
        with self.assertRaises(TestScenarioFailure) as exc:
            outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device="en0", packet=newp)
        self.assertIn("Missing headers", str(exc.exception))

        p = Ethernet() + IPv4() + ICMP()
        newp = Packet() 
        outev = PacketOutputEvent("en0", p, exact=True)
        with self.assertRaises(TestScenarioFailure) as exc:
            outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device="en0", packet=newp)
        self.assertIn("Missing headers", str(exc.exception))

        p = Ethernet() + IPv4() + ICMP()
        newp = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        outev = PacketOutputEvent("en0", p, exact=True)
        with self.assertRaises(TestScenarioFailure) as exc:
            outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device="en0", packet=newp)
        self.assertIn("Header types differ at index 2", str(exc.exception))

        p = Ethernet() + IPv4(src="1.2.3.4", dst="4.5.6.7", protocol=IPProtocol.UDP, ttl=78) + UDP(src=10, dst=42)
        newp = copy.deepcopy(p)
        newp[UDP].src = 11
        newp[IPv4].dst = "5.5.5.5"
        outev = PacketOutputEvent("en0", p, exact=True)
        with self.assertRaises(TestScenarioFailure) as exc:
            outev.match(SwitchyardTestEvent.EVENT_OUTPUT, device="en0", packet=newp)
        self.assertIn("In the IPv4 header, dst is wrong", str(exc.exception))
        self.assertIn("In the UDP header, src is wrong", str(exc.exception))

    def testWildcardOutput2(self):
        p = Ethernet() + \
             IPv4(protocol=IPProtocol.UDP,src="1.2.3.4",dst="5.6.7.8") + \
             UDP(src=9999, dst=4444)
        xcopy = copy.copy(p)
        xcopy[2].src = 2345

        wm = WildcardMatch(p, ('tp_src','dl_src','nw_dst'))
        self.assertTrue(wm.match(xcopy))
        x = wm.show(xcopy)
        self.assertEqual("Ethernet **:**:**:**:**:**->00:00:00:00:00:00 IP | IPv4 1.2.3.4->*.*.*.* UDP | UDP *->4444", x)

        wm = WildcardMatch(p, ('tp_src','dl_src'))
        self.assertTrue(wm.match(xcopy))
        x = wm.show(xcopy)
        self.assertEqual("Ethernet **:**:**:**:**:**->00:00:00:00:00:00 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP *->4444", x)

        wm = WildcardMatch(p, ('tp_src',))
        self.assertTrue(wm.match(xcopy))
        x = wm.show(xcopy)
        self.assertEqual("Ethernet 00:00:00:00:00:00->00:00:00:00:00:00 IP | IPv4 1.2.3.4->5.6.7.8 UDP | UDP *->4444", x)

        with self.assertRaises(ValueError):
            # subtle: missing comma to make tuple
            wm = WildcardMatch(p, ('tp_src'))

    def testInputTimeoutEv(self):
        x = PacketInputTimeoutEvent(0.1)
        self.assertNotEqual(x, 5)
        self.assertEqual(x.match(SwitchyardTestEvent.EVENT_OUTPUT), SwitchyardTestEvent.MATCH_FAIL)
        self.assertEqual(x.match(SwitchyardTestEvent.EVENT_INPUT), SwitchyardTestEvent.MATCH_SUCCESS)
        with self.assertRaises(NoPackets):
            x.generate_packet(1.0, self)

    def testConstructPaths(self):
        p = Ethernet() + \
            IPv4(protocol=IPProtocol.UDP,src="1.2.3.4",dst="5.6.7.8") + \
            UDP(src=9999, dst=4444)
        xcopy = copy.copy(p)
        with self.assertLogs() as cm:
            outev = PacketOutputEvent("eth1", p, wildcards=('tp_src',), exact=True)
        self.assertIn("Wildcards given but exact match specified. Ignoring exact match.", cm.output[-1])

        outev = PacketOutputEvent("eth1", p, wildcards=('tp_src',))
        for dev,mobj in outev._device_packet_map.items():
            self.assertFalse(mobj._exact)

        with self.assertLogs() as cm:
            outev = PacketOutputEvent("eth1", p, wildcards=('tp_src',), blahblah=True)
        self.assertIn("unrecognized keyword arg", cm.output[-1])

        with self.assertRaises(Exception):
            outev = PacketOutputEvent("eth1", p, predicates="print('hello,world')")

        with self.assertRaises(Exception):
            outev = PacketOutputEvent("eth1", p, predicates="def x(): return -1")

    def testMatcherSyntax(self):
        p = Ethernet() + \
             IPv4(protocol=IPProtocol.UDP,src="1.2.3.4",dst="5.6.7.8") + \
             UDP(src=9999, dst=4444)
        xcopy = copy.copy(p)
        xcopy[2].src = 2345

        wm = WildcardMatch(p, ((UDP,'src'),(IPv4,'dst'),(Ethernet,'src')))
        self.assertTrue(wm.match(xcopy))
        x = wm.show(xcopy)
        self.assertEqual("Ethernet **:**:**:**:**:**->00:00:00:00:00:00 IP | IPv4 1.2.3.4->*.*.*.* UDP | UDP *->4444", x)
        xcopy[1].dst = "1.2.3.4"
        self.assertTrue(wm.match(xcopy))
        xcopy[1].src = "2.2.2.2"
        self.assertFalse(wm.match(xcopy))
        xcopy[1].src = "1.2.3.4"
        xcopy[0].src = "00:11:22:33:44:55"
        self.assertTrue(wm.match(xcopy))
        xcopy[0].dst = "00:11:22:33:44:55"
        self.assertFalse(wm.match(xcopy))

        
if __name__ == '__main__':
    setup_logging(False)
    unittest.main()
