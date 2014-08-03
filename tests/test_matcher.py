import sys
import os
import os.path
import unittest
import copy
import time

from switchyard.lib.common import * 
from switchyard.lib.testing import *
from switchyard.lib.address import *
from switchyard.lib.packet import *


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
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, exact=True)
        pkt[0].ethertype = EtherType.ARP
        self.assertRaises(ScenarioFailure, matcher.match, pkt)

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
        
    def testWildcardMatch1(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch1(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, '''lambda pkt: pkt[0].src == '00:00:00:00:00:00' ''', exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch2(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, '''lambda pkt: pkt[0].src == '00:00:00:00:00:01' ''', exact=False)
        self.assertRaises(ScenarioFailure, matcher.match, pkt)

    def testPredicateMatch3(self):
        pkt = Ethernet() + IPv4()
        matcher = PacketMatcher(pkt, 
            '''lambda pkt: pkt[0].src == '00:00:00:00:00:00' ''', 
            '''lambda pkt: isinstance(pkt[1], IPv4) and pkt[1].ttl == 0 ''',
            exact=False)
        self.assertTrue(matcher.match(pkt))

    def testWildcarding(self):
        pkt = Ethernet() + IPv4()
        pkt[1].srcip = IPAddr("192.168.1.1")
        pkt[1].dstip = IPAddr("192.168.1.2")
        pkt[1].ttl = 64
        
        matcher = PacketMatcher(pkt, wildcard=['dl_dst', 'nw_dst'], exact=False)
        pkt[0].dst = "11:11:11:11:11:11"
        pkt[1].dstip = "192.168.1.3"
        self.assertTrue(matcher.match(copy.deepcopy(pkt)))


if __name__ == '__main__':
    setup_logging(False)
    unittest.main(verbosity=2)
