import sys
import os
import os.path
import unittest
import copy
import time

sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))

from switchy import PacketMatcher,setup_logging,ScenarioFailure
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,ipv4,packet_base
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr


class SrpyMatcherTest(unittest.TestCase):
    def testExactMatch1(self):
        pkt = ethernet()
        matcher = PacketMatcher(pkt, exact=True)
        self.assertTrue(matcher.match(pkt))

    def testExactMatch2(self):
        pkt = ethernet()
        matcher = PacketMatcher(pkt, exact=True)
        pkt.type = pkt.IP_TYPE
        self.assertRaises(ScenarioFailure, matcher.match, pkt)

    def testOFPMatch(self):
        pkt = ethernet()
        matcher = PacketMatcher(pkt, exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch1(self):
        pkt = ethernet()
        matcher = PacketMatcher(pkt, '''lambda eth: str(eth.src) == '00:00:00:00:00:00' ''', exact=False)
        self.assertTrue(matcher.match(pkt))

    def testPredicateMatch2(self):
        pkt = ethernet()
        matcher = PacketMatcher(pkt, '''lambda eth: str(eth.src) == '00:00:00:00:00:01' ''', exact=False)
        self.assertRaises(ScenarioFailure, matcher.match, pkt)

    def testPredicateMatch3(self):
        pkt = ethernet()
        ip = ipv4()
        pkt.payload = ip
        pkt.type = pkt.IP_TYPE
        matcher = PacketMatcher(pkt, 
            '''lambda eth: str(eth.src) == '00:00:00:00:00:00' ''', 
            '''lambda eth: isinstance(eth.next, ipv4) and eth.next.ttl > 0 ''',
            exact=False)
        self.assertTrue(matcher.match(pkt))

    def testWildcarding(self):
        pkt = ethernet()
        ip = ipv4()
        ip.srcip = IPAddr("192.168.1.1")
        ip.dstip = IPAddr("192.168.1.2")
        ip.ttl = 64
        pkt.payload = ip
        pkt.type = pkt.IP_TYPE
        matcher = PacketMatcher(pkt, wildcard=['dl_dst', 'nw_dst'], exact=False)
        pkt.dst = EthAddr("11:11:11:11:11:11")
        ip.dstip = IPAddr("192.168.1.3")
        self.assertTrue(matcher.match(copy.deepcopy(pkt)))


if __name__ == '__main__':
    setup_logging(False)
    unittest.main(verbosity=2)
