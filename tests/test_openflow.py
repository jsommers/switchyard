import unittest 
from copy import deepcopy
from switchyard.lib.openflow import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr
from switchyard.lib.pcapffi import PcapDumper
from switchyard.lib.packet import Ethernet, IPv4, TCP, TCPFlags
from time import time


class OpenflowPacketTests(unittest.TestCase):
    def _storePkt(self, ofhdr, dstport=6633):
        return

        pkt = (Ethernet(src="11:22:33:44:55:66") + IPv4() + TCP()) + ofhdr

        xname = pkt[OpenflowHeader].type.name
        dumper = PcapDumper("oftests_{}.pcap".format(xname))

        pkt[Ethernet].dst = ''.join(list(reversed("11:22:33:44:55:66")))
        pkt[IPv4].protocol = 6
        pkt[IPv4].src = "149.43.80.25"
        pkt[IPv4].dst = "149.43.80.25"
        pkt[IPv4].ttl = 5
        pkt[IPv4].ipid = 42
        pkt[TCP].dstport = dstport
        pkt[TCP].srcport = 5555
        pkt[TCP].window = 1000
        pkt[TCP].seq = 42
        pkt[TCP].ack = 500
        pkt[TCP].PSH = 1
        pkt[TCP].ACK = 1
        dumper.write_packet(pkt.to_bytes(), time())
        dumper.close()

    def testHello(self):
        hello = OpenflowHeader(OpenflowType.Hello, 0)
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        hello.xid = 42
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
        bval = hello.to_bytes()

        hello2 = OpenflowHeader(OpenflowType.Hello)
        hello2.from_bytes(bval)
        self.assertEqual(hello, hello2)
        self._storePkt(hello)
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowHeader(OpenflowType.FeaturesRequest, 0)
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')
        self._storePkt(featuresreq)

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
        self._storePkt(OpenflowHeader(OpenflowType.FeaturesReply, 0) + featuresreply)

    def testEchoRequest(self):
        echoreq = OpenflowEchoRequest()        
        echoreq.data = b'\x01\x23\x45'
        b = echoreq.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = OpenflowEchoRequest()
        another.from_bytes(b)
        self.assertEqual(echoreq, another)
        self._storePkt(OpenflowHeader(OpenflowType.EchoRequest, 0) + echoreq)

    def testEchoReply(self):
        echorepl = OpenflowEchoReply()
        echorepl.data = b'\x01\x23\x45'
        b = echorepl.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = OpenflowEchoRequest()
        another.from_bytes(b)
        self.assertEqual(echorepl, another)
        self._storePkt(OpenflowHeader(OpenflowType.EchoReply, 0) + echorepl)

    def testMatchStruct(self):
        m = OpenflowMatch()
        b = m.to_bytes()
        self.assertEqual(len(b), 40)

        m2 = OpenflowMatch()
        m2.from_bytes(b)
        self.assertEqual(m, m2)

        m.wildcard_all()
        m2.from_bytes(m.to_bytes())
        self.assertListEqual(['NwSrc:32','NwDst:32','All'], m2.wildcards) 

        m.reset_wildcards()
        m.add_wildcard(OpenflowWildcards.DlSrc)
        m.add_wildcard(OpenflowWildcards.DlDst)
        xlist = m.wildcards
        m2.from_bytes(m.to_bytes())
        self.assertListEqual(xlist, m2.wildcards)

    def testMatchOverlap(self):
        m = OpenflowMatch()
        self.assertTrue(m.overlaps(m))
        
    def testError(self):
        e = OpenflowError()
        e.errortype = OpenflowErrorType.HelloFailed
        e.errorcode = OpenflowHelloFailedCode.PermissionsError
        e.data = b'\xef' * 10
        b = e.to_bytes()
        self.assertEqual(b, b'\x00\x00\x00\x01' + b'\xef'*10)

        e.errortype = OpenflowErrorType.BadAction
        e.errorcode = OpenflowBadActionCode.BadArgument
        b = e.to_bytes()
        self.assertEqual(b, b'\x00\x02\x00\x05' + b'\xef'*10)
        self._storePkt(OpenflowHeader(OpenflowType.Error, 0) + e)

    def testPacketIn(self):
        pass

    def testPacketOut(self):
        pass

    def testFlowMod1(self):
        pass

    def testFlowRemoved(self):
        pass

    def testPortMod(self):
        pass

    def testBarrier(self):
        pass

    def testQueueConfigRequest(self):
        pass

    def testQueueConfigReply(self):
        pass

    def testPortStatus(self):
        pass

    def testStatsRequest(self):
        pass

    def testStatsReply(self):
        pass

if __name__ == '__main__':
    unittest.main()
