import unittest 
from copy import deepcopy
from switchyard.lib.openflow import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr
from switchyard.lib.pcapffi import PcapDumper
from switchyard.lib.packet import Ethernet, IPv4, TCP, TCPFlags, ICMP
from time import time


class OpenflowPacketTests(unittest.TestCase):
    def _storePkt(self, ofhdr, dstport=6633):
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
        hello = OpenflowHeader.build(OpenflowType.Hello, 0)
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        hello[0].xid = 42
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
        bval = hello.to_bytes()

        hello2 = Packet.from_bytes(bval, OpenflowHeader)
        self.assertEqual(hello, hello2)
        self._storePkt(hello)
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowHeader.build(OpenflowType.FeaturesRequest, 0)
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')
        self._storePkt(featuresreq)

    def testSwitchFeatureReply(self):
        featuresreply = OpenflowHeader.build(OpenflowType.FeaturesReply, 0)
        featuresreply[1].dpid_low48 = EthAddr("00:01:02:03:04:05")
        featuresreply[1].dpid_high16 = b'\xab\xcd'
        p = OpenflowPhysicalPort(0, EthAddr("ab:cd:ef:ab:cd:ef"), "eth0")
        featuresreply[1].ports.append(p)
        xb = featuresreply.to_bytes()
        fr = Packet.from_bytes(xb, OpenflowHeader)
        self.assertEqual(fr, featuresreply)
        self._storePkt(featuresreply)

    def testEchoRequest(self):
        echoreq = OpenflowHeader.build(OpenflowType.EchoRequest, 0)        
        echoreq[1].data = b'\x01\x23\x45'
        b = echoreq.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(echoreq, another)
        self._storePkt(echoreq)

    def testEchoReply(self):
        echorepl = OpenflowHeader.build(OpenflowType.EchoReply, 0)
        echorepl[1].data = b'\x01\x23\x45'
        b = echorepl.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(echorepl, another)
        self._storePkt(echorepl)

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
        # FIXME: make something non-overlap and test

        
    def testError(self):
        e = OpenflowHeader.build(OpenflowType.Error, 0)
        e[1].errortype = OpenflowErrorType.HelloFailed
        e[1].errorcode = OpenflowHelloFailedCode.PermissionsError
        e[1].data = b'\xef' * 10
        b = e.to_bytes()
        self.assertEqual(b, b'\x01\x01\x00\x16\x00\x00\x00\x00\x00\x00\x00\x01' + b'\xef'*10)

        e[1].errortype = OpenflowErrorType.BadAction
        e[1].errorcode = OpenflowBadActionCode.BadArgument
        b = e.to_bytes()
        self.assertEqual(b, b'\x01\x01\x00\x16\x00\x00\x00\x00\x00\x02\x00\x05' + b'\xef'*10)
        self._storePkt(e)

    def testPacketIn(self):
        pktin = OpenflowHeader.build(OpenflowType.PacketIn, 44)
        pktin[1].packet = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
                          IPv4(src="1.2.3.4", dst="5.6.7.8") + ICMP()
        self._storePkt(pktin)
        # FIXME: assertions

    def testPacketOut(self):
        pktout = OpenflowHeader.build(OpenflowType.PacketOut, 43)
        pktout[1].buffer = 0xffffffff
        pktout[1].in_port = 4
        pktout[1].packet = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
                           IPv4(src="1.2.3.4", dst="5.6.7.8") + ICMP()
        pktout[1].actions.append(ActionOutput(port=OpenflowPort.Flood))
        self._storePkt(pktout)
        # FIXME: assertions

    def testFlowMod(self):
        flowmod = OpenflowHeader.build(OpenflowType.FlowMod, 72) 
        flowmod[1].priority = 0xffee
        flowmod[1].hard_timeout = 3600
        flowmod[1].idle_timeout = 1800
        flowmod[1].buffer_id = 0xdeadbeef
        flowmod[1].cookie = 0xcafebeefbabe0000
        flowmod[1].match.add_wildcard(OpenflowWildcards.DlSrc)
        flowmod[1].match.add_wildcard(OpenflowWildcards.DlVlan)
        flowmod[1].match.dl_dst = "55:44:33:22:ab:cd"
        flowmod[1].match.nw_src = "149.43.0.0"
        flowmod[1].match.nwsrc_wildcard = 16
        flowmod[1].match.in_port = 42
        flowmod[1].actions.append(ActionOutput(port=OpenflowPort.Flood))
        flowmod[1].actions.append(ActionEnqueue(port=OpenflowPort.Flood, queue_id=13))
        flowmod[1].actions.append(ActionVlanVid(vlan_vid=42))
        flowmod[1].actions.append(ActionVlanPcp(vlan_pcp=2))
        flowmod[1].actions.append(ActionDlAddr(OpenflowActionType.SetDlSrc, "55:44:33:22:11:00"))
        flowmod[1].actions.append(ActionDlAddr(OpenflowActionType.SetDlDst, "aa:bb:cc:dd:ee:ff"))
        flowmod[1].actions.append(ActionNwAddr(OpenflowActionType.SetNwSrc, "10.1.2.3"))
        flowmod[1].actions.append(ActionNwAddr(OpenflowActionType.SetNwDst, "10.2.3.4"))
        flowmod[1].actions.append(ActionNwTos(0x11))
        flowmod[1].actions.append(ActionTpPort(OpenflowActionType.SetTpSrc, 1111))
        flowmod[1].actions.append(ActionTpPort(OpenflowActionType.SetTpDst, 2222))
        flowmod[1].actions.append(ActionTpPort(OpenflowActionType.SetTpDst, 2222))
        flowmod[1].actions.append(ActionVendorHeader(0xbeefbeef, b'1234'))
        self._storePkt(flowmod)
        # FIXME: assertions

    def testFlowRemoved(self):
        flowrm = OpenflowHeader.build(OpenflowType.FlowRemoved, 43)
        flowrm[1].match.wildcard_all()
        flowrm[1].cookie = 42
        flowrm[1].priority = 0xabcd
        flowrm[1].duration = 5.005
        self.assertEqual(flowrm[1].duration_sec, 5)
        self.assertLessEqual(abs(flowrm[1].duration_nsec - 5000000), 1)
        self._storePkt(flowrm)
        # FIXME: assertions

    def testPortMod(self):
        portmod = OpenflowHeader.build(OpenflowType.PortMod)
        portmod[1].hwaddr = "b2:00:1d:9c:4f:40"
        portmod[1].set_config(OpenflowPortConfig.NoStp)
        portmod[1].set_mask(OpenflowPortConfig.NoStp)
        portmod[1].set_advertise(OpenflowPortFeatures.Pause)
        portmod[1].set_advertise(OpenflowPortFeatures.Fiber)
        portmod[1].set_advertise(OpenflowPortFeatures.e1Gb_Full)
        self._storePkt(portmod)
        # FIXME: assertions

    def testPortStatus(self):
        portstat = OpenflowHeader.build(OpenflowType.PortStatus)
        portstat[1].port.name = "testport"
        portstat[1].port.portnum = 13
        # FIXME: config capabilities, etc.
        self._storePkt(portstat)
        # FIXME: assertions

    def testBarrier(self):
        barrierreq = OpenflowHeader.build(OpenflowType.BarrierRequest)
        self._storePkt(barrierreq)
        barrierreply = OpenflowHeader.build(OpenflowType.BarrierReply)
        self._storePkt(barrierreply)
        # FIXME: assertions

    def testQueueConfigRequest(self):
        qcfg = OpenflowHeader.build(OpenflowType.QueueGetConfigRequest)
        qcfg[1].port = 4
        self._storePkt(qcfg)
        # FIXME: assertions

    def testQueueConfigReply(self):
        qcfg = OpenflowHeader.build(OpenflowType.QueueGetConfigReply)
        qcfg[1].port = 4
        qcfg[1].queues.append(OpenflowPacketQueue(queue_id=0))
        qcfg[1].queues[0].properties.append(OpenflowQueueMinRateProperty(rate=(40 * 10)))
        self._storePkt(qcfg)
        # FIXME: assertions

    def testStatsRequest(self):
        pass

    def testStatsReply(self):
        pass

if __name__ == '__main__':
    unittest.main()
