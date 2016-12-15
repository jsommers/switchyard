import unittest 
from copy import deepcopy
from time import time

from switchyard.lib.openflow.openflow10 import *
from switchyard.lib.address import EthAddr, IPv4Address, SpecialIPv4Addr
from switchyard.pcapffi import PcapDumper
from switchyard.lib.packet import Ethernet, IPv4, TCP, TCPFlags, ICMP

class OpenflowPacketTests(unittest.TestCase):
    def _storePkt(self, ofhdr, dst=6633):
        # comment the return to save pcap packets for analysis
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
        pkt[TCP].dst = dst
        pkt[TCP].src = 5555
        pkt[TCP].window = 1000
        pkt[TCP].seq = 42
        pkt[TCP].ack = 500
        pkt[TCP].PSH = 1
        pkt[TCP].ACK = 1
        dumper.write_packet(pkt.to_bytes(), time())
        dumper.close()

    def testHello(self):
        hello = OpenflowHeader.build(OpenflowType.Hello, xid=0, version=0x01)
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x00')
        hello[0].xid = 42
        self.assertEqual(hello.to_bytes(), b'\x01\x00\x00\x08\x00\x00\x00\x2a')
        bval = hello.to_bytes()

        hello2 = Packet.from_bytes(bval, OpenflowHeader)
        self.assertEqual(hello, hello2)
        self._storePkt(hello)
       
    def testSwitchFeatureRequest(self):
        featuresreq = OpenflowHeader.build(OpenflowType.FeaturesRequest, xid=0, version=0x01)
        self.assertEqual(featuresreq.to_bytes(), b'\x01\x05\x00\x08\x00\x00\x00\x00')
        self._storePkt(featuresreq)

    def testSwitchFeatureReply(self):
        featuresreply = OpenflowHeader.build(OpenflowType.FeaturesReply, xid=0, version=0x01)
        featuresreply[1].dpid_low48 = EthAddr("00:01:02:03:04:05")
        featuresreply[1].dpid_high16 = b'\xab\xcd'
        p = OpenflowPhysicalPort(0, EthAddr("ab:cd:ef:ab:cd:ef"), "eth0")
        featuresreply[1].ports.append(p)
        xb = featuresreply.to_bytes()
        fr = Packet.from_bytes(xb, OpenflowHeader)
        self.assertEqual(fr, featuresreply)
        self._storePkt(featuresreply)

    def testEchoRequest(self):
        echoreq = OpenflowHeader.build(OpenflowType.EchoRequest, xid=0)        
        echoreq[1].data = b'\x01\x23\x45'
        b = echoreq.to_bytes()
        self.assertTrue(b.endswith(b'\x01\x23\x45'))
        another = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(echoreq, another)
        self._storePkt(echoreq)

    def testEchoReply(self):
        echorepl = OpenflowHeader.build(OpenflowType.EchoReply, xid=0)
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
        m.add_wildcard(OpenflowWildcard.DlSrc)
        m.add_wildcard(OpenflowWildcard.DlDst)
        xlist = m.wildcards
        m2 = OpenflowMatch()
        m2.from_bytes(m.to_bytes())
        self.assertListEqual(xlist, m2.wildcards)

    def testMatchOverlap1(self):
        m = OpenflowMatch()
        p = Ethernet() + IPv4() + ICMP()
        self.assertTrue(m.overlaps_with(m))
        m.wildcard_all()
        self.assertTrue(m.matches_packet(p))

    def testMatchOverlap2(self):
        m = OpenflowMatch()
        m2 = OpenflowMatch()
        m2.in_port = 5
        self.assertFalse(m.overlaps_with(m2))

    def testMatchOverlap3(self):
        m = OpenflowMatch()
        m2 = OpenflowMatch()
        m.in_port = 5
        m2.add_wildcard(OpenflowWildcard.InPort)
        self.assertTrue(m.matches_entry(m2))
        m.add_wildcard(OpenflowWildcard.InPort)
        self.assertTrue(m.overlaps_with(m2))

    def testMatchOverlap4(self):
        m = OpenflowMatch()
        m.nw_src = "1.2.3.4"
        m2 = OpenflowMatch()
        m2.nwsrc_wildcard = 32
        self.assertTrue(m.matches_entry(m2))
        m.nwsrc_wildcard = 32
        self.assertTrue(m.overlaps_with(m2))

    def testMatchOverlap5(self):
        m = OpenflowMatch()
        m.nw_src = "0.0.1.1"
        m2 = OpenflowMatch()
        m2.nwsrc_wildcard = 16
        self.assertTrue(m.matches_entry(m2))
        m.nwsrc_wildcard = 16
        self.assertTrue(m.overlaps_with(m2))
        self.assertFalse(m.overlaps_with(m2, strict=True))

    def testBuildMatch(self):
        pkt = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
              IPv4(src="1.2.3.4", dst="5.6.7.8", protocol=6) + \
              TCP(src=4000, dst=10000)
        m = OpenflowMatch.build_from_packet(pkt)
        self.assertEqual(m.dl_src, "11:22:33:44:55:66")
        self.assertEqual(m.dl_dst, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(m.dl_vlan, 0)
        self.assertEqual(m.dl_vlan_pcp, 0)
        self.assertEqual(m.nw_proto.value, 6)
        self.assertEqual(m.nw_tos, 0)
        self.assertEqual(str(m.nw_src), "1.2.3.4")
        self.assertEqual(str(m.nw_dst), "5.6.7.8")
        self.assertEqual(m.tp_src, 4000)
        self.assertEqual(m.tp_dst, 10000)

    def testPacketMatch(self):
        pkt = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
              IPv4(src="1.2.3.4", dst="5.6.7.8", protocol=6) + \
              TCP(src=4000, dst=10000)
        m = OpenflowMatch.build_from_packet(pkt)
        self.assertTrue(m.matches_packet(pkt))

        pkt[TCP].src = 42
        self.assertFalse(m.matches_packet(pkt))

        m.add_wildcard(OpenflowWildcard.TpSrc)
        self.assertTrue(m.matches_packet(pkt))

        pkt[IPv4].src = "1.2.3.0"
        self.assertFalse(m.matches_packet(pkt))

        m.nwsrc_wildcard = 8
        self.assertTrue(m.matches_packet(pkt))

    def testPacketMatch2(self):
        pkt = Ethernet(src="30:00:00:00:00:03", dst="30:00:00:00:00:02") + \
              IPv4(src="10.0.42.200", dst="172.16.42.2", protocol=1) + \
              ICMP() 
        m = OpenflowMatch(dl_src="30:00:00:00:00:03", dl_dst="30:00:00:00:00:02", \
                          nw_src="10.0.42.200", nw_dst="172.16.42.2", \
                          nw_proto=IPProtocol.ICMP, \
                          tp_src=8, tp_dst=0, \
                          dl_type=EtherType.IP, dl_vlan=65535, dl_vlan_pcp=0, \
                          in_port=2)
        self.assertTrue(m.matches_packet(pkt))
        
    def testError(self):
        e = OpenflowHeader.build(OpenflowType.Error, xid=0, version=0x01)
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
        pktin = OpenflowHeader.build(OpenflowType.PacketIn, xid=44, version=0x01)
        pktin[1].packet = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
                          IPv4(src="1.2.3.4", dst="5.6.7.8") + ICMP()
        pktin[1].in_port = OpenflowPort.NoPort
        self._storePkt(pktin)
        b = pktin.to_bytes()
        pktin2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(pktin, pktin2)

        pktin = OpenflowHeader.build(OpenflowType.PacketIn, xid=44)
        pktin[1].packet = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
                          IPv4(src="1.2.3.4", dst="5.6.7.8") + ICMP()
        pktin[1].in_port = 42
        pktin[1].buffer_id = 1334
        pktin[1].reason = OpenflowPacketInReason.NoMatch
        self._storePkt(pktin)
        b = pktin.to_bytes()
        pktin2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(pktin, pktin2)

    def testPacketOut(self):
        pktout = OpenflowHeader.build(OpenflowType.PacketOut, xid=43)
        pktout[1].buffer = 0xffffffff
        pktout[1].in_port = 4
        pktout[1].packet = Ethernet(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") + \
                           IPv4(src="1.2.3.4", dst="5.6.7.8") + ICMP()
        pktout[1].actions.append(ActionOutput(port=OpenflowPort.Flood))
        self._storePkt(pktout)
        b = pktout.to_bytes()
        pktout2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(pktout, pktout2)

    def testFlowMod(self):
        flowmod = OpenflowHeader.build(OpenflowType.FlowMod, xid=72) 
        flowmod[1].priority = 0xffee
        flowmod[1].hard_timeout = 3600
        flowmod[1].idle_timeout = 1800
        flowmod[1].buffer_id = 0xdeadbeef
        flowmod[1].cookie = 0xcafebeefbabe0000
        flowmod[1].match.add_wildcard(OpenflowWildcard.DlSrc)
        flowmod[1].match.add_wildcard(OpenflowWildcard.DlVlan)
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
        b = flowmod.to_bytes()
        flowmod2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(flowmod, flowmod2)

    def testFlowRemoved(self):
        flowrm = OpenflowHeader.build(OpenflowType.FlowRemoved, xid=43)
        flowrm[1].match.wildcard_all()
        flowrm[1].cookie = 42
        flowrm[1].priority = 0xabcd
        flowrm[1].duration = 5.005
        self.assertEqual(flowrm[1].duration_sec, 5)
        self.assertLessEqual(abs(flowrm[1].duration_nsec - 5000000), 1)
        self._storePkt(flowrm)
        b = flowrm.to_bytes()
        flowrm2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(flowrm, flowrm2)

    def testPortMod(self):
        portmod = OpenflowHeader.build(OpenflowType.PortMod)
        portmod[1].hwaddr = "b2:00:1d:9c:4f:40"
        portmod[1].set_config(OpenflowPortConfig.NoStp)
        portmod[1].set_mask(OpenflowPortConfig.NoStp)
        portmod[1].set_advertise(OpenflowPortFeatures.Pause)
        portmod[1].set_advertise(OpenflowPortFeatures.Fiber)
        portmod[1].set_advertise(OpenflowPortFeatures.e1Gb_Full)
        self._storePkt(portmod)
        b = portmod.to_bytes()
        portmod2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(portmod, portmod2)

    def testPortStatus(self):
        portstat = OpenflowHeader.build(OpenflowType.PortStatus)
        portstat[1].port.name = "testport"
        portstat[1].port.portnum = 13
        # FIXME: config capabilities, etc.
        self._storePkt(portstat)
        b = portstat.to_bytes()
        portstat2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(portstat, portstat2)

    def testBarrier(self):
        barrierreq = OpenflowHeader.build(OpenflowType.BarrierRequest)
        self._storePkt(barrierreq)
        barrierreq2 = Packet.from_bytes(barrierreq.to_bytes(), OpenflowHeader)
        self.assertEqual(barrierreq, barrierreq2)

        barrierreply = OpenflowHeader.build(OpenflowType.BarrierReply)
        self._storePkt(barrierreply)
        barrierrep2 = Packet.from_bytes(barrierreply.to_bytes(), OpenflowHeader)
        self.assertEqual(barrierreply, barrierrep2)

    def testQueueConfigRequest(self):
        qcfg = OpenflowHeader.build(OpenflowType.QueueGetConfigRequest)
        qcfg[1].port = 4
        self._storePkt(qcfg)
        b = qcfg.to_bytes()
        qcfg2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(qcfg, qcfg2)

    def testQueueConfigReply(self):
        qcfg = OpenflowHeader.build(OpenflowType.QueueGetConfigReply, xid=2)
        qcfg[1].port = 4
        qcfg[1].queues.append(OpenflowPacketQueue(queue_id=7))
        qcfg[1].queues[0].properties.append(OpenflowQueueMinRateProperty(rate=(40 * 10)))
        self._storePkt(qcfg)
        b = qcfg.to_bytes()
        qcfg2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(qcfg, qcfg2)

    def testSwitchStats(self):
        switchstatsreq = OpenflowHeader(OpenflowType.StatsRequest) + SwitchDescriptionStatsRequest()
        self._storePkt(switchstatsreq)
        b = switchstatsreq.to_bytes()
        sreq = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(switchstatsreq, sreq)

        switchstatsreply = OpenflowHeader(OpenflowType.StatsReply) + SwitchDescriptionStatsReply()
        self._storePkt(switchstatsreply)
        b = switchstatsreply.to_bytes()
        sreply = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(switchstatsreply, sreply)

    def testIndividualFlowStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + IndividualFlowStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply, 42) + IndividualFlowStatsReply()
        reply[1].table_id = 42
        reply[1].match.wildcard_all()
        reply[1].duration_sec = 5
        reply[1].duration_nsec = 16384
        reply[1].idle_timeout = 32
        reply[1].hard_timeout = 48
        reply[1].cookie = 4
        reply[1].packet_count = 10
        reply[1].byte_count = 11
        reply[1].priority = 0x2222
        reply[1].actions.append(ActionOutput(port=OpenflowPort.Flood))
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

    def testAggregateFlowStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + AggregateFlowStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply) + AggregateFlowStatsReply()
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

    def testTableStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + TableStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply) + TableStatsReply()
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

    def testPortStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + PortStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply) + PortStatsReply()
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

    def testQueueStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + QueueStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply) + QueueStatsReply()
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

    def testVendorStats(self):
        req = OpenflowHeader(OpenflowType.StatsRequest) + VendorStatsRequest()
        self._storePkt(req)
        b = req.to_bytes()
        req2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(req, req2)

        reply = OpenflowHeader(OpenflowType.StatsReply) + VendorStatsReply()
        self._storePkt(reply)
        b = reply.to_bytes()
        reply2 = Packet.from_bytes(b, OpenflowHeader)
        self.assertEqual(reply, reply2)

if __name__ == '__main__':
    unittest.main()
