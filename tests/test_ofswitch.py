#!/usr/bin/env python

'''
OF (v13) switch unit tests.
'''

import sys
import asyncore
import socket
import unittest

from unittest.mock import MagicMock
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.exceptions import *
import switchyard.lib.openflow.openflow13 as of13
import switchyard.lib.openflow.openflow10 as of10
from switchyard.lib.openflow.ofswitch import OpenflowSwitch, SwitchActionCallbacks, FlowTable
from switchyard.llnetbase import LLNetBase
from switchyard.lib.interface import Interface


def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

class NetConnection(LLNetBase):
    '''
    Mock network for driving tests.
    '''
    def __init__(self):
        LLNetBase.__init__(self)
        self._devinfo['eth0'] = Interface('eth0', '11:22:33:44:55:66', '192.168.1.1', '255.255.255.0', 0)
        self.lastsent = None

    def recv_packet(self, timeout=None):
        time.sleep(0.5)
        raise NoPackets()

    def send_packet(self, dev, packet):
        self.lastsent = (dev, packet)

    def shutdown(self):
        pass

class SwitchUnitTests(unittest.TestCase):
    def _receiver(self, sock, pkt):
        self.lastrecv.append(pkt)

    def setUp(self):
        setattr(socket, "socket", MagicMock(return_value=MagicMock()))
        self.net = NetConnection()
        self.cb = SwitchActionCallbacks()

    def _setup_switch(self, pkt):
        self.switch = OpenflowSwitch(self.net, "abcdef00", self.cb)
        self.lastrecv = []
        self.switch._send_openflow_message_internal = self._receiver
        self.switch._running = False
        self.switch._receive_openflow_message_internal = MagicMock(return_value=pkt) 

    def testHello10(self):
        hellopkt = of10.OpenflowHeader.build(of10.OpenflowType.Hello, xid=42)
        self._setup_switch(hellopkt)
        self.switch._controller_thread(MagicMock())

        self.assertEqual(len(self.lastrecv), 1)
        pkt = self.lastrecv.pop()[0]
        self.assertEqual(pkt.type, of10.OpenflowType.Hello)
        self.assertEqual(pkt.version, 0x01)
        self.assertEqual(pkt.length, hellopkt[0].length)

    def testHello13(self):
        hellopkt = of13.OpenflowHeader.build(of13.OpenflowType.Hello, xid=42)
        self._setup_switch(hellopkt)
        self.switch._controller_thread(MagicMock())

        self.assertEqual(len(self.lastrecv), 1)
        pkt = self.lastrecv.pop()[0]
        self.assertEqual(pkt.type, of13.OpenflowType.Hello)
        self.assertEqual(pkt.version, 0x04)
        self.assertEqual(pkt.length, hellopkt[0].length)

    def testBarrier10(self):
        barrier = of10.OpenflowHeader.build(of10.OpenflowType.BarrierRequest, xid=42)
        self._setup_switch(barrier)
        self.switch._controller_thread(MagicMock())

        pkt = self.lastrecv.pop()[0]
        self.assertEqual(pkt.type, of10.OpenflowType.BarrierReply)
        self.assertEqual(pkt.version, barrier[0].version)
        self.assertEqual(pkt.length, barrier[0].length)

    def testBarrier13(self):
        barrier = of13.OpenflowHeader.build(of13.OpenflowType.BarrierRequest, xid=42)
        self._setup_switch(barrier)
        self.switch._controller_thread(MagicMock())

        pkt = self.lastrecv.pop()[0]
        self.assertEqual(pkt.type, of13.OpenflowType.BarrierReply)
        self.assertEqual(pkt.version, barrier[0].version)
        self.assertEqual(pkt.length, barrier[0].length)

    def testFeaturesRequest10(self):
        request = of10.OpenflowHeader.build(of10.OpenflowType.FeaturesRequest, xid=42)
        self._setup_switch(request)
        self.switch._controller_thread(MagicMock())

        self.assertEqual(len(self.lastrecv), 1)
        pkt = self.lastrecv.pop()[0]
        print(pkt)

    def testData1(self):
        self.switch = OpenflowSwitch(self.net, "abcdef00", self.cb)
        self.switch._send_openflow_message_internal = self._receiver
        self.switch._running = False

        self.switch._handle_datapath("eth0", Ethernet() + IPv4() + ICMP())



    # def testTable1(self):
    #     table = FlowTable(self.cb)
    #     flowmod = OpenflowHeader.build(OpenflowType.FlowMod, xid=72) 
    #     flowmod[1].priority = 0xffee
    #     flowmod[1].hard_timeout = 3600
    #     flowmod[1].idle_timeout = 1800
    #     flowmod[1].buffer_id = 0xdeadbeef
    #     flowmod[1].cookie = 0xcafebeefbabe0000
    #     flowmod[1].match.add_wildcard(OpenflowWildcard.DlSrc)
    #     flowmod[1].match.add_wildcard(OpenflowWildcard.DlVlan)
    #     flowmod[1].match.add_wildcard(OpenflowWildcard.TpSrc)
    #     flowmod[1].match.add_wildcard(OpenflowWildcard.TpDst)
    #     flowmod[1].match.dl_dst = "55:44:33:22:ab:cd"
    #     flowmod[1].match.nw_src = "149.43.0.0"
    #     flowmod[1].match.nwsrc_wildcard = 16
    #     flowmod[1].match.in_port = 42
    #     flowmod[1].set_flag(FlowModFlags.CheckOverlap)
    #     flowmod[1].actions.append(ActionOutput(port=OpenflowPort.Flood))
      
    #     rv = table.add(flowmod[1])
    #     self.assertEqual(len(table), 1)
    #     self.assertIsNone(rv)

    #     rv = table.add(flowmod[1])
    #     self.assertEqual(len(table), 1)
    #     self.assertEqual(rv, OpenflowFlowModFailedCode.Overlap)

    #     p = Ethernet() + IPv4() + UDP()
    #     p[0].dst = "55:44:33:22:ab:cd"
    #     p[1].src = "149.43.80.25"
    #     rv = table.match_packet(p)
    #     self.assertEqual(len(rv), 1)
    #     self.assertIsInstance(rv[0], ActionOutput)

    #     p[2].srcport = 10000
    #     p[2].dstport = 80
    #     rv = table.match_packet(p)
    #     self.assertEqual(len(rv), 1)
    #     self.assertIsInstance(rv[0], ActionOutput)

    #     p[1].src = "8.8.8.8"
    #     rv = table.match_packet(p)
    #     self.assertIsNone(rv)


    # def testTable2(self):
    #     p = Ethernet() + IPv4() + UDP()
    #     # flowmod = OpenflowFlowMod(OpenflowMatch.build_from_packet(p))
    #     flowmod = OpenflowHeader.build(OpenflowType.FlowMod, OpenflowMatch.build_from_packet(p), xid=42)
    #     flowmod[1].hard_timeout = 1
    #     flowmod[1].match.in_port = 13
    #     flowmod[1].actions.append(ActionEnqueue(port=13, queue_id=0))

    #     table = FlowTable(self.cb)
    #     rv = table.add(flowmod[1])
    #     self.assertIsNone(rv)

    #     rv = table.match_packet(p)
    #     self.assertEqual(len(rv), 1)
    #     self.assertIsInstance(rv[0], ActionEnqueue)

    #     # test that matched entry counters go up
    #     # test that expiration happens correctly (with flag, should send remove, w/o no flowremove)

        
    #     # flowmod[1].set_flag(FlowModFlags.CheckOverlap)
    #     # flowmod[1].set_flag(FlowModFlags.SendFlowRemove)
    #     # flowmod[1].set_flag(FlowModFlags.Emergency)


if __name__ == '__main__':
    unittest.main()
