#!/usr/bin/env python

'''
OF switch unit tests.
'''

import sys
import asyncore
import socket
import unittest
from unittest.mock import MagicMock
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.openflow import *
from switchyard.lib.openflow.ofswitch import OpenflowSwitch, SwitchActionCallbacks


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
    def __init__(self):
        LLNetBase.__init__(self)
        self.devinfo['eth0'] = Interface('eth0', '11:22:33:44:55:66', '192.168.1.1', '255.255.255.0', 0)
        self.lastsent = None

    def recv_packet(self, timeout=None, timestamp=False):
        time.sleep(0.5)
        raise NoPackets()

    def send_packet(self, dev, packet):
        self.lastsent = (dev, packet)

    def shutdown(self):
        pass

class SwitchUnitTests(unittest.TestCase):
    def _receiver(self, sock, pkt):
        self.lastrecv = pkt

    def setUp(self):
        socket.socket = MagicMock(return_value=MagicMock()) 
        self.net = NetConnection()
        self.cb = SwitchActionCallbacks()

    def testHello(self):
        def switch_off(*args):
            self.switch._running = False

        self.switch = OpenflowSwitch(self.net, "abcdef00", self.cb)
        self.switch._send_openflow_message_internal = self._receiver
        hellopkt = OpenflowHeader.build(OpenflowType.Hello, xid=42)
        self.switch._receive_openflow_message_internal = MagicMock(return_value=hellopkt, side_effect=switch_off)
        self.switch._running = True

        self.switch.add_controller('localhost', 6633)
        self.switch._controller_thread(MagicMock())
        self.assertEqual(self.lastrecv[0].type, hellopkt[0].type)
        self.assertEqual(self.lastrecv[0].version, hellopkt[0].version)
        self.assertEqual(self.lastrecv[0].length, hellopkt[0].length)


if __name__ == '__main__':
    unittest.main()
