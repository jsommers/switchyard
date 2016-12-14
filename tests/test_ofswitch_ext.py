#!/usr/bin/env python

'''
OF switch tests for use with an external controller.
'''

import sys
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.testing import *
from switchyard.lib.openflow import *


def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def ofswitch_tests():
    s = TestScenario("Openflow Switch Tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt(
        "30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet),
             "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketInputTimeoutEvent(timeout=5), description="Wait for events to complete")
    s.expect(PacketOutputEvent("eth2", testpkt, "eth0", testpkt, display=Ethernet),
             "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")
    # test case 2: frame with dest 30:...:02 should be sent out eth 1 (from where bcast frame arrived)
    testpkt2 = mk_pkt(
        "30:00:00:00:00:03", "30:00:00:00:00:02", "10.0.42.200", "172.16.42.2")
    s.expect(PacketInputEvent("eth2", testpkt2, display=Ethernet),
             "An Ethernet frame with a destination address 172.16.42.2 should arrive on eth2")
    s.expect(PacketInputTimeoutEvent(timeout=5), description="Wait for events to complete")
    s.expect(PacketOutputEvent("eth1", testpkt2, display=Ethernet),
             "An Ethernet frame with a destination address 172.16.42.2 should be forwarded out port eth1")
    s.expect(PacketInputTimeoutEvent(timeout=5), description="Wait for events to complete")

    # test case 3: dest port for 30::03 should have been learned from previous exchange
    testpkt3 = mk_pkt(
        "30:00:00:00:00:01", "30:00:00:00:00:03", "172.16.42.2", "10.1.13.13")
    s.expect(PacketInputEvent("eth0", testpkt3, display=Ethernet),
             "An Ethernet frame with a destination address 10.1.13.13 should arrive on eth0")
    s.expect(PacketInputTimeoutEvent(timeout=5), description="Wait for events to complete")
    s.expect(PacketOutputEvent("eth2", testpkt3, display=Ethernet),
             "An Ethernet frame with a destination address 10.1.13.13 should be forwarded out port eth2")

    return s


scenario = ofswitch_tests()
