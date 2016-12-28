#!/usr/bin/env python3

from switchyard.lib.userlib import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def inouttests():
    s = TestScenario("in/out basic tests")
    s.add_interface('eth0', '10:00:00:00:00:01', '172.16.42.1', '255.255.255.252')
    s.add_interface('eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('eth2', '10:00:00:00:00:03', '192.168.1.1', '255.255.255.0')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "The Ethernet frame should be forwarded back out eth1.")
    return s

scenario = inouttests()
