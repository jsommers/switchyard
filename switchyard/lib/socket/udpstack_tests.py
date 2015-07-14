#!/usr/bin/env python

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *

def udp_stack_tests():
    s = Scenario("hub tests")
    s.add_interface('eth0', '10:00:00:00:00:01')

    p = Ethernet() + IPv4() + UDP() + b'Hello, world'
    p[0].src = '10:00:00:00:00:01'
    p[0].dst = '20:00:00:00:00:01'
    p[1].srcip = '127.0.0.1'
    p[1].dstip = '10.0.1.7'
    p[1].protocol = IPProtocol.UDP
    p[2].srcport = 10000
    p[2].dstport = 10000

    s.expect(PacketOutputEvent("eth0", p), "Emit UDP packet")
    s.expect(PacketInputEvent("eth0", p), "Receive UDP packet")

    return s

scenario = udp_stack_tests()
