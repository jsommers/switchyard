#!/usr/bin/env python

from copy import deepcopy
from switchyard.lib.userlib import *

def udp_stack_tests():
    s = TestScenario("UDP stack test (with pretend localhost)")
    s.add_interface('lo0', '00:00:00:00:00:00', '127.0.0.1', iftype=InterfaceType.Loopback)

    p = Null() + \
        IPv4(srcip='127.0.0.1',dstip='127.0.0.1',protocol=IPProtocol.UDP) + \
        UDP(srcport=65535, dstport=10000) + b'Hello stack'

    s.expect(PacketOutputEvent("lo0", p, exact=False, wildcard=['tp_src']), "Emit UDP packet")

    reply = deepcopy(p)
    reply[1].src,reply[1].dst = reply[1].dst,reply[1].src
    reply[2].srcport,reply[2].dstport = reply[2].dstport,reply[2].srcport

    s.expect(PacketInputEvent('lo0', reply, 
        copyfromlastout=('lo0',UDP,'srcport',UDP,'dstport')),
        "Receive UDP packet")

    return s

scenario = udp_stack_tests()
