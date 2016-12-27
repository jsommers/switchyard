#!/usr/bin/env python

from copy import deepcopy
from switchyard.lib.userlib import *

def udp_stack_tests():
    s = TestScenario("UDP stack test (with pretend localhost)")
    s.add_interface('lo0', '00:00:00:00:00:00', '127.0.0.1', iftype=InterfaceType.Loopback)

    p = Null() + \
        IPv4(src='127.0.0.1',dst='127.0.0.1',protocol=IPProtocol.UDP) + \
        UDP(src=65535, dst=10000) + b'Hello stack'

    s.expect(PacketOutputEvent("lo0", p, exact=False, wildcards=[(UDP, 'src')]), "Emit UDP packet")

    reply = deepcopy(p)
    reply[1].src,reply[1].dst = reply[1].dst,reply[1].src
    reply[2].src,reply[2].dst = reply[2].dst,reply[2].src

    s.expect(PacketInputEvent('lo0', reply, 
        copyfromlastout=('lo0',UDP,'src',UDP,'dst')),
        "Receive UDP packet")

    return s

scenario = udp_stack_tests()
