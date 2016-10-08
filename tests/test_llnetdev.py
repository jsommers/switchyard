#!/usr/bin/env python

'''
OF switch unit tests.
'''

import unittest
from unittest.mock import Mock
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import Scenario, SwitchyTestEvent
from switchyard.switchy_test import FakePyLLNet
from switchyard.switchy_real import PyLLNet

class WrapPyLLNet(PyLLNet):
    def __init__(self, devlist, name=None):
        LLNetBase.__init__(self)
        # don't call up to PyLLNet; avoid any actual pcap stuff
        
    def _fix_devinfo(self, dlist):
        self.devinfo = {}
        for i,d in enumerate(dlist):
            self.devinfo[d] = Interface(d, EthAddr('00:00:00:00:00:00'), IPAddr(i), '255.255.255.255', i)

class LLNetDevTests(unittest.TestCase):
    def setUp(self):
        self.scenario = Scenario('test')
        self.scenario.add_interface('eth1', '11:11:11:11:11:11')
        self.scenario.add_interface('eth0', '00:00:00:00:00:00')
        self.scenario.add_interface('eth2', '22:22:22:22:22:22')
        self.scenario.add_interface('eth7', '77:77:77:77:77:77')
        self.scenario.done = Mock(return_value=False)
        self.ev = Mock()
        self.ev.match = Mock(return_value=None)
        self.scenario.next = Mock(return_value=self.ev)
        self.fake = FakePyLLNet(self.scenario)

        self.devs = make_device_list([], [])
        self.real = WrapPyLLNet(self.devs)
        self.real._fix_devinfo(self.devs)
        self.real.pcaps = Mock()
        self.real.pcaps.get = Mock(return_value=Mock())

    def testFakeSendDevName(self):
        p = Packet()
        self.fake.send_packet("eth1", p)
        self.ev.match.assert_called_with(SwitchyTestEvent.EVENT_OUTPUT, device='eth1', packet=p)

    def testFakeSendDevNum(self):
        p = Packet()
        self.fake.send_packet(0, p)
        self.ev.match.assert_called_with(SwitchyTestEvent.EVENT_OUTPUT, device='eth1', packet=p)
        self.fake.send_packet(3, p)
        self.ev.match.assert_called_with(SwitchyTestEvent.EVENT_OUTPUT, device='eth7', packet=p)

    def testFakeSendIntfObj(self):
        p = Packet()
        ifmap = self.scenario.interfaces()
        self.fake.send_packet(ifmap['eth1'], p)
        self.ev.match.assert_called_with(SwitchyTestEvent.EVENT_OUTPUT, device='eth1', packet=p)
        self.fake.send_packet(ifmap['eth2'], p)
        self.ev.match.assert_called_with(SwitchyTestEvent.EVENT_OUTPUT, device='eth2', packet=p)

    def testRealSendDevName(self):
        p = Packet()
        for d in self.devs:
            self.real.send_packet(d, p)
            self.real.pcaps.get.assert_called_with(d, None)

    def testRealSendDevNum(self):
        p = Packet()
        for d,intf in self.real.devinfo.items():
            self.real.send_packet(intf.ifnum, p)
            self.real.pcaps.get.assert_called_with(intf.name, None)

    def testRealSendIntfObj(self):
        p = Packet()
        for d,intf in self.real.devinfo.items():
            self.real.send_packet(intf, p)
            self.real.pcaps.get.assert_called_with(intf.name, None)


if __name__ == '__main__':
    unittest.main()
