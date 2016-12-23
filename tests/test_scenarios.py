import sys
import os
import os.path
import unittest
import copy
import time
import importlib

from switchyard.lib.logging import setup_logging
from switchyard.lib.testing import TestScenario,PacketInputEvent,PacketOutputEvent,compile_scenario,uncompile_scenario,get_test_scenario_from_file, TestScenarioFailure
from switchyard.lib.packet import *
from switchyard.lib.address import *

class SrpyCompileTest(unittest.TestCase):
    CONTENTS1 = '''
from switchyard.lib.userlib import *

s = TestScenario("ARP request")
s.timeout = 1
s.add_interface('router-eth0', '40:00:00:00:00:00', '192.168.1.1', '255.255.255.0')
s.add_interface('router-eth1', '40:00:00:00:00:01', '192.168.100.1', '255.255.255.0')
s.add_interface('router-eth2', '40:00:00:00:00:02', '10.0.1.2', '255.255.255.0')
s.add_interface('router-eth3', '40:00:00:00:00:03', '10.1.1.2', '255.255.255.0')

# arp coming from client
arpreq = create_ip_arp_request("30:00:00:00:00:01", "10.1.1.1", "10.1.1.2")
s.expect(PacketInputEvent("router-eth3", arpreq), "Incoming ARP request")

arprep = create_ip_arp_reply("40:00:00:00:00:03", "30:00:00:00:00:01", "10.1.1.2", "10.1.1.1")

s.expect(PacketOutputEvent("router-eth3", arprep), "Outgoing ARP reply")
scenario = s
'''

    def setUp(self):
        importlib.invalidate_caches()
        self.writeScenario1('stest.py', SrpyCompileTest.CONTENTS1)
    
    def tearDown(self):
        self.removeScenario('stest')

    def writeScenario1(self, name, contents):
        outfile = open(name, 'w')
        outfile.write(contents)
        outfile.close()

    def removeScenario(self, name):
        try:
            os.unlink(name + '.py')
        except:
            pass
        try:
            os.unlink(name + '.pyc')
        except:
            pass
        try:
            os.unlink(name + '.srpy')
        except:
            pass

    def testScenarioFromPy(self):
        self.scenario = get_test_scenario_from_file('stest.py')
        self.assertIsInstance(self.scenario, TestScenario)
        self.assertIsInstance(self.scenario.next(), PacketInputEvent)
        self.scenario.testpass()
        self.assertIsInstance(self.scenario.next(), PacketOutputEvent)
        self.scenario.testpass()
        self.assertRaises(TestScenarioFailure, self.scenario.next)

    def testScenarioFromSrpy(self):
        # test that compilation and resurrection give the same scenario
        self.scenario = get_test_scenario_from_file('stest.py')
        compile_scenario('stest.py')
        self.assertTrue(os.stat('stest.srpy') != None)
        self.scenario_compiled = get_test_scenario_from_file('stest.srpy')
        self.assertIsInstance(self.scenario_compiled, TestScenario)
        self.assertEqual(self.scenario, self.scenario_compiled)

    def testSlowOutput(self):
        self.scenario = get_test_scenario_from_file('stest.py')
        self.scenario.next()
        self.scenario.testpass()
        self.scenario.next()
        self.assertRaises(TestScenarioFailure, time.sleep, 61)

    def testNoMorePending(self):
        self.scenario = get_test_scenario_from_file('stest.py')
        s = copy.deepcopy(self.scenario)
        s._pending_events.pop()
        s.next()
        s.testpass()
        self.assertRaises(TestScenarioFailure, s.next)

    def testScenarioSanity(self):
        self.scenario = get_test_scenario_from_file('stest.py')
        self.scenario.scenario_sanity_check()

    def testInterfaces(self):
        self.scenario = get_test_scenario_from_file('stest.py')
        p = self.scenario.ports()
        self.assertIn('router-eth0', p)
        self.assertIn('router-eth1', p)
        self.assertIn('router-eth2', p)
        self.assertIn('router-eth3', p)

    def testMiscScenario(self):
        setupok = teardownok = False
        def xup():
            nonlocal setupok
            setupok = True
        def xdown():
            nonlocal teardownok
            teardownok = True
        s = TestScenario("random")
        self.assertEqual(s.name, "random")
        s.add_file("xfiletest.txt", '''this is a test''')
        s.setup = xup
        s.teardown = xdown
        self.assertIs(s.setup, xup)
        self.assertIs(s.teardown, xdown)
        s.do_setup()
        s.do_teardown()
        self.assertTrue(setupok)
        self.assertTrue(teardownok)
        s.write_files()
        rv = os.lstat("xfiletest.txt")
        self.assertIsNotNone(rv)
        with open("xfiletest.txt") as f:
            contents = f.read()
        self.assertEqual(contents, "this is a test")
        os.unlink("xfiletest.txt")

        with self.assertRaises(Exception):
            PacketOutputEvent()

        with self.assertRaises(Exception):
            PacketOutputEvent("dev1")

        s2 = TestScenario("random")
        self.assertEqual(s, s2)
        s.add_interface("eth0", "00:00:00:11:11:11")
        s2.add_interface("eth1", "00:00:00:11:11:11")
        self.assertEqual(s, s2)
        p = Packet()
        s.expect(PacketOutputEvent("eth0", p), "pktout")
        s2.expect(PacketOutputEvent("eth0", p), "pktout")
        self.assertEqual(s, s2)
        s2.expect(PacketOutputEvent("eth1", p), "pktout2")
        self.assertNotEqual(s, s2)
        s.expect(PacketOutputEvent("eth1", p), "pktout2")
        self.assertEqual(s, s2)
        s.expect(PacketInputEvent("eth0", p), "pkt3")
        s2.expect(PacketOutputEvent("eth1", p), "pkt3")
        self.assertNotEqual(s, s2)
        self.assertNotEqual(s, 42)

if __name__ == '__main__':
    setup_logging(False)
    unittest.main()
