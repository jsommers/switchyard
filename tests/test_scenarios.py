import sys
import os
import os.path
import unittest
import copy
import time

from switchyard.lib.common import ScenarioFailure, setup_logging
from switchyard.lib.testing import Scenario,PacketInputEvent,PacketOutputEvent,compile_scenario,uncompile_scenario,get_test_scenario_from_file
from switchyard.lib.packet import *
from switchyard.lib.address import *

class SrpyCompileTest(unittest.TestCase):
    CONTENTS1 = '''
from switchyard.lib.testing import *
from switchyard.lib.address import *
from switchyard.lib.packet import *

s = Scenario("ARP request")
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
        self.writeScenario1('stest.py', SrpyCompileTest.CONTENTS1)
        self.scenario = get_test_scenario_from_file('stest.py')
    
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
            os.unlink(name + '.switchy')
        except:
            pass

    def testScenarioFromPy(self):
        self.scenario.reset()
        self.assertIsInstance(self.scenario, Scenario)
        self.assertIsInstance(self.scenario.next(), PacketInputEvent)
        self.scenario.testpass()
        self.assertIsInstance(self.scenario.next(), PacketOutputEvent)
        self.scenario.testpass()
        self.assertRaises(ScenarioFailure, self.scenario.next)

    def testScenarioFromSrpy(self):
        # test that compilation and resurrection give the same scenario
        self.scenario.reset()
        compile_scenario('stest.py')
        self.assertTrue(os.stat('stest.switchy') != None)
        self.scenario_compiled = get_test_scenario_from_file('stest.switchy')
        self.assertIsInstance(self.scenario_compiled, Scenario)
        self.assertEqual(self.scenario, self.scenario_compiled)

    def testSlowOutput(self):
        self.scenario.reset()
        self.scenario.next()
        self.scenario.testpass()
        self.scenario.next()
        self.assertRaises(ScenarioFailure, time.sleep, 30)

    def testNoMorePending(self):
        self.scenario.reset()
        s = copy.deepcopy(self.scenario)
        s.pending_events.pop()
        s.next()
        s.testpass()
        self.assertRaises(ScenarioFailure, s.next)

    def testScenarioSanity(self):
        self.scenario.reset()
        self.scenario.scenario_sanity_check()

    def testInterfaces(self):
        p = self.scenario.reset()
        p = self.scenario.ports()
        self.assertIn('router-eth0', p)
        self.assertIn('router-eth1', p)
        self.assertIn('router-eth2', p)
        self.assertIn('router-eth3', p)


if __name__ == '__main__':
    setup_logging(False)
    unittest.main()
