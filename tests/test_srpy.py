import sys
import os
import os.path
import unittest
import copy
import time

from switchyard.switchy_test import run_tests
from switchyard.lib.common import ScenarioFailure, setup_logging
from switchyard.lib.testing import Scenario,PacketInputEvent,PacketOutputEvent,compile_scenario,uncompile_scenario,get_test_scenario_from_file
from switchyard.lib.packet import *
from switchyard.lib.address import *

class TestFrameworkTests(unittest.TestCase):
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


# test srpy calls like interface_by_ipaddr
# interface_by_name interface_by_macaddr; if the port_ calls are made,
# both actually get called; that will improve test coverage
# in switchyard.lib.common

if __name__ == '__main__':
    setup_logging(False)
    unittest.main() 