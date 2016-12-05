import sys
import os
import os.path
import importlib
import unittest
from unittest.mock import Mock
import copy
import time
from io import StringIO
from contextlib import ContextDecorator
import re

from switchyard.llnettest import run_tests, main_test
from switchyard.lib.exceptions import TestScenarioFailure
from switchyard.lib.logging import setup_logging
from switchyard.lib.testing import *
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.hostfirewall import Firewall

from contextlib import ContextDecorator

class Opt(object):
    pass

class redirectio(ContextDecorator):
    def __init__(self):
        self.iobuf = StringIO()

    def __enter__(self):
        self.stdout = getattr(sys, 'stdout')
        self.stderr = getattr(sys, 'stderr')
        setattr(sys, 'stdout', self.iobuf)
        setattr(sys, 'stderr', self.iobuf)
        return self

    def __exit__(self, *exc):
        setattr(sys, 'stdout', self.stdout)
        setattr(sys, 'stderr', self.stderr)
        return False

    @property 
    def contents(self):
        return self.iobuf.getvalue()


class TestFrameworkTests(unittest.TestCase):
    CONTENTS1 = '''
from switchyard.lib.userlib import *

s = TestScenario("ARP request")
s.timeout = 1.0
s.add_interface('router-eth0', '40:00:00:00:00:00', '192.168.1.1', '255.255.255.0')
s.add_interface('router-eth1', '40:00:00:00:00:01', '192.168.100.1', '255.255.255.0')
s.add_interface('router-eth2', '40:00:00:00:00:02', '10.0.1.2', '255.255.255.0')
s.add_interface('router-eth3', '40:00:00:00:00:03', '10.1.1.2', '255.255.255.0')

# arp coming from client
arpreq = create_ip_arp_request("30:00:00:00:00:01", "10.1.1.1", "10.1.1.2")
arprep = create_ip_arp_reply("40:00:00:00:00:03", "30:00:00:00:00:01", "10.1.1.2", "10.1.1.1")

s.expect(PacketInputEvent("router-eth3", arpreq), "Incoming ARP request")
s.expect(PacketOutputEvent("router-eth3", arprep), "Outgoing ARP reply (1)")
s.expect(PacketInputTimeoutEvent(0.5), "Timeout on recv")
s.expect(PacketOutputEvent("router-eth3", arprep), "Outgoing ARP reply (2)")

scenario = s
'''

    CONTENTS2 = '''
from switchyard.lib.userlib import *

s = TestScenario("Ref to prev pkt")
s.timeout = 1.0
s.add_interface('lo0', '00:00:00:00:00:00', '127.0.0.1', iftype=InterfaceType.Loopback)
p = Null() + IPv4(srcip='127.0.0.1',dstip='127.0.0.1',protocol=IPProtocol.UDP) + UDP(srcport=65535, dstport=10000) + b'Hello stack'
s.expect(PacketOutputEvent("lo0", p, exact=False, wildcard=['tp_src']), "Emit UDP packet")

reply = deepcopy(p)
reply[1].src,reply[1].dst = reply[1].dst,reply[1].src
reply[2].srcport,reply[2].dstport = reply[2].dstport,reply[2].srcport
s.expect(PacketInputEvent("lo0", reply, copyfromlastout=('lo0',UDP,'srcport',UDP,'dstport')), "Receive UDP packet")
scenario = s
'''

    CONTENTS3 = '''
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
'''

    USERCODE1 = '''
def main(obj):
    pass
'''

    USERCODE2 = '''
def main(obj):
    obj.recv_packet()
'''

    USERCODE3 = '''
def main(obj):
    obj.recv_packet()
    obj.recv_packet()
'''

    USERCODE4 = '''
from time import sleep
def main(obj):
    obj.recv_packet()
    sleep(30)
    obj.recv_packet()
'''

    USERCODE5 = '''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.testing import *

def main(obj):
    obj.recv_packet()
    pkt = create_ip_arp_reply("40:00:00:00:00:03", "30:00:00:00:00:01", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth3', pkt)
    try:
        obj.recv_packet()
    except NoPackets:
        pass

    obj.send_packet('router-eth3', pkt)
'''

    USERCODE6 = '''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.testing import *

def main(obj):
    obj.recv_packet()
    pkt = create_ip_arp_reply("40:00:00:00:00:03", "30:00:00:00:00:01", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth3', pkt)
    try:
        obj.recv_packet()
    except NoPackets:
        pass

    obj.send_packet('router-eth3', pkt)
    obj.recv_packet()
'''

    USERCODE7 = '''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.testing import *

def main(obj):
    obj.recv_packet()
    pkt = create_ip_arp_reply("40:00:00:00:00:03", "30:00:00:00:00:01", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth3', pkt)
    try:
        obj.recv_packet()
    except NoPackets:
        pass

    obj.send_packet('router-eth3', pkt)
    obj.send_packet('router-eth3', pkt)
'''

    USERCODE8 = '''
def main(obj):
    1/0 # epic fail
'''

    USERCODE9 = '''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.testing import *

def main(obj):
    obj.recv_packet()
    pkt = create_ip_arp_reply("40:00:00:00:00:AB", "30:00:00:00:00:CD", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth2', pkt)
'''

    USERCODE10 = '''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.testing import *

def main(obj):
    obj.recv_packet()
    pkt = create_ip_arp_reply("40:00:00:00:00:AB", "30:00:00:00:00:CD", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth3', pkt)
'''

    USERCODE11 = '''
from switchyard.lib.userlib import *
def main(obj):
    pkt = create_ip_arp_reply("40:00:00:00:00:AB", "30:00:00:00:00:CD", "10.1.1.2", "10.1.1.1")
    obj.send_packet('router-eth3', pkt)
'''

    USERCODE12 = '''
from switchyard.lib.userlib import *
from random import randint
from copy import copy

def main(obj):
    xport = randint(1024,65535)
    p = Null() + IPv4(srcip='127.0.0.1',dstip='127.0.0.1',protocol=IPProtocol.UDP) + UDP(srcport=xport, dstport=10000) + b'Test this!'
    obj.send_packet('lo0', p)
    print("After send")
    pkt2 = obj.recv_packet()
    print("Checking header")
    udphdr = pkt2.packet.get_header(UDP)
    print("UDP header received: ".format(udphdr))
    if udphdr.dstport == xport:
        print("Ports match!")
    else:
        print("Ports don't match")
    obj.shutdown()
'''

    USERCODE13 = '''
import sys
from switchyard.lib.userlib import *
from switchyard.llnetreal import LLNetReal

def main(net):
    # beware of limitations using loopback interface w/libpcap on
    # non-macos (e.g., linux) platforms.  haven't yet tested it on
    # platforms besides macos.
    if isinstance(net, LLNetReal) and sys.platform != 'darwin': 
        raise Exception("This example only works on macos at present")

    # find the loopback interface
    intf = None
    for i in net.interfaces():
        if i.iftype == InterfaceType.Loopback:
            intf = i
            break
    if intf is None:
        raise Exception("This example is designed to use the loopback interface but I didn't find one")

    while True:
        appdata = None
        try:
            appdata = ApplicationLayer.recv_from_app(timeout=0.1)
        except NoPackets:
            pass
        except Shutdown:
            break
        if appdata is not None:
            handle_app_data(net, intf, appdata)

        netdata = None
        try:
            netdata = net.recv_packet(timeout=0.1)
        except NoPackets:
            pass
        except Shutdown:
            break
        if netdata is not None:
            handle_network_data(netdata)

    net.shutdown()

def handle_app_data(net, intf, appdata):
    flowaddr,message = appdata
    log_debug("Received data from app layer: <{}>".format(message))
    log_debug("flowaddr: {}".format(flowaddr))

    proto,srcip,srcport,dstip,dstport = flowaddr
    p = Null() + IPv4(protocol=proto, srcip=srcip, dstip=dstip, ipid=0xabcd, ttl=64, flags=IPFragmentFlag.DontFragment) + UDP(srcport=srcport,dstport=dstport) + message

    log_debug("Sending {} to {}".format(p, intf.name))
    net.send_packet(intf, p)

def handle_network_data(netdata):
    timestamp, ingress, pkt = netdata
    log_debug("On {} received {}".format(ingress, pkt))
    if pkt.has_header(IPv4):
        ipidx = pkt.get_header_index(IPv4)
        ip = pkt[ipidx]
        if pkt[ipidx].protocol == IPProtocol.UDP:
            udp = pkt.get_header(UDP)
            ApplicationLayer.send_to_app(IPProtocol.UDP, (ip.dst, udp.dstport),
            (ip.src, udp.srcport), pkt[-1].data)
        elif pkt[ipidx].protocol == IPProtocol.ICMP:
            log_info("Received ICMP message: {}".format(pkt[ipidx+1]))
        else:
            log_info("Received an unexpected packet: {}".format(pkt[1:]))
'''
    APPCODE13 = '''
import switchyard.lib.socket.socketemu as socket
import time

HOST = '127.0.0.1'
PORT = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)

print("Sending message to server at {},{}".format(HOST,PORT))
s.sendto(b'Hello, stack', (HOST,PORT))
try:
    data,addr = s.recvfrom(1024)
    print('Client socket application received message from {}: {}'.format(repr(addr),data.decode('utf8')))
except:
    print("Timeout")

s.close()
'''

    def setUp(self):
        importlib.invalidate_caches()
        Firewall._instance = None

    @classmethod
    def setUpClass(cls):
        def writeFile(name, contents):
            outfile = open(name, 'w')
            outfile.write(contents)
            outfile.close()
            
        writeFile('stest.py', TestFrameworkTests.CONTENTS1)
        writeFile('stest2.py', TestFrameworkTests.CONTENTS2)
        writeFile('stest3.py', TestFrameworkTests.CONTENTS3)
        writeFile('ucode1.py', TestFrameworkTests.USERCODE1)
        writeFile('ucode2.py', TestFrameworkTests.USERCODE2)
        writeFile('ucode3.py', TestFrameworkTests.USERCODE3)
        writeFile('ucode4.py', TestFrameworkTests.USERCODE4)
        writeFile('ucode5.py', TestFrameworkTests.USERCODE5)
        writeFile('ucode6.py', TestFrameworkTests.USERCODE6)
        writeFile('ucode7.py', TestFrameworkTests.USERCODE7)
        writeFile('ucode8.py', TestFrameworkTests.USERCODE8)
        writeFile('ucode9.py', TestFrameworkTests.USERCODE9)
        writeFile('ucode10.py', TestFrameworkTests.USERCODE10)
        writeFile('ucode11.py', TestFrameworkTests.USERCODE11)
        writeFile('ucode12.py', TestFrameworkTests.USERCODE12)
        writeFile('ucode13.py', TestFrameworkTests.USERCODE13)
        writeFile('appcode13.py', TestFrameworkTests.APPCODE13)

        sys.path.append('.')
        sys.path.append(os.getcwd())
        sys.path.append(os.path.join(os.getcwd(),'tests'))
        sys.path.append(os.path.join(os.getcwd(),'..'))

        cls.opt_compile = Opt()
        cls.opt_compile.verbose = False
        cls.opt_compile.testmode = True
        cls.opt_compile.compile = True
        cls.opt_compile.debug = False
        cls.opt_compile.dryrun = False
        cls.opt_compile.nohandle = False
        cls.opt_compile.nopdb = True
        cls.opt_compile.cli = False
        cls.opt_compile.fwconfig = []
        cls.opt_compile.tests = []
        cls.opt_compile.usercode = None

        cls.opt_nocompile = copy.copy(cls.opt_compile)
        cls.opt_nocompile.compile = False

        cls.opt_app = copy.copy(cls.opt_nocompile)

        cls.opt_dryrun = copy.copy(cls.opt_compile)
        cls.opt_dryrun.compile = False
        cls.opt_dryrun.dryrun = True

    @classmethod
    def copyOptions(cls):
        return copy.copy(cls.opt_nocompile)
    
    @classmethod
    def tearDownClass(cls):
        def removeFile(name):
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

        removeFile('stest')
        removeFile('stest2')
        removeFile('stest3')
        removeFile('appcode13')
        for t in range(1, 14):
            removeFile("ucode{}".format(t))

    def testDryRun(self):
        with self.assertLogs(level='INFO') as cm:
            main_test('ucode1.py', ['stest'], TestFrameworkTests.opt_dryrun)
        self.assertIn('Imported your code successfully', cm.output[0])
        with self.assertLogs(level='INFO') as cm:
            main_test('ucode1', ['stest'], TestFrameworkTests.opt_dryrun)
        self.assertIn('Imported your code successfully', cm.output[0])

    def testNoScenario(self):
        with self.assertLogs(level='ERROR') as cm:
            main_test('ucode1', [], TestFrameworkTests.opt_compile)
        self.assertIn('no scenarios', cm.output[0])

    def testCompileOutput(self):
        with self.assertLogs(level='INFO') as cm:
            main_test('ucode1', ['stest'], TestFrameworkTests.opt_compile)
        self.assertIn('Compiling', cm.output[0])
        self.assertIsNotNone(os.stat('stest.srpy'))

    def testEmptyUserProgram(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode1', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('0 passed, 1 failed, 3 pending', xio.contents)
        self.assertNotIn('All tests passed', xio.contents)

    def testCleanScenario(self):
        scen = get_test_scenario_from_file('stest')
        self.assertFalse(scen.done())
        self.assertEqual(len(scen._pending_events), 4)
        self.assertListEqual(scen._completed_events, [])

    def testOneRecvCall(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode2', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('1 passed, 1 failed, 2 pending', xio.contents)
        self.assertRegex(xio.contents, re.compile('Passed:\s*1\s*Incoming ARP request', re.M))
        self.assertRegex(xio.contents, re.compile('Failed:\s*Outgoing ARP reply',re.M))

    def testTwoRecvCalls(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode3', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('1 passed, 1 failed, 2 pending', xio.contents)
        self.assertRegex(xio.contents, re.compile('Passed:\s*1\s*Incoming ARP request', re.M))
        self.assertRegex(xio.contents, re.compile('Failed:\s*Outgoing ARP reply',re.M))
        self.assertRegex(xio.contents, re.compile('recv_packet\s+called,\s+but\s+I\s+was\s+expecting\s+send_packet', re.M))

    def testDelayedSent(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode4', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('1 passed, 1 failed, 2 pending', xio.contents)
        self.assertRegex(xio.contents, re.compile('Passed:\s*1\s*Incoming ARP request', re.M))
        self.assertRegex(xio.contents, re.compile('Failed:\s*Outgoing ARP reply',re.M))
        self.assertRegex(xio.contents, re.compile('1\s+Timeout on recv', re.M))

    def testScenarioTimeoutHandledCorrectly(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode5', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('4 passed, 0 failed, 0 pending', xio.contents)
        self.assertIn('All tests passed', xio.contents)

    def testShutdownSignal(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode6', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('4 passed, 0 failed, 0 pending', xio.contents)
        self.assertIn('All tests passed', xio.contents)

    def testTooManySends(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode7', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('4 passed, 0 failed, 0 pending', xio.contents)
        self.assertRegex(xio.contents, 
            re.compile('Your\s+code\s+didn\'t\s+crash,\s+but\s+something\s+unexpected\s+happened.', re.M))
        self.assertNotIn('All tests passed', xio.contents)

    def testEpicFail(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode8', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertNotIn('All tests passed', xio.contents)
        self.assertIn('0 passed, 1 failed, 3 pending', xio.contents)
        self.assertRegex(xio.contents, 
            re.compile('Your\s+code\s+crashed', re.M))

    def testDeviceMatchFail(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode9', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('1 passed, 1 failed, 2 pending', xio.contents)
        self.assertRegex(xio.contents, 
            re.compile('output\s+on\s+device\s+router-eth2\s+unexpected', re.M))

    def testPacketMatchFail(self):
        with redirectio() as xio:
            with self.assertLogs(level='INFO') as cm:
                main_test('ucode10', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('1 passed, 1 failed, 2 pending', xio.contents)
        self.assertRegex(xio.contents, 
            re.compile('an\s+exact\s+match\s+failed', re.M | re.I))

    def testSendInsteadOfRecv(self):
        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                main_test('ucode11', ['stest'], TestFrameworkTests.opt_nocompile)
        self.assertIn('send_packet was called, but I was expecting recv_packet', xio.contents)

    def testRefToPrevInTest(self):
        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                main_test('ucode12', ['stest2'], TestFrameworkTests.opt_nocompile)
        self.assertIn("Ports match", xio.contents)
        self.assertIn("Test pass", cm.output[-1])

    def testSockemu(self):
        from switchyard.syinit import start_framework
        TestFrameworkTests.opt_app.app = "appcode13"
        TestFrameworkTests.opt_app.tests = ['stest3']
        TestFrameworkTests.opt_app.usercode = 'ucode13'

        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                start_framework(TestFrameworkTests.opt_app)
        self.assertIn("All tests passed", xio.contents)
        self.assertIn("Client socket application received message", xio.contents)
        self.assertIn("Adding firewall/bpf rule udp dst port", cm.output[4])
        del(start_framework)

    def testNoCode(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.usercode = None
        opt.compile = False
        opt.tests = ['stest3']
        opt.verbose = True
        with self.assertLogs(level='DEBUG') as cm:
            start_framework(opt)
        self.assertIn("need to specify the name of your module to run", cm.output[-1])
        del(start_framework)

    def testCompileWithCode(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.compile = True
        opt.usercode = 'ucode13'
        opt.tests = ['stest3']
        opt.app = None #"appcode13"
        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                start_framework(opt)
        self.assertIn("specified user code to run with compile flag", cm.output[0])
        self.assertIn("Doing sanity check", cm.output[-1])
        del(start_framework)

    def testFailUserCode(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.usercode = 'doesntexist'
        opt.tests = ['stest3']
        opt.app = "appcode13"
        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                with self.assertRaises(ImportError):
                    start_framework(opt)
        del(start_framework)

    def testFailAppCode(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.usercode = 'ucode13'
        opt.app = "doesntexist"
        opt.tests = ['stest3']
        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                start_framework(opt)
        self.assertIn("No module named 'doesntexist'", xio.contents)
        del(start_framework)

    def testReal(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.usercode = 'ucode13'
        opt.app = "appcode13"
        opt.tests = None
        opt.exclude = None
        opt.intf = None
        mrmock = Mock(return_value=True)
        mdlmock = Mock(return_value=['fakedev'])
        netmock = Mock(return_value=Mock())
        import switchyard.syinit
        setattr(switchyard.syinit, "main_real", mrmock)
        setattr(switchyard.syinit, "make_device_list", mrmock)
        setattr(switchyard.syinit, "LLNetReal", netmock)

        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                start_framework(opt)

        self.assertIn("WARNING:root:You're running in real mode, but not as root", cm.output[-1])
        del(start_framework)

    def testReal2(self):
        from switchyard.syinit import start_framework
        opt = TestFrameworkTests.copyOptions()
        opt.usercode = 'ucode13'
        opt.app = None
        opt.tests = None
        opt.exclude = None
        opt.intf = None
        opt.fwconfig = []
        mrmock = Mock(return_value=True)
        mdlmock = Mock(side_effect=[[],['fakedev']])
        netmock = Mock(return_value=Mock())
        import switchyard.syinit
        setattr(switchyard.syinit, "main_real", mrmock)
        setattr(switchyard.syinit, "make_device_list", mdlmock)
        setattr(switchyard.syinit, "LLNetReal", netmock)

        with redirectio() as xio:
            with self.assertLogs(level='DEBUG') as cm:
                start_framework(opt)

        self.assertIn("CRITICAL:root:Here are all the interfaces I see on your system: fakedev", cm.output[-1])
        del(start_framework)

if __name__ == '__main__':
    setup_logging(False)
    unittest.main() 
