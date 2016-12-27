import unittest
from unittest.mock import Mock
from queue import Queue
from ipaddress import IPv4Address, ip_address
from contextlib import ContextDecorator
from io import StringIO
import sys

import switchyard.lib.socket.socketemu as sock
from switchyard.lib.packet import IPProtocol
from switchyard.lib.exceptions import *


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


class SocketEmuTests(unittest.TestCase):
    def setUp(self):
        sock.ApplicationLayer._init()
        sock.ApplicationLayer._to_app = {}
        sock.ApplicationLayer._from_app = Queue()

        sock.setdefaulttimeout(1.0)

        self.firemock = Mock()
        self.firemock.add_rule = Mock()
        self.pcapmock = Mock()
        self.pcapmock.set_bpf_filter_on_all_devices = Mock()
        setattr(sock, "Firewall", self.firemock)
        setattr(sock, "PcapLiveDevice", self.pcapmock)

    def testEphemeral(self):
        p = sock._get_ephemeral_port()
        xset = sock._gather_ports() 
        self.assertNotIn(p, xset)

    def testSockCreate(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertEqual(s._protoname, 'udp')
        self.assertEqual(s._proto, IPProtocol.UDP)
        self.assertEqual(s.family, sock.AF_INET)
        self.assertEqual(s.type, sock.SOCK_DGRAM)
        self.assertEqual(s.proto, IPProtocol.UDP)
        localport = s._local_addr[1]
        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)
        self.assertIn((IPProtocol.UDP, IPv4Address('0.0.0.0'), localport), sock.ApplicationLayer._to_app)

        self.firemock.add_rule.assert_called_with('udp:{}'.format(localport))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('udp dst port {} or icmp or icmp6'.format(localport))

        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)
        self.assertIsInstance(sock.ApplicationLayer._from_app, Queue)

        with self.assertRaises(NotImplementedError):
            sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        with self.assertRaises(NotImplementedError):
            sock.socket(sock.AF_INET, sock.SOCK_RAW)
        s.close()
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)

    def testSockBind(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        localport = s._local_addr[1]
        self.assertEqual(s._protoname, 'udp')
        self.firemock.add_rule.assert_called_with('udp:{}'.format(localport))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('udp dst port {} or icmp or icmp6'.format(localport))
        s.bind(('10.1.1.1', 5555))
        self.firemock.add_rule.assert_called_with('udp:{}'.format(5555))
        self.pcapmock.set_bpf_filter_on_all_devices.assert_called_with('udp dst port {} or icmp or icmp6'.format(5555))

    def testDefaults(self):
        self.assertEqual(sock.getdefaulttimeout(), 1.0)
        sock.setdefaulttimeout(2.0)
        self.assertEqual(sock.getdefaulttimeout(), 2.0)
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertEqual(s._timeout, 2.0)

    def testNoInstance(self):
        with self.assertRaises(RuntimeError):
            sock.ApplicationLayer()

    def testAppSockRegister(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertIn(s._sockid(), sock.ApplicationLayer._to_app)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)

        sock.ApplicationLayer._registry_update(s, s._sockid())
        self.assertIn(s._sockid(), sock.ApplicationLayer._to_app)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)

        sock.ApplicationLayer._unregister_socket(s)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)

        fromapp,toapp = sock.ApplicationLayer._register_socket(s)
        toapp.put((0,0,0))
        with self.assertLogs() as cm:
            sock.ApplicationLayer._unregister_socket(s)
        self.assertIn("WARNING", cm.output[0])
        self.assertIn("still has data enqueued", cm.output[0])

    def testAppSend(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertIsInstance(sock.ApplicationLayer._from_app, Queue)
        self.assertIsInstance(sock.ApplicationLayer._to_app[s._sockid()], Queue)

        with self.assertRaises(NoPackets):
            sock.ApplicationLayer.recv_from_app(timeout=0.1)

        s.sendto("testme!", ('127.0.0.1', 10000))
        self.assertEqual(sock.ApplicationLayer._from_app.qsize(), 1)
        self.assertFalse(sock.ApplicationLayer._from_app.empty())

        addrs,data = sock.ApplicationLayer.recv_from_app(timeout=0.1)
        self.assertEqual(data, "testme!")
        self.assertEqual(addrs[0], 17)
        self.assertEqual(str(addrs[1]), '0.0.0.0')
        self.assertEqual(str(addrs[3]), '127.0.0.1')
        self.assertEqual(addrs[4], 10000)

    def testAppRecv(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertIsInstance(sock.ApplicationLayer._from_app, Queue)
        self.assertIsInstance(sock.ApplicationLayer._to_app[s._sockid()], Queue)
        toapp = sock.ApplicationLayer._to_app[s._sockid()]

        data = "testme!"
        localport = s._local_addr[1]
        localaddr = (ip_address('127.0.0.1'), localport)
        remoteaddr = (ip_address('127.0.0.1'), 10000)
        toapp.put((localaddr, remoteaddr, data))
        rdata,addr = s.recvfrom(1500)
        self.assertEqual(data, rdata)
        self.assertEqual(addr[0], '127.0.0.1')
        self.assertEqual(addr[1], 10000)
        self.assertTrue(toapp.empty())

        sock.ApplicationLayer.send_to_app(IPProtocol.UDP, 
            ('127.0.0.1', localport), ('127.0.0.1', 10000), data)
        self.assertFalse(sock.ApplicationLayer._to_app[s._sockid()].empty())
        self.assertEqual(sock.ApplicationLayer._to_app[s._sockid()].qsize(), 1)
        rdata,addr = s.recvfrom(1500)
        self.assertEqual(data, rdata)
        self.assertEqual(addr[0], '127.0.0.1')
        self.assertEqual(addr[1], 10000)
        self.assertTrue(toapp.empty())


        sock.ApplicationLayer.send_to_app(IPProtocol.UDP, 
            ('127.0.0.1', localport), ('127.0.0.1', 10000), data)
        self.assertFalse(sock.ApplicationLayer._to_app[s._sockid()].empty())
        self.assertEqual(sock.ApplicationLayer._to_app[s._sockid()].qsize(), 1)
        rdata = s.recv(1500)
        self.assertEqual(data, rdata)
        self.assertTrue(toapp.empty())        

        with self.assertLogs() as cm:
            sock.ApplicationLayer.send_to_app(IPProtocol.UDP, 
                ('127.0.0.1', 8888), ('127.0.0.1', 9999), data)
        self.assertIn("No socket queue found for", cm.output[0])

    def testConnect(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        self.assertEqual(s.proto, 55)

        with self.assertRaises(sock.error):
            s.send("testsend") 

        s.connect(('127.0.0.1', 4567))
        s.send("testsend") 
        self.assertEqual(sock.ApplicationLayer._from_app.qsize(), 1)
        self.assertFalse(sock.ApplicationLayer._from_app.empty())

        addrs,data = sock.ApplicationLayer.recv_from_app(timeout=0.1)
        self.assertEqual(data, "testsend")
        self.assertEqual(addrs[0], 55)
        self.assertEqual(str(addrs[1]), '0.0.0.0')
        self.assertEqual(str(addrs[3]), '127.0.0.1')
        self.assertEqual(addrs[4], 4567)

        s.connect_ex(('127.0.0.1', 5678))
        self.assertEqual(s._remote_addr, (ip_address('127.0.0.1'), 5678))

    def testUnimplemented(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        with self.assertRaises(NotImplementedError):
            s.accept()
        with self.assertRaises(NotImplementedError):
            s.listen(128)
        with self.assertRaises(NotImplementedError):
            s.getsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR)
        with self.assertRaises(NotImplementedError):
            s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        buf = []
        with self.assertRaises(NotImplementedError):
            s.recv_into(buf)
        with self.assertRaises(NotImplementedError):
            s.recvfrom_into(buf)
        with self.assertRaises(NotImplementedError):
            s.recvfrom_into(buf)
        with self.assertRaises(NotImplementedError):
            s.recvmsg(buf)
        with self.assertRaises(NotImplementedError):
            s.sendmsg(buf)
        with self.assertRaises(NotImplementedError):
            s.sendall('blahblahblah')

    def testSockName(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        s.connect(('127.0.0.1', 4567))
        localport = s._local_addr[1]
        self.assertEqual(s.getsockname(), ('0.0.0.0', localport))
        self.assertEqual(s.getpeername(), ('127.0.0.1', 4567))
        s.bind(('127.0.0.1', 9876))
        self.assertEqual(s.getsockname(), ('127.0.0.1', 9876))

    def testTimeouts(self):
        t = sock.getdefaulttimeout()
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        self.assertEqual(t, s.gettimeout())
        s.settimeout(2.0)
        self.assertEqual(s.gettimeout(), 2.0)
        sock.setdefaulttimeout(3.0)
        s2 = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        self.assertEqual(3.0, s2.gettimeout())
        self.assertEqual(s2.timeout, 3.0)

    def testCloseShutdown(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 1)
        s.shutdown(1)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)
        s.shutdown(1)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)
        s.close()
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)
        s.close()
        self.assertEqual(len(sock.ApplicationLayer._to_app), 0)

    def testBlocking(self):
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        x = s.timeout
        s.settimeout(None)
        self.assertEqual(x, s.timeout)
        self.assertTrue(s._block)
        s.settimeout(1.0)
        self.assertTrue(s._block)
        s.setblocking(False)
        self.assertEqual(s.timeout, x)
        s.setblocking(True)
        self.assertTrue(s._block)
        self.assertEqual(s.timeout, x)
        s.setblocking(False)
        with self.assertRaises(sock.timeout):
            s.recv(1500)
        s.settimeout(0.0)
        self.assertFalse(s._block)
        with self.assertRaises(sock.timeout):
            s.recv(1500)

    def testMultiSocket(self):
        s1 = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 17)
        s2 = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 6)
        s3 = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, 55)
        self.assertEqual(len(sock.ApplicationLayer._to_app), 3)

        self.assertEqual(s1.bind(('127.0.0.1', 80)), 0)
        with self.assertLogs() as cm:
            self.assertEqual(s2.bind(('127.0.0.1', 80)), -1)
        self.assertIn("in use", cm.output[0])

        sock.ApplicationLayer.send_to_app(IPProtocol.UDP, 
            s1.getsockname(), ('127.0.0.1', 4567), "to s1")

        self.assertFalse(sock.ApplicationLayer._to_app[s1._sockid()].empty())
        self.assertTrue(sock.ApplicationLayer._to_app[s2._sockid()].empty())
        self.assertTrue(sock.ApplicationLayer._to_app[s3._sockid()].empty())

        with self.assertLogs() as cm:
            sock.ApplicationLayer.send_to_app(IPProtocol.UDP,
                ('1.2.3.4', 5678), s2.getsockname(), "failure")
        self.assertIn("No socket queue found", cm.output[0])

    def testFail(self):
        pcapmock = Mock()
        pcapmock.set_bpf_filter_on_all_devices = Mock(side_effect=Exception())
        setattr(sock, "PcapLiveDevice", pcapmock)

        with redirectio() as xio:
            with self.assertRaises(Exception):
                s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        self.assertIn("Unable to complete socket emulation setup", xio.contents)


if __name__ == '__main__':
    unittest.main()
