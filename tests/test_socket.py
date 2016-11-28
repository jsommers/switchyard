import unittest
from unittest.mock import Mock
from queue import Queue
from ipaddress import IPv4Address, ip_address

import switchyard.lib.socket.socketemu as sock
from switchyard.lib.packet import IPProtocol
from switchyard.lib.exceptions import *

class SocketEmuTests(unittest.TestCase):
    def setUp(self):
        sock.ApplicationLayer._init()
        sock.ApplicationLayer._to_app = {}
        sock.ApplicationLayer._from_app = Queue()

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
        self.assertIn((IPProtocol.UDP, IPv4Address('127.0.0.1'), localport), sock.ApplicationLayer._to_app)

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
        self.assertEqual(str(addrs[1]), '127.0.0.1')
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


if __name__ == '__main__':
    unittest.main()
